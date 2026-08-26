from __future__ import annotations

import json
import re
import statistics
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from phishguard.api.deps import (
    current_user_optional,
    db_session,
    require_analyst,
    require_api_key,
    require_ready,
    require_user,
    settings_dep,
    write_audit,
)
from phishguard.api.schemas import (
    AllowlistCreate,
    AllowlistEntryOut,
    AllowlistListResponse,
    AuditEventOut,
    AuditListResponse,
    BatchScanRequest,
    BatchScanResponse,
    ClickCheckResponse,
    DispositionRequest,
    EmailScanRequest,
    OpsSummary,
    ScanListResponse,
    ScanResponse,
    UrlScanRequest,
)
from phishguard.core.config import Settings
from phishguard.core.metrics import PREDICTIONS
from phishguard.db.models import AllowlistEntry, AuditEvent, Campaign, ClickToken, Scan, User
from phishguard.services.campaigns import campaign_fingerprint
from phishguard.services.org_context import get_allowlist_set, get_brand_domains
from phishguard.services.predictor import PhishGuardPredictor
from phishguard.services.qr_decode import decode_qr_bytes

router = APIRouter(prefix="/api/v1", tags=["scans"], dependencies=[Depends(require_api_key)])
public_router = APIRouter(tags=["safe-click"])


def _preview(text: str, n: int = 240) -> str:
    t = text.replace("\n", " ").strip()
    return t if len(t) <= n else t[: n - 1] + "…"


def _coaching_for(result: dict[str, Any]) -> dict[str, Any]:
    reasons = result.get("reasons") or []
    tips: list[str] = []
    if any(r.startswith("bec_") for r in reasons):
        tips.append("Verify payment or gift-card requests via a known phone number — not by replying.")
    if any("lookalike" in r for r in reasons):
        tips.append("Hover links and check the real domain; brand lookalikes are common.")
    if any(r.startswith("qr_") for r in reasons):
        tips.append("QR codes can hide destinations — paste the payload into a scanner first.")
    if not tips:
        tips.append("When unsure, report rather than click. Analysts will share the disposition.")
    return {
        "headline": "Thanks — this is in the analyst queue" if result.get("reported") else "Report if something feels off",
        "tips": tips,
        "shared_evidence": True,
    }


def _upsert_campaign(session: Session, result: dict[str, Any]) -> Campaign | None:
    if not (result.get("reasons") or result.get("extracted_urls") or result.get("qr_payload")):
        return None
    fp, brand = campaign_fingerprint(result)
    existing = session.scalars(select(Campaign).where(Campaign.fingerprint == fp)).first()
    now = datetime.now(timezone.utc)
    if existing:
        existing.member_count = int(existing.member_count or 0) + 1
        existing.updated_at = now
        if brand and not existing.brand:
            existing.brand = brand
        return existing
    camp = Campaign(
        id=str(uuid.uuid4()),
        fingerprint=fp,
        brand=brand,
        member_count=1,
        status="open",
        created_at=now,
        updated_at=now,
    )
    session.add(camp)
    session.flush()
    return camp


def _create_click_tokens(session: Session, scan_id: str, result: dict[str, Any]) -> list[ClickToken]:
    urls: list[str] = list(result.get("extracted_urls") or [])
    intel = result.get("url_intel") or {}
    if intel.get("url") and intel["url"] not in urls:
        urls.insert(0, str(intel["url"]))
    tokens: list[ClickToken] = []
    seen: set[str] = set()
    for u in urls[:8]:
        u = (u or "").strip()
        if not u or u in seen:
            continue
        seen.add(u)
        tok = ClickToken(
            id=str(uuid.uuid4()),
            scan_id=scan_id,
            target_url=u,
            created_at=datetime.now(timezone.utc),
            last_verdict=str(result.get("verdict")),
        )
        session.add(tok)
        tokens.append(tok)
    return tokens


def _safe_click_payload(tokens: list[ClickToken], base: str = "") -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for t in tokens:
        path = f"/c/{t.id}"
        out.append({"token": t.id, "target_url": t.target_url, "safe_click_url": f"{base}{path}"})
    return out


def _row_to_response(row: Scan, request: Request, session: Session | None = None) -> ScanResponse:
    payload = json.loads(row.payload_json)
    rid = getattr(request.state, "request_id", None)
    kind = row.kind if row.kind in ("url", "email", "qr") else "url"
    decision_log = payload.get("decision_log")
    if not decision_log and row.decision_log_json:
        try:
            decision_log = json.loads(row.decision_log_json)
        except json.JSONDecodeError:
            decision_log = None
    coaching = payload.get("coaching")
    if not coaching and row.coaching_json:
        try:
            coaching = json.loads(row.coaching_json)
        except json.JSONDecodeError:
            coaching = None

    camp_fp = None
    camp_brand = None
    camp_count = None
    if session and row.campaign_id:
        camp = session.get(Campaign, row.campaign_id)
        if camp:
            camp_fp = camp.fingerprint
            camp_brand = camp.brand
            camp_count = camp.member_count

    safe_clicks = payload.get("safe_click_urls")
    if session and not safe_clicks:
        toks = session.scalars(select(ClickToken).where(ClickToken.scan_id == row.id)).all()
        if toks:
            safe_clicks = _safe_click_payload(list(toks))

    return ScanResponse(
        id=row.id,
        kind=kind,  # type: ignore[arg-type]
        model_version=row.model_version,
        created_at=row.created_at,
        verdict=row.verdict,
        confidence=float(payload.get("confidence", 0.0)),
        phishing_score=row.phishing_score,
        label=int(payload.get("label", 0)),
        low_confidence=bool(payload.get("low_confidence")),
        insufficient_input=bool(payload.get("insufficient_input")),
        note=payload.get("note"),
        features=payload.get("features"),
        flagged_keywords=payload.get("flagged_keywords"),
        request_id=rid,
        reasons=payload.get("reasons")
        or (json.loads(row.reasons_json) if row.reasons_json else None),
        extracted_urls=payload.get("extracted_urls"),
        status=row.status,
        reported=bool(row.reported),
        reporter_id=row.reporter_id,
        qr_payload=payload.get("qr_payload"),
        url_intel=payload.get("url_intel"),
        email_intel=payload.get("email_intel"),
        disposition_note=row.disposition_note,
        campaign_id=row.campaign_id,
        campaign_fingerprint=camp_fp,
        campaign_brand=camp_brand,
        campaign_member_count=camp_count,
        bec_score=row.bec_score if row.bec_score is not None else payload.get("bec_score"),
        decision_log=decision_log,
        safe_click_urls=safe_clicks,
        coaching=coaching,
    )


def _persist_and_respond(
    *,
    session: Session,
    settings: Settings,
    request: Request,
    kind: str,
    raw_input: str,
    result: dict[str, Any],
    user: User | None,
) -> ScanResponse:
    sid = str(uuid.uuid4())
    created = datetime.now(timezone.utc)
    reasons = result.get("reasons") or []
    camp = _upsert_campaign(session, result)
    tokens = _create_click_tokens(session, sid, result)
    safe_clicks = _safe_click_payload(tokens)
    coaching = _coaching_for(result)
    decision_log = list(result.get("decision_log") or [])
    decision_log.append(
        {
            "step": "persist",
            "campaign_id": camp.id if camp else None,
            "safe_click_count": len(tokens),
        }
    )

    payload = {
        **result,
        "id": sid,
        "kind": kind,
        "model_version": settings.model_version,
        "created_at": created.isoformat(),
        "status": "open",
        "reported": False,
        "reporter_id": user.id if user else None,
        "safe_click_urls": safe_clicks,
        "coaching": coaching,
        "decision_log": decision_log,
        "campaign_id": camp.id if camp else None,
    }
    row = Scan(
        id=sid,
        kind=kind,
        input_preview=_preview(raw_input),
        verdict=str(result.get("verdict", "Uncertain")),
        phishing_score=float(result.get("phishing_score", 0.0)),
        model_version=settings.model_version,
        payload_json=json.dumps(payload, default=str),
        created_at=created,
        reporter_id=user.id if user else None,
        status="open",
        reported=False,
        reasons_json=json.dumps(reasons),
        org_id="demo",
        campaign_id=camp.id if camp else None,
        bec_score=float(result.get("bec_score") or 0) if result.get("bec_score") is not None else None,
        decision_log_json=json.dumps(decision_log, default=str),
        coaching_json=json.dumps(coaching),
    )
    session.add(row)
    PREDICTIONS.labels(kind, row.verdict).inc()
    write_audit(
        session,
        actor_id=user.id if user else None,
        action="scan_created",
        resource_type="scan",
        resource_id=sid,
        detail={"kind": kind, "verdict": row.verdict, "campaign_id": row.campaign_id},
    )
    return _row_to_response(row, request, session)


def _domain_from_scan(row: Scan) -> str | None:
    payload = json.loads(row.payload_json)
    urls = payload.get("extracted_urls") or []
    if urls:
        try:
            host = urlparse(urls[0]).hostname
            if host:
                return host.lower()
        except Exception:
            pass
    m = re.search(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", row.input_preview or "")
    if m:
        return m.group(1).lower()
    return None


@router.post("/urls/scans", response_model=ScanResponse, status_code=201)
def scan_url(
    body: UrlScanRequest,
    request: Request,
    predictor: PhishGuardPredictor = Depends(require_ready),
    session: Session = Depends(db_session),
    settings: Settings = Depends(settings_dep),
    user: User | None = Depends(current_user_optional),
) -> ScanResponse:
    brands = get_brand_domains(session)
    allow = get_allowlist_set(session)
    try:
        result = predictor.predict_url(body.url, brands=brands, allowlisted=allow)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return _persist_and_respond(
        session=session,
        settings=settings,
        request=request,
        kind="url",
        raw_input=body.url,
        result=result,
        user=user,
    )


@router.post("/emails/scans", response_model=ScanResponse, status_code=201)
def scan_email(
    body: EmailScanRequest,
    request: Request,
    predictor: PhishGuardPredictor = Depends(require_ready),
    session: Session = Depends(db_session),
    settings: Settings = Depends(settings_dep),
    user: User | None = Depends(current_user_optional),
) -> ScanResponse:
    brands = get_brand_domains(session)
    allow = get_allowlist_set(session)
    try:
        result = predictor.predict_email(body.text, brands=brands, allowlisted=allow)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return _persist_and_respond(
        session=session,
        settings=settings,
        request=request,
        kind="email",
        raw_input=body.text,
        result=result,
        user=user,
    )


@router.post("/scans/qr", response_model=ScanResponse, status_code=201)
async def scan_qr(
    request: Request,
    file: UploadFile = File(...),
    predictor: PhishGuardPredictor = Depends(require_ready),
    session: Session = Depends(db_session),
    settings: Settings = Depends(settings_dep),
    user: User | None = Depends(current_user_optional),
) -> ScanResponse:
    data = await file.read()
    if len(data) > settings.max_body_bytes:
        raise HTTPException(status_code=413, detail="image too large")
    decoded = decode_qr_bytes(data)
    if not decoded.get("ok") or not decoded.get("payloads"):
        raise HTTPException(
            status_code=422,
            detail=decoded.get("error") or "no QR code found in image",
        )
    payload_text = str(decoded["payloads"][0])
    brands = get_brand_domains(session)
    allow = get_allowlist_set(session)
    if "://" in payload_text or payload_text.startswith("www."):
        result = predictor.predict_url(
            payload_text,
            brands=brands,
            allowlisted=allow,
            extra_reasons=["qr_decoded"],
        )
    else:
        result = predictor.predict_email(
            payload_text,
            brands=brands,
            allowlisted=allow,
        )
        reasons = list(result.get("reasons") or [])
        reasons.insert(0, "qr_decoded")
        result["reasons"] = reasons
    result["qr_payload"] = payload_text
    return _persist_and_respond(
        session=session,
        settings=settings,
        request=request,
        kind="qr",
        raw_input=payload_text,
        result=result,
        user=user,
    )


@router.post("/scans:batch", response_model=BatchScanResponse, status_code=201)
def scan_batch(
    body: BatchScanRequest,
    request: Request,
    predictor: PhishGuardPredictor = Depends(require_ready),
    session: Session = Depends(db_session),
    settings: Settings = Depends(settings_dep),
    user: User | None = Depends(current_user_optional),
) -> BatchScanResponse:
    if len(body.items) > settings.batch_max_items:
        raise HTTPException(
            status_code=422,
            detail=f"batch size {len(body.items)} exceeds max {settings.batch_max_items}",
        )
    brands = get_brand_domains(session)
    allow = get_allowlist_set(session)
    out: list[ScanResponse] = []
    for item in body.items:
        if item.kind == "url":
            result = predictor.predict_url(item.value, brands=brands, allowlisted=allow)
        else:
            result = predictor.predict_email(item.value, brands=brands, allowlisted=allow)
        out.append(
            _persist_and_respond(
                session=session,
                settings=settings,
                request=request,
                kind=item.kind,
                raw_input=item.value,
                result=result,
                user=user,
            )
        )
    return BatchScanResponse(scans=out)


@router.get("/scans/{scan_id}", response_model=ScanResponse)
def get_scan(
    scan_id: str,
    request: Request,
    session: Session = Depends(db_session),
) -> ScanResponse:
    row = session.get(Scan, scan_id)
    if row is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return _row_to_response(row, request, session)


@router.get("/me/scans", response_model=ScanListResponse)
def my_scans(
    request: Request,
    session: Session = Depends(db_session),
    user: User = Depends(require_user),
    limit: int = Query(default=25, ge=1, le=100),
) -> ScanListResponse:
    rows = session.scalars(
        select(Scan)
        .where(Scan.reporter_id == user.id)
        .order_by(Scan.created_at.desc())
        .limit(limit)
    ).all()
    return ScanListResponse(scans=[_row_to_response(r, request, session) for r in rows])


@router.post("/scans/{scan_id}/report", response_model=ScanResponse)
def report_scan(
    scan_id: str,
    request: Request,
    session: Session = Depends(db_session),
    user: User = Depends(require_user),
) -> ScanResponse:
    row = session.get(Scan, scan_id)
    if row is None:
        raise HTTPException(status_code=404, detail="scan not found")
    if row.reporter_id and row.reporter_id != user.id and user.role != "analyst":
        raise HTTPException(status_code=403, detail="not your scan")
    row.reported = True
    if row.status == "open":
        row.status = "in_review"
    payload = json.loads(row.payload_json)
    payload["reported"] = True
    payload["status"] = row.status
    coaching = _coaching_for({**payload, "reported": True})
    payload["coaching"] = coaching
    row.coaching_json = json.dumps(coaching)
    log = list(payload.get("decision_log") or [])
    log.append({"step": "reported", "by": user.id, "at": datetime.now(timezone.utc).isoformat()})
    payload["decision_log"] = log
    row.decision_log_json = json.dumps(log)
    row.payload_json = json.dumps(payload, default=str)
    write_audit(
        session,
        actor_id=user.id,
        action="scan_reported",
        resource_type="scan",
        resource_id=scan_id,
    )
    return _row_to_response(row, request, session)


@router.get("/analyst/queue", response_model=ScanListResponse)
def analyst_queue(
    request: Request,
    session: Session = Depends(db_session),
    user: User = Depends(require_analyst),
    limit: int = Query(default=50, ge=1, le=200),
) -> ScanListResponse:
    _ = user
    rows = session.scalars(
        select(Scan)
        .where(
            or_(
                Scan.reported.is_(True),
                Scan.verdict.in_(["Uncertain", "Phishing", "Suspicious"]),
                Scan.status.in_(["in_review", "open"]),
            )
        )
        .where(Scan.status.in_(["open", "in_review"]))
        .order_by(Scan.created_at.desc())
        .limit(limit)
    ).all()
    rows = sorted(
        rows,
        key=lambda r: (
            0 if r.reported else 1,
            0 if r.campaign_id else 1,
            0 if r.verdict == "Phishing" else 1,
            r.created_at,
        ),
        reverse=False,
    )
    return ScanListResponse(scans=[_row_to_response(r, request, session) for r in rows])


@router.get("/ops/summary", response_model=OpsSummary)
def ops_summary(
    session: Session = Depends(db_session),
    user: User = Depends(require_analyst),
) -> OpsSummary:
    _ = user
    open_queue = len(
        session.scalars(select(Scan).where(Scan.status.in_(["open", "in_review"]))).all()
    )
    open_campaigns = len(
        session.scalars(select(Campaign).where(Campaign.status == "open")).all()
    )
    reported_count = len(session.scalars(select(Scan).where(Scan.reported.is_(True))).all())
    disposed = session.scalars(
        select(Scan).where(Scan.disposed_at.is_not(None), Scan.created_at.is_not(None))
    ).all()
    fp = sum(1 for s in disposed if s.status == "false_positive")
    fp_rate = (fp / len(disposed)) if disposed else 0.0
    deltas: list[float] = []
    for s in disposed:
        if s.disposed_at and s.created_at:
            deltas.append((s.disposed_at - s.created_at).total_seconds() / 60.0)
    median = float(statistics.median(deltas)) if deltas else None
    return OpsSummary(
        open_campaigns=open_campaigns,
        open_queue=open_queue,
        false_positive_rate=round(fp_rate, 3),
        median_disposition_minutes=round(median, 1) if median is not None else None,
        reported_count=reported_count,
    )


def _apply_disposition(
    session: Session,
    row: Scan,
    body: DispositionRequest,
    user: User,
) -> None:
    now = datetime.now(timezone.utc)
    row.status = body.status
    row.disposition_note = body.note
    row.disposed_by = user.id
    row.disposed_at = now
    payload = json.loads(row.payload_json)
    payload["status"] = row.status
    payload["disposition_note"] = body.note
    log = list(payload.get("decision_log") or [])
    log.append(
        {
            "step": "disposition",
            "status": body.status,
            "scope": body.scope,
            "by": user.id,
            "at": now.isoformat(),
            "note": body.note,
        }
    )
    payload["decision_log"] = log
    row.decision_log_json = json.dumps(log)
    row.payload_json = json.dumps(payload, default=str)

    if body.status == "allowlisted":
        val = (body.allowlist_value or "").strip().lower()
        if body.scope == "campaign" and row.campaign_id:
            val = val or f"campaign:{row.campaign_id}"
            kind = "campaign"
            scope = "campaign"
        elif body.scope == "domain":
            val = val or (_domain_from_scan(row) or "")
            kind = "email" if "@" in val else "domain"
            scope = "domain"
        else:
            kind = "email" if "@" in val else "domain"
            scope = body.scope
        if val:
            session.add(
                AllowlistEntry(
                    id=str(uuid.uuid4()),
                    value=val,
                    kind=kind,
                    scope=scope,
                    note=body.note,
                    created_by=user.id,
                    org_id="demo",
                    expires_at=now + timedelta(days=body.expires_days),
                )
            )
            log.append({"step": "allowlist", "value": val, "expires_days": body.expires_days})
            payload["decision_log"] = log
            row.decision_log_json = json.dumps(log)
            row.payload_json = json.dumps(payload, default=str)


@router.post("/scans/{scan_id}/disposition", response_model=ScanResponse)
def dispose_scan(
    scan_id: str,
    body: DispositionRequest,
    request: Request,
    session: Session = Depends(db_session),
    user: User = Depends(require_analyst),
) -> ScanResponse:
    row = session.get(Scan, scan_id)
    if row is None:
        raise HTTPException(status_code=404, detail="scan not found")
    _apply_disposition(session, row, body, user)

    members: list[Scan] = [row]
    if body.scope == "campaign" and row.campaign_id:
        others = session.scalars(
            select(Scan).where(
                Scan.campaign_id == row.campaign_id,
                Scan.id != row.id,
                Scan.status.in_(["open", "in_review"]),
            )
        ).all()
        for other in others:
            _apply_disposition(session, other, body, user)
            members.append(other)
        camp = session.get(Campaign, row.campaign_id)
        if camp and body.status in ("confirmed_phish", "false_positive", "allowlisted"):
            camp.status = "closed"
            camp.updated_at = datetime.now(timezone.utc)

    write_audit(
        session,
        actor_id=user.id,
        action="scan_disposition",
        resource_type="scan",
        resource_id=scan_id,
        detail={
            "status": body.status,
            "scope": body.scope,
            "members": len(members),
            "reporter_notified": bool(row.reporter_id),
        },
    )
    return _row_to_response(row, request, session)


@router.get("/allowlist", response_model=AllowlistListResponse)
def list_allowlist(
    session: Session = Depends(db_session),
    user: User = Depends(require_analyst),
) -> AllowlistListResponse:
    _ = user
    rows = session.scalars(select(AllowlistEntry).order_by(AllowlistEntry.created_at.desc())).all()
    return AllowlistListResponse(
        entries=[
            AllowlistEntryOut(
                id=r.id,
                value=r.value,
                kind=r.kind,
                scope=getattr(r, "scope", None) or "domain",
                note=r.note,
                created_at=r.created_at,
                expires_at=getattr(r, "expires_at", None),
            )
            for r in rows
        ]
    )


@router.post("/allowlist", response_model=AllowlistEntryOut, status_code=201)
def add_allowlist(
    body: AllowlistCreate,
    session: Session = Depends(db_session),
    user: User = Depends(require_analyst),
) -> AllowlistEntryOut:
    eid = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    row = AllowlistEntry(
        id=eid,
        value=body.value.strip().lower(),
        kind=body.kind,
        scope=body.scope or body.kind,
        note=body.note,
        created_by=user.id,
        org_id="demo",
        expires_at=now + timedelta(days=body.expires_days),
    )
    session.add(row)
    write_audit(
        session,
        actor_id=user.id,
        action="allowlist_add",
        resource_type="allowlist",
        resource_id=eid,
        detail={"value": row.value, "expires_at": row.expires_at.isoformat() if row.expires_at else None},
    )
    return AllowlistEntryOut(
        id=row.id,
        value=row.value,
        kind=row.kind,
        scope=row.scope,
        note=row.note,
        created_at=row.created_at or now,
        expires_at=row.expires_at,
    )


@router.get("/audit", response_model=AuditListResponse)
def list_audit(
    session: Session = Depends(db_session),
    user: User = Depends(require_analyst),
    limit: int = Query(default=50, ge=1, le=200),
) -> AuditListResponse:
    _ = user
    rows = session.scalars(
        select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(limit)
    ).all()
    events: list[AuditEventOut] = []
    for r in rows:
        detail = None
        if r.detail_json:
            try:
                detail = json.loads(r.detail_json)
            except json.JSONDecodeError:
                detail = None
        events.append(
            AuditEventOut(
                id=r.id,
                actor_id=r.actor_id,
                action=r.action,
                resource_type=r.resource_type,
                resource_id=r.resource_id,
                created_at=r.created_at,
                detail=detail,
            )
        )
    return AuditListResponse(events=events)


@public_router.get("/c/{token}", response_model=ClickCheckResponse)
def safe_click(
    token: str,
    predictor: PhishGuardPredictor = Depends(require_ready),
    session: Session = Depends(db_session),
) -> ClickCheckResponse:
    """Click-time revalidation (Proofpoint Safe Links analogue — local tokens only)."""
    row = session.get(ClickToken, token)
    if row is None:
        raise HTTPException(status_code=404, detail="token not found")
    brands = get_brand_domains(session)
    allow = get_allowlist_set(session)
    previous = row.last_verdict
    try:
        result = predictor.predict_url(row.target_url, brands=brands, allowlisted=allow)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    verdict = str(result.get("verdict", "Uncertain"))
    reasons = list(result.get("reasons") or [])
    row.last_checked_at = datetime.now(timezone.utc)
    row.last_verdict = verdict
    row.last_reasons_json = json.dumps(reasons)
    scan = session.get(Scan, row.scan_id)
    if scan:
        payload = json.loads(scan.payload_json)
        log = list(payload.get("decision_log") or [])
        changed = previous is not None and previous != verdict
        log.append(
            {
                "step": "click_time",
                "token": token,
                "previous_verdict": previous,
                "verdict": verdict,
                "changed": changed,
                "at": row.last_checked_at.isoformat(),
            }
        )
        payload["decision_log"] = log
        scan.decision_log_json = json.dumps(log)
        scan.payload_json = json.dumps(payload, default=str)
        write_audit(
            session,
            actor_id=None,
            action="safe_click_check",
            resource_type="click_token",
            resource_id=token,
            detail={"verdict": verdict, "changed": changed},
        )
    return ClickCheckResponse(
        token=token,
        target_url=row.target_url,
        verdict=verdict,
        reasons=reasons,
        changed=previous is not None and previous != verdict,
        previous_verdict=previous,
    )
