from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

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
    DispositionRequest,
    EmailScanRequest,
    ScanListResponse,
    ScanResponse,
    UrlScanRequest,
)
from phishguard.core.config import Settings
from phishguard.core.metrics import PREDICTIONS
from phishguard.db.models import AllowlistEntry, AuditEvent, Scan, User
from phishguard.services.org_context import get_allowlist_set, get_brand_domains
from phishguard.services.predictor import PhishGuardPredictor
from phishguard.services.qr_decode import decode_qr_bytes

router = APIRouter(prefix="/api/v1", tags=["scans"], dependencies=[Depends(require_api_key)])


def _preview(text: str, n: int = 240) -> str:
    t = text.replace("\n", " ").strip()
    return t if len(t) <= n else t[: n - 1] + "…"


def _row_to_response(row: Scan, request: Request) -> ScanResponse:
    payload = json.loads(row.payload_json)
    rid = getattr(request.state, "request_id", None)
    kind = row.kind if row.kind in ("url", "email", "qr") else "url"
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
    payload = {
        **result,
        "id": sid,
        "kind": kind,
        "model_version": settings.model_version,
        "created_at": created.isoformat(),
        "status": "open",
        "reported": False,
        "reporter_id": user.id if user else None,
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
    )
    session.add(row)
    PREDICTIONS.labels(kind, row.verdict).inc()
    write_audit(
        session,
        actor_id=user.id if user else None,
        action="scan_created",
        resource_type="scan",
        resource_id=sid,
        detail={"kind": kind, "verdict": row.verdict},
    )
    return _row_to_response(row, request)


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
    # QR payloads are often URLs
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
    return _row_to_response(row, request)


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
    return ScanListResponse(scans=[_row_to_response(r, request) for r in rows])


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
    row.payload_json = json.dumps(payload, default=str)
    write_audit(
        session,
        actor_id=user.id,
        action="scan_reported",
        resource_type="scan",
        resource_id=scan_id,
    )
    return _row_to_response(row, request)


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
    # Prefer reported / high risk
    rows = sorted(
        rows,
        key=lambda r: (0 if r.reported else 1, 0 if r.verdict == "Phishing" else 1, r.created_at),
        reverse=False,
    )
    return ScanListResponse(scans=[_row_to_response(r, request) for r in rows])


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
    row.status = body.status
    row.disposition_note = body.note
    row.disposed_by = user.id
    row.disposed_at = datetime.now(timezone.utc)
    if body.status == "allowlisted" and body.allowlist_value:
        val = body.allowlist_value.strip().lower()
        session.add(
            AllowlistEntry(
                id=str(uuid.uuid4()),
                value=val,
                kind="email" if "@" in val else "domain",
                note=body.note,
                created_by=user.id,
                org_id="demo",
            )
        )
    payload = json.loads(row.payload_json)
    payload["status"] = row.status
    payload["disposition_note"] = body.note
    row.payload_json = json.dumps(payload, default=str)
    write_audit(
        session,
        actor_id=user.id,
        action="scan_disposition",
        resource_type="scan",
        resource_id=scan_id,
        detail={"status": body.status},
    )
    return _row_to_response(row, request)


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
                note=r.note,
                created_at=r.created_at,
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
    row = AllowlistEntry(
        id=eid,
        value=body.value.strip().lower(),
        kind=body.kind,
        note=body.note,
        created_by=user.id,
        org_id="demo",
    )
    session.add(row)
    write_audit(
        session,
        actor_id=user.id,
        action="allowlist_add",
        resource_type="allowlist",
        resource_id=eid,
        detail={"value": row.value},
    )
    return AllowlistEntryOut(
        id=row.id,
        value=row.value,
        kind=row.kind,
        note=row.note,
        created_at=row.created_at or datetime.now(timezone.utc),
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
