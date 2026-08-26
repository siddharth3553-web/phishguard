from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from phishguard.api.deps import db_session, require_api_key, require_ready, settings_dep
from phishguard.api.schemas import (
    BatchScanRequest,
    BatchScanResponse,
    EmailScanRequest,
    ScanResponse,
    UrlScanRequest,
)
from phishguard.core.config import Settings
from phishguard.core.metrics import PREDICTIONS
from phishguard.db.models import Scan
from phishguard.services.predictor import PhishGuardPredictor

router = APIRouter(prefix="/api/v1", tags=["scans"], dependencies=[Depends(require_api_key)])


def _preview(text: str, n: int = 240) -> str:
    t = text.replace("\n", " ").strip()
    return t if len(t) <= n else t[: n - 1] + "…"


def _persist_and_respond(
    *,
    session: Session,
    settings: Settings,
    request: Request,
    kind: str,
    raw_input: str,
    result: dict[str, Any],
) -> ScanResponse:
    sid = str(uuid.uuid4())
    created = datetime.now(timezone.utc)
    payload = {
        **result,
        "id": sid,
        "kind": kind,
        "model_version": settings.model_version,
        "created_at": created.isoformat(),
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
    )
    session.add(row)
    PREDICTIONS.labels(kind, row.verdict).inc()
    rid = getattr(request.state, "request_id", None)
    return ScanResponse(
        id=sid,
        kind=kind,  # type: ignore[arg-type]
        model_version=settings.model_version,
        created_at=created,
        verdict=row.verdict,
        confidence=float(result.get("confidence", 0.0)),
        phishing_score=row.phishing_score,
        label=int(result.get("label", 0)),
        low_confidence=bool(result.get("low_confidence")),
        insufficient_input=bool(result.get("insufficient_input")),
        note=result.get("note"),
        features=result.get("features"),
        flagged_keywords=result.get("flagged_keywords"),
        request_id=rid,
    )


@router.post("/urls/scans", response_model=ScanResponse, status_code=201)
def scan_url(
    body: UrlScanRequest,
    request: Request,
    predictor: PhishGuardPredictor = Depends(require_ready),
    session: Session = Depends(db_session),
    settings: Settings = Depends(settings_dep),
) -> ScanResponse:
    try:
        result = predictor.predict_url(body.url)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return _persist_and_respond(
        session=session,
        settings=settings,
        request=request,
        kind="url",
        raw_input=body.url,
        result=result,
    )


@router.post("/emails/scans", response_model=ScanResponse, status_code=201)
def scan_email(
    body: EmailScanRequest,
    request: Request,
    predictor: PhishGuardPredictor = Depends(require_ready),
    session: Session = Depends(db_session),
    settings: Settings = Depends(settings_dep),
) -> ScanResponse:
    try:
        result = predictor.predict_email(body.text)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return _persist_and_respond(
        session=session,
        settings=settings,
        request=request,
        kind="email",
        raw_input=body.text,
        result=result,
    )


@router.post("/scans:batch", response_model=BatchScanResponse, status_code=201)
def scan_batch(
    body: BatchScanRequest,
    request: Request,
    predictor: PhishGuardPredictor = Depends(require_ready),
    session: Session = Depends(db_session),
    settings: Settings = Depends(settings_dep),
) -> BatchScanResponse:
    if len(body.items) > settings.batch_max_items:
        raise HTTPException(
            status_code=422,
            detail=f"batch size {len(body.items)} exceeds max {settings.batch_max_items}",
        )
    out: list[ScanResponse] = []
    for item in body.items:
        if item.kind == "url":
            result = predictor.predict_url(item.value)
        else:
            result = predictor.predict_email(item.value)
        out.append(
            _persist_and_respond(
                session=session,
                settings=settings,
                request=request,
                kind=item.kind,
                raw_input=item.value,
                result=result,
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
    payload = json.loads(row.payload_json)
    rid = getattr(request.state, "request_id", None)
    return ScanResponse(
        id=row.id,
        kind=row.kind,  # type: ignore[arg-type]
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
    )
