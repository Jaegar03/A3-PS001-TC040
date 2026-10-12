"""POST /api/v1/analyze/{text,url,file,prompt,sql} (brief §25).

All five endpoints are implemented: `file` (Phase 3 — metadata, YARA,
ClamAV when reachable, structural heuristics) and the Phase 4 text
endpoints `text`, `url`, `prompt` and `sql`, which run the
SQLInjectionDetector, URLDetector and PromptInjectionDetector over
bounded, explainable rule/heuristic layers — not trained models
(docs/model-card.md). Submitted bodies and URLs are analyzed in memory
and never persisted, and a submitted URL is parsed locally without any
network fetch (brief §32's "no fake features" principle applied to API
surface, not just detection results).
"""

from __future__ import annotations

import hashlib
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_detector_registry
from app.detectors.file.metadata import analyze_file
from app.detectors.registry import DetectorRegistry
from app.events.schema import (
    AttachmentRef,
    EventContent,
    SecurityEvent,
    SecurityEventType,
    SourceType,
)
from app.security.auth import require_scopes
from app.security.uploads import (
    ArchiveBombSuspected,
    UploadTooLarge,
    inspect_zip_bomb_safe,
    validate_upload_size,
)
from app.services.file_blob_store import blob_store
from app.services.pipeline import run_pipeline

router = APIRouter(prefix="/api/v1/analyze", tags=["analyze"], dependencies=[Depends(require_scopes("analyze"))])

_MAX_TEXT = 100_000
_MAX_URL = 2_048


def _string_field(payload: Any, field: str, maximum: int) -> str:
    """Validate without letting FastAPI/Pydantic echo attacker input."""
    if not isinstance(payload, dict):
        raise HTTPException(status_code=422, detail="Request body must be a JSON object")
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        raise HTTPException(status_code=422, detail=f"{field} must be a non-empty string")
    value = value.strip()
    if len(value) > maximum:
        raise HTTPException(status_code=422, detail=f"{field} exceeds the maximum length of {maximum} characters")
    return value


async def _analyze_submission(*, text: str | None = None, url: str | None = None,
                              event_type: SecurityEventType, db: Session,
                              registry: DetectorRegistry) -> dict:
    value = text if text is not None else url
    if value is None:  # defensive invariant; callers provide exactly one value
        raise HTTPException(status_code=500, detail="Analysis value was not provided")
    metadata = {
        "analysis_sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
        "analysis_length": len(value),
        "analysis_kind": "url" if url is not None else "text",
    }
    if url is not None:
        metadata["limitation"] = "URL parsed heuristically; no remote fetch, redirect following, or DNS resolution"
    analyzed = SecurityEvent(
        event_type=event_type, source="api", source_type=SourceType.LIVE,
        content=EventContent(body=text, urls=[url] if url is not None else []),
        metadata={**metadata, "analysis_text": text or "", "analysis_url": url or ""},
    )
    # Never persist the submitted body or URL; detectors still receive it in memory.
    persisted = analyzed.model_copy(update={"content": None, "metadata": metadata})
    findings, assessment = await run_pipeline(analyzed, db=db, registry=registry, persist=persisted)
    result = {
        "event_id": analyzed.event_id, "source_type": analyzed.source_type.value,
        "findings": [f.model_dump(mode="json") for f in findings],
        "risk_assessment": assessment.model_dump(mode="json"),
    }
    if url is not None:
        result["limitations"] = [metadata["limitation"]]
    return result


@router.post("/file")
async def analyze_file_endpoint(
    file: UploadFile,
    db: Session = Depends(get_db),
    registry: DetectorRegistry = Depends(get_detector_registry),
) -> dict:
    data = await file.read()
    try:
        validate_upload_size(len(data))
    except UploadTooLarge as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc

    if (file.filename or "").lower().endswith(".zip"):
        try:
            inspect_zip_bomb_safe(data)
        except ArchiveBombSuspected as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    meta = analyze_file(file.filename or "unnamed", data, declared_mime=file.content_type)

    blob_store.put(meta.sha256, data)
    try:
        event = SecurityEvent(
            event_type=SecurityEventType.FILE_ANALYSIS,
            source="api",
            source_type=SourceType.LIVE,
            attachments=[
                AttachmentRef(
                    filename=meta.filename,
                    declared_mime=meta.declared_mime,
                    size_bytes=meta.size_bytes,
                    sha256=meta.sha256,
                )
            ],
            metadata={"sha256": meta.sha256, "file_metadata": meta.__dict__},
        )
        findings, assessment = await run_pipeline(event, db=db, registry=registry)
    finally:
        blob_store.discard(meta.sha256)  # never retained past this request (brief §30)

    return {
        "event_id": event.event_id,
        "source_type": event.source_type.value,
        "file_metadata": {
            "filename": meta.filename,
            "sha256": meta.sha256,
            "size_bytes": meta.size_bytes,
            "entropy": round(meta.entropy, 3),
            "matched_magic_types": meta.matched_magic_types,
            "extension_mismatch": meta.extension_mismatch,
            "is_polyglot": meta.is_polyglot,
        },
        "findings": [f.model_dump(mode="json") for f in findings],
        "risk_assessment": assessment.model_dump(mode="json"),
    }


@router.post("/text")
async def analyze_text_endpoint(payload: dict = Body(...), db: Session = Depends(get_db), registry: DetectorRegistry = Depends(get_detector_registry)) -> dict:
    return await _analyze_submission(text=_string_field(payload, "text", _MAX_TEXT), event_type=SecurityEventType.TEXT_ANALYSIS, db=db, registry=registry)


@router.post("/url")
async def analyze_url_endpoint(payload: dict = Body(...), db: Session = Depends(get_db), registry: DetectorRegistry = Depends(get_detector_registry)) -> dict:
    return await _analyze_submission(url=_string_field(payload, "url", _MAX_URL), event_type=SecurityEventType.URL_ANALYSIS, db=db, registry=registry)


@router.post("/prompt")
async def analyze_prompt_endpoint(payload: dict = Body(...), db: Session = Depends(get_db), registry: DetectorRegistry = Depends(get_detector_registry)) -> dict:
    return await _analyze_submission(text=_string_field(payload, "prompt", _MAX_TEXT), event_type=SecurityEventType.PROMPT_ANALYSIS, db=db, registry=registry)


@router.post("/sql")
async def analyze_sql_endpoint(payload: dict = Body(...), db: Session = Depends(get_db), registry: DetectorRegistry = Depends(get_detector_registry)) -> dict:
    return await _analyze_submission(text=_string_field(payload, "sql", _MAX_TEXT), event_type=SecurityEventType.SQL_ANALYSIS, db=db, registry=registry)
