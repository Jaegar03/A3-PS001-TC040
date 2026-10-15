"""POST /api/v1/events, GET /api/v1/events, GET /api/v1/events/{id}."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_detector_registry
from app.detectors.registry import DetectorRegistry
from app.events.schema import SecurityEvent
from app.security.auth import current_actor, require_scopes
from app.services.event_repository import EventRepository
from app.services.pipeline import run_pipeline
from app.services.simulation_visibility import COMMAND_CENTER_SOURCE, command_center_event

router = APIRouter(prefix="/api/v1/events", tags=["events"])


@router.post("", dependencies=[Depends(require_scopes("ingest"))])
async def ingest_event(
    event: SecurityEvent,
    db: Session = Depends(get_db),
    registry: DetectorRegistry = Depends(get_detector_registry),
) -> dict:
    if event.source == COMMAND_CENTER_SOURCE:
        raise HTTPException(status_code=422, detail="This event source is reserved for trusted simulations")
    if db.execute(select(command_center_event(event.event_id))).scalar_one():
        raise HTTPException(status_code=409, detail="Event identifier is reserved")
    findings, assessment = await run_pipeline(event, db=db, registry=registry)
    return {
        "event_id": event.event_id,
        "findings": [f.model_dump(mode="json") for f in findings],
        "risk_assessment": assessment.model_dump(mode="json"),
    }


@router.get("", dependencies=[Depends(require_scopes("read"))])
async def list_events(limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0), db: Session = Depends(get_db)) -> list[dict]:
    repo = EventRepository(db)
    rows = repo.list_recent(limit=limit, offset=offset, actor=current_actor())
    return [repo.to_domain(r).model_dump(mode="json") for r in rows]


@router.get("/{event_id}", dependencies=[Depends(require_scopes("read"))])
async def get_event(event_id: str, db: Session = Depends(get_db)) -> dict:
    repo = EventRepository(db)
    row = repo.get(event_id, actor=current_actor())
    if row is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return repo.to_domain(row).model_dump(mode="json")
