"""GET /api/v1/audit — the append-only audit log, newest first. Read-only:
there is no endpoint that edits or deletes audit rows."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.models.orm import AlertORM, AuditLogORM, EventORM
from app.security.auth import current_actor, require_scopes
from app.services.simulation_visibility import command_center_event

router = APIRouter(prefix="/api/v1", tags=["audit"], dependencies=[Depends(require_scopes("read"))])


@router.get("/audit")
async def list_audit(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    action: str | None = Query(None, max_length=128),
    db: Session = Depends(get_db),
) -> dict:
    stmt = select(AuditLogORM)
    count = select(func.count()).select_from(AuditLogORM)
    simulation_resource = or_(
        AuditLogORM.resource.in_(select("event:" + EventORM.event_id).where(
            command_center_event(EventORM.event_id))),
        AuditLogORM.resource.in_(select("alert:" + AlertORM.alert_id).where(
            command_center_event(AlertORM.event_id))),
    )
    visible = or_(~simulation_resource, AuditLogORM.actor == current_actor())
    stmt, count = stmt.where(visible), count.where(visible)
    if action:
        stmt = stmt.where(AuditLogORM.action == action)
        count = count.where(AuditLogORM.action == action)
    rows = db.execute(stmt.order_by(AuditLogORM.created_at.desc()).offset(offset).limit(limit)).scalars()
    return {
        "total": db.execute(count).scalar_one(),
        "entries": [
            {"id": r.id, "created_at": r.created_at.isoformat(), "actor": r.actor, "action": r.action,
             "resource": r.resource, "detail": json.loads(r.detail_json or "{}")}
            for r in rows
        ],
    }
