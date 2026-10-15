"""AlertRepository — persists RiskAssessment results as queryable alerts."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.orm import AlertORM
from app.schemas.detection import RiskAssessment, Severity
from app.services.simulation_visibility import operational_event, visible_event

ALERT_STATUSES = ("OPEN", "ACKNOWLEDGED", "RESOLVED")
ALERT_DISPOSITIONS = ("TRUE_POSITIVE", "FALSE_POSITIVE", "BENIGN_INTERESTING", "DUPLICATE")


class AlertRepository:
    def __init__(self, db: Session) -> None:
        self._db = db

    def create(self, assessment: RiskAssessment, *, commit: bool = True) -> AlertORM:
        row = AlertORM(
            alert_id=assessment.assessment_id,
            event_id=assessment.event_id,
            risk_score=assessment.risk_score,
            severity=assessment.severity.value,
            classification=assessment.classification,
            confidence=assessment.confidence,
            assessment_json=assessment.model_dump_json(),
        )
        self._db.add(row)
        self._db.flush()
        if commit:
            self._db.commit()
        self._db.refresh(row)
        return row

    def get(self, alert_id: str, *, actor: str | None = None) -> AlertORM | None:
        stmt = select(AlertORM).where(AlertORM.alert_id == alert_id)
        if actor is not None:
            stmt = stmt.where(visible_event(AlertORM.event_id, actor))
        return self._db.execute(stmt).scalars().first()

    def get_by_event(self, event_id: str) -> AlertORM | None:
        """Return the existing alert for an event, if one was already raised."""
        stmt = select(AlertORM).where(AlertORM.event_id == event_id).order_by(AlertORM.created_at.asc())
        return self._db.execute(stmt).scalars().first()

    def list_recent(
        self,
        limit: int = 50,
        offset: int = 0,
        min_severity_rank: int = 0,
        status: str | None = None,
        actor: str | None = None,
    ) -> list[AlertORM]:
        # Filters go into the query, before LIMIT, so a filtered page is full
        # whenever enough matching alerts exist.
        stmt = select(AlertORM)
        if actor is not None:
            stmt = stmt.where(visible_event(AlertORM.event_id, actor))
        if min_severity_rank > 0:
            allowed = [s.value for s in Severity if s.rank >= min_severity_rank]
            stmt = stmt.where(AlertORM.severity.in_(allowed))
        if status:
            stmt = stmt.where(AlertORM.status == status)
        stmt = stmt.order_by(AlertORM.created_at.desc()).offset(offset).limit(limit)
        return list(self._db.execute(stmt).scalars())

    def since(self, cutoff: datetime, limit: int = 5000, *, operational_only: bool = False) -> list[AlertORM]:
        stmt = select(AlertORM).where(AlertORM.created_at >= cutoff).order_by(AlertORM.created_at.desc()).limit(limit)
        if operational_only:
            stmt = stmt.where(operational_event(AlertORM.event_id))
        return list(self._db.execute(stmt).scalars())

    def set_status(self, row: AlertORM, status: str) -> AlertORM:
        if status not in ALERT_STATUSES:
            raise ValueError(f"status must be one of {ALERT_STATUSES}")
        row.status = status
        self._db.commit()
        self._db.refresh(row)
        return row

    def set_disposition(self, row: AlertORM, disposition: str | None, note: str | None, actor: str) -> AlertORM:
        if disposition is not None and disposition not in ALERT_DISPOSITIONS:
            raise ValueError(f"disposition must be one of {ALERT_DISPOSITIONS}")
        row.disposition = disposition
        row.disposition_note = note
        row.disposition_by = actor if disposition else None
        row.disposition_at = datetime.now(UTC) if disposition else None
        self._db.commit()
        self._db.refresh(row)
        return row

    def to_domain(self, row: AlertORM) -> RiskAssessment:
        return RiskAssessment.model_validate_json(row.assessment_json)
