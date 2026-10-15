"""Persistence model for local, simulation-only command-center runs."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.models.orm import _utcnow, _uuid


class SimulationExecutionORM(Base):
    __tablename__ = "simulation_executions"
    __table_args__ = (
        UniqueConstraint("actor_id", "request_key", name="uq_simulation_actor_request_key"),
    )

    execution_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    # Simulation history is a private command-center surface.  The actor is
    # stored on the execution rather than inferred from a request at read time
    # so a later token change cannot disclose another actor's history.
    actor_id: Mapped[str] = mapped_column(String(128), index=True)
    request_key: Mapped[str] = mapped_column(String(128), index=True, default=_uuid)
    scenario_id: Mapped[str] = mapped_column(String(64), index=True)
    scenario_version: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(32), index=True)
    source_type: Mapped[str] = mapped_column(String(16), default="SIMULATED", index=True)
    event_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    alert_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    detection_state: Mapped[str] = mapped_column(String(32))
    enforcement_decision: Mapped[str] = mapped_column(String(32))
    duration_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    result_json: Mapped[str] = mapped_column(Text)
    error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
