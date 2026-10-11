"""The shared analysis pipeline: SecurityEvent -> applicable detectors ->
RiskEngine -> persistence -> audit log. Used by every ingestion path
(POST /analyze/file today; POST /events and the remaining /analyze/*
endpoints in later phases) so there is exactly one place this flow is
implemented (docs/architecture.md §3).
"""

from __future__ import annotations

import asyncio
import logging

from sqlalchemy.orm import Session

from app.audit import service as audit_service
from app.detectors.registry import DetectorRegistry
from app.events.schema import SecurityEvent
from app.risk.engine import RiskEngine
from app.schemas.detection import AnalysisStatus, DetectionResult, FindingStatus, RiskAssessment
from app.security.auth import current_actor
from app.services.alert_repository import AlertRepository
from app.services.event_repository import EventRepository

logger = logging.getLogger("sentivra.pipeline")

_risk_engine = RiskEngine()


async def run_pipeline(
    event: SecurityEvent,
    *,
    db: Session,
    registry: DetectorRegistry,
    actor: str | None = None,
    persist: SecurityEvent | None = None,
) -> tuple[list[DetectionResult], RiskAssessment]:
    """Run every applicable detector on `event`, then persist.

    `persist` lets a caller store a different (usually redacted) copy of the
    event than the one detectors analyzed — the webhook connectors hand the
    detectors the message body and persist hash + metadata instead, so raw
    message content never reaches the database (README principle 4,
    docs/privacy.md). It defaults to `event`, so every other caller is
    unchanged.
    """
    detectors = registry.applicable_to(event)

    async def _run_one(detector) -> tuple[DetectionResult | None, str | None]:
        try:
            return await detector.analyze(event), None
        except TimeoutError:
            logger.exception("Detector %s timed out on event %s", detector.name, event.event_id)
            return None, f"{detector.name}: timed_out"
        except Exception:
            logger.exception("Detector %s failed on event %s", detector.name, event.event_id)
            return None, f"{detector.name}: internal_error"

    results = await asyncio.gather(*(_run_one(d) for d in detectors))
    raw_results = [r for r, _ in results if r is not None]
    errors = [error for _, error in results if error]
    findings = [r for r in raw_results if r.severity.value != "SAFE"]

    degraded_statuses = {
        FindingStatus.PARTIAL_ANALYSIS,
        FindingStatus.INVALID_INPUT,
        FindingStatus.SCANNER_OR_MODEL_UNAVAILABLE,
        FindingStatus.TIMED_OUT,
        FindingStatus.INTERNAL_ERROR,
    }
    if any(r.status in degraded_statuses for r in raw_results):
        errors.extend(f"{r.detector}: {r.status.value}" for r in raw_results if r.status in degraded_statuses)

    assessment = _risk_engine.assess(event.event_id, findings)
    if errors:
        assessment = assessment.model_copy(update={
            "analysis_status": AnalysisStatus.PARTIAL_ANALYSIS,
            "analysis_errors": sorted(set(errors)),
        })

    EventRepository(db).create_if_absent(persist or event)
    if assessment.severity.rank > 0:  # only persist an alert when there's something to alert on
        AlertRepository(db).create(assessment)
    audit_service.record(
        db,
        actor=actor or current_actor(),
        action="analyze",
        resource=f"event:{event.event_id}",
        detail={"severity": assessment.severity.value, "risk_score": assessment.risk_score},
    )

    return findings, assessment
