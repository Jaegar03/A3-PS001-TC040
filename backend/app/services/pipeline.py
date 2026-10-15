"""The shared analysis pipeline: SecurityEvent -> applicable detectors ->
RiskEngine -> persistence -> audit log. Used by every ingestion path
(POST /analyze/file today; POST /events and the remaining /analyze/*
endpoints in later phases) so there is exactly one place this flow is
implemented (docs/architecture.md §3).
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Iterable
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.audit import service as audit_service
from app.detectors.registry import DetectorRegistry
from app.events.schema import SecurityEvent, SecurityEventType
from app.integrations.common import without_body
from app.risk.engine import RiskEngine
from app.schemas.detection import (
    AnalysisStatus,
    DetectionResult,
    FindingStatus,
    RecommendedAction,
    RiskAssessment,
    Severity,
)
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
    detector_allowlist: Iterable[str] | None = None,
    detector_results: list[DetectionResult] | None = None,
    preflight_errors: Iterable[str] = (),
    commit: bool = True,
    timeline: list[dict[str, str]] | None = None,
) -> tuple[list[DetectionResult], RiskAssessment]:
    """Run every applicable detector on `event`, then persist.

    `persist` lets a caller store a different (usually redacted) copy of the
    event than the one detectors analyzed — the webhook connectors hand the
    detectors the message body and persist hash + metadata instead, so raw
    message content never reaches the database (README principle 4,
    docs/privacy.md). It defaults to `event`, so every other caller is
    unchanged.
    """
    allowlist = set(detector_allowlist) if detector_allowlist is not None else None
    candidates = (registry.get(name) for name in sorted(allowlist)) if allowlist is not None else registry.all()
    detectors = [detector for detector in candidates if detector is not None and detector.applies_to(event)]

    async def _run_one(detector) -> tuple[DetectionResult | None, str | None]:
        try:
            result = DetectionResult.model_validate(await detector.analyze(event))
            if detector_results is not None:
                # Retain completed detectors even if a sibling later times
                # out and its caller cancels the aggregate task.
                detector_results.append(result)
            return result, None
        except TimeoutError:
            status = FindingStatus.TIMED_OUT
        except Exception:  # noqa: BLE001 - detector boundary must fail closed without exposing exceptions
            status = FindingStatus.INTERNAL_ERROR
        # Neither exception text nor traceback enters persisted output/logs.
        logger.warning("Detector %s returned %s on event %s", detector.name, status.value, event.event_id)
        failure = DetectionResult(
            detector=detector.name, category=detector.category, severity=Severity.SAFE,
            score=0, confidence=0, recommended_action=RecommendedAction.REVIEW, status=status,
        )
        if detector_results is not None:
            detector_results.append(failure)
        return failure, f"{detector.name}: {status.value}"

    results = await asyncio.gather(*(_run_one(d) for d in detectors))
    if timeline is not None:
        timeline.append({"stage": "detectors_completed", "timestamp": datetime.now(UTC).isoformat()})
    raw_results = [r for r, _ in results if r is not None]
    errors = [*preflight_errors, *(error for _, error in results if error)]
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
    if timeline is not None:
        timeline.append({"stage": "risk_assessed", "timestamp": assessment.generated_at.isoformat()})
    if errors:
        assessment = assessment.model_copy(update={
            "analysis_status": AnalysisStatus.PARTIAL_ANALYSIS,
            "analysis_errors": sorted(set(errors)),
        })

    stored_event = persist or event
    if stored_event.event_type in {
        SecurityEventType.GMAIL_MESSAGE,
        SecurityEventType.TELEGRAM_MESSAGE,
        SecurityEventType.WHATSAPP_MESSAGE,
    }:
        stored_event = without_body(stored_event)
    EventRepository(db).create_if_absent(stored_event, commit=commit)
    if timeline is not None:
        timeline.append({"stage": "event_staged", "timestamp": datetime.now(UTC).isoformat()})
    if assessment.severity.rank > 0:  # only persist an alert when there's something to alert on
        alerts = AlertRepository(db)
        existing = alerts.get_by_event(event.event_id)
        if existing is None:
            alerts.create(assessment, commit=commit)
        else:
            assessment = alerts.to_domain(existing)
        if timeline is not None:
            timeline.append({"stage": "alert_staged", "timestamp": datetime.now(UTC).isoformat()})
    audit_service.record(
        db,
        actor=actor or current_actor(),
        action="analyze",
        resource=f"event:{event.event_id}",
        detail={"severity": assessment.severity.value, "risk_score": assessment.risk_score},
        commit=commit,
    )

    return findings, assessment
