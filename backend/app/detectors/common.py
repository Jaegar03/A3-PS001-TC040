"""Scoring helpers shared by the text/URL detectors, so every detector maps
scores to severities and actions the same way the RiskEngine does."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from app.schemas.detection import (
    DetectionResult,
    DetectorCategory,
    FindingStatus,
    RecommendedAction,
    Severity,
)

MAX_ANALYSIS_CHARS = 12_000


def bounded_text(value: Any, *, limit: int = MAX_ANALYSIS_CHARS) -> str:
    return "" if value is None else str(value)[:limit]


def event_text(event: Any, *, limit: int = MAX_ANALYSIS_CHARS) -> str:
    metadata = getattr(event, "metadata", {}) or {}
    if metadata.get("analysis_text") not in (None, ""):
        return bounded_text(metadata["analysis_text"], limit=limit)
    content = getattr(event, "content", None)
    if content is None:
        return ""
    return bounded_text("\n".join(p for p in (content.subject or "", content.body or "") if p), limit=limit)


def event_urls(event: Any, *, limit: int = 32) -> list[str]:
    metadata = getattr(event, "metadata", {}) or {}
    if metadata.get("analysis_url") not in (None, ""):
        return [bounded_text(metadata["analysis_url"], limit=2048)]
    content = getattr(event, "content", None)
    return [bounded_text(u, limit=2048) for u in (getattr(content, "urls", []) if content else [])[:limit] if u]

# Same cut points as app.risk.engine, so a detector's own severity label
# and the aggregate label never disagree about what a score means.
_SEVERITY_CUTS = (
    (0.90, Severity.CRITICAL),
    (0.70, Severity.HIGH),
    (0.40, Severity.MEDIUM),
    (0.15, Severity.LOW),
)


def severity_from_score(score: float) -> Severity:
    for cut, severity in _SEVERITY_CUTS:
        if score >= cut:
            return severity
    return Severity.SAFE


def action_for(severity: Severity) -> RecommendedAction:
    if severity.rank >= Severity.HIGH.rank:
        return RecommendedAction.BLOCK
    if severity == Severity.MEDIUM:
        return RecommendedAction.REVIEW
    if severity == Severity.LOW:
        return RecommendedAction.MONITOR
    return RecommendedAction.ALLOW


def noisy_or(strengths: Iterable[float]) -> float:
    """Combine independent signal strengths in [0, 1]: 1 - prod(1 - s).
    Two moderate signals add up to more than either alone, but the result
    never exceeds 1 and a single weak signal stays weak."""
    remaining = 1.0
    for s in strengths:
        remaining *= 1.0 - max(0.0, min(1.0, s))
    return 1.0 - remaining


def safe_result(
    detector: str,
    category: DetectorCategory,
    *,
    confidence: float = 0.0,
    model_version: str | None = None,
) -> DetectionResult:
    return DetectionResult(
        detector=detector,
        category=category,
        severity=Severity.SAFE,
        score=0.0,
        confidence=confidence,
        evidence=[],
        recommended_action=RecommendedAction.ALLOW,
        status=FindingStatus.NO_FINDING_OBSERVED,
        model_version=model_version,
    )
