"""Failure and missing-engine states must not be serialized as benign findings."""
from __future__ import annotations

import pytest

from app.detectors.base import AvailabilityStatus, BaseDetector, DetectorAvailability
from app.detectors.clamav_detector import ClamAVDetector
from app.detectors.registry import DetectorRegistry
from app.detectors.yara_detector import YaraDetector
from app.events.schema import SecurityEvent, SecurityEventType, SourceType
from app.schemas.detection import AnalysisStatus, DetectorCategory, FindingStatus, Severity


def _file_event() -> SecurityEvent:
    return SecurityEvent(event_type=SecurityEventType.FILE_ANALYSIS, source="test", source_type=SourceType.DEMO_DATA)


@pytest.mark.asyncio
async def test_yara_missing_rules_is_explicitly_unavailable(tmp_path):
    detector = YaraDetector(tmp_path)
    assert (await detector.is_available()).status == AvailabilityStatus.NOT_CONFIGURED
    result = await detector.analyze(_file_event())
    assert result.severity == Severity.SAFE
    assert result.status == FindingStatus.SCANNER_OR_MODEL_UNAVAILABLE


@pytest.mark.asyncio
async def test_clamav_missing_blob_is_partial_not_clean():
    result = await ClamAVDetector().analyze(_file_event())
    assert result.severity == Severity.SAFE
    assert result.status == FindingStatus.SCANNER_OR_MODEL_UNAVAILABLE


def test_partial_assessment_status_is_distinct_from_safe():
    from app.risk.engine import RiskEngine

    assessment = RiskEngine().assess("evt-partial", [])
    assessment = assessment.model_copy(update={
        "analysis_status": AnalysisStatus.PARTIAL_ANALYSIS,
        "analysis_errors": ["ClamAVDetector: scanner_or_model_unavailable"],
    })
    assert assessment.severity == Severity.SAFE
    assert assessment.analysis_status == AnalysisStatus.PARTIAL_ANALYSIS
    assert assessment.analysis_errors


@pytest.mark.asyncio
async def test_pipeline_detector_exception_is_partial_not_benign(db_session):
    from app.services.pipeline import run_pipeline

    class BrokenDetector(BaseDetector):
        name = "BrokenDetector"
        version = "test"
        category = DetectorCategory.LOG_ANOMALY
        applicable_event_types = frozenset({SecurityEventType.SYSTEM_LOG})

        async def is_available(self) -> DetectorAvailability:
            return DetectorAvailability(status=AvailabilityStatus.ERROR, detail="test")

        async def analyze(self, event):
            raise RuntimeError("fixture failure")

    registry = DetectorRegistry()
    registry.register(BrokenDetector())
    event = SecurityEvent(event_type=SecurityEventType.SYSTEM_LOG, source="test", source_type=SourceType.DEMO_DATA)
    _, assessment = await run_pipeline(event, db=db_session, registry=registry)
    assert assessment.severity == Severity.SAFE
    assert assessment.analysis_status == AnalysisStatus.PARTIAL_ANALYSIS
    assert "BrokenDetector: internal_error" in assessment.analysis_errors
