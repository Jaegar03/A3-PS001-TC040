"""Rule and lexical SQL/NoSQL injection detector.

The detector deliberately does not execute or connect to a database.  It
normalizes attacker-controlled input, runs the reviewed rule pack with the
same timeout guard as the other rule engines, and combines independent
signals into an explainable result.
"""
from __future__ import annotations

import logging

from app.core.rules import RuleTimeout, compile_pattern_rules, load_yaml, rules_path
from app.detectors.base import AvailabilityStatus, BaseDetector, DetectorAvailability
from app.detectors.common import action_for, bounded_text, event_text, noisy_or, safe_result, severity_from_score
from app.detectors.sqli.lexer import analyze as lexical_analyze
from app.detectors.sqli.normalizer import build_sqli_views
from app.events.schema import SecurityEvent, SecurityEventType
from app.schemas.detection import DetectionResult, DetectorCategory, Evidence

logger = logging.getLogger("sentivra.sqli")


class SQLInjectionDetector(BaseDetector):
    name = "SQLInjectionDetector"
    version = "0.1.0"
    category = DetectorCategory.SQL_INJECTION
    applicable_event_types = frozenset({SecurityEventType.SQL_ANALYSIS, SecurityEventType.TEXT_ANALYSIS})

    def __init__(self) -> None:
        raw = load_yaml(rules_path("custom", "sql_injection.yaml")) or {}
        self.rules = compile_pattern_rules(raw.get("rules", []))

    async def is_available(self) -> DetectorAvailability:
        if not self.rules:
            return DetectorAvailability(status=AvailabilityStatus.NOT_CONFIGURED, detail="No SQLi rules loaded")
        return DetectorAvailability(status=AvailabilityStatus.AVAILABLE, detail=f"{len(self.rules)} SQLi rules loaded")

    async def analyze(self, event: SecurityEvent) -> DetectionResult:
        text = event_text(event)
        if not text:
            return safe_result(self.name, self.category, confidence=0.5, model_version=self.version)
        views = build_sqli_views(bounded_text(text))
        hits = []
        for rule in self.rules:
            view = views.raw if rule.extra.get("view") == "raw" else views.normalized
            try:
                if rule.search(view):
                    hits.append(rule)
            except RuleTimeout:
                logger.warning("SQLi rule timed out: %s", rule.id)
        lexical = lexical_analyze(text)
        strongest_by_category: dict[str, float] = {}
        for rule in hits:
            strongest_by_category[rule.category] = max(strongest_by_category.get(rule.category, 0.0), rule.weight)
        signals = list(strongest_by_category.values())
        if lexical.strength and not hits:
            signals.append(min(0.95, lexical.strength))
        score = noisy_or(signals)
        if views.url_decode_rounds >= 2 or views.unicode_folded:
            score = min(1.0, score + 0.05)
        if not score:
            return safe_result(self.name, self.category, confidence=0.85, model_version=self.version)
        evidence = [Evidence(type=f"rule:{r.id}", detail=r.description, weight=r.weight) for r in hits]
        if lexical.signals:
            evidence.append(Evidence(type="lexical_structure", detail="SQL lexical signals: " + ", ".join(lexical.signals), weight=lexical.strength))
        evidence.extend(Evidence(type="normalization", detail=n) for n in views.notes)
        severity = severity_from_score(score)
        return DetectionResult(detector=self.name, category=self.category, severity=severity,
            score=round(score, 4), confidence=round(min(0.88, 0.62 + 0.04 * min(len(strongest_by_category), 4)), 2),
            evidence=evidence, recommended_action=action_for(severity), model_version=self.version)
