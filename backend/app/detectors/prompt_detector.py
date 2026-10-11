"""Prompt injection detector using transparent instruction-abuse heuristics."""
from __future__ import annotations

import re

from app.detectors.base import AvailabilityStatus, BaseDetector, DetectorAvailability
from app.detectors.common import action_for, event_text, noisy_or, safe_result, severity_from_score
from app.detectors.text.unicode_tools import inspect_hidden_text
from app.detectors.text.views import build_views
from app.events.schema import SecurityEvent, SecurityEventType
from app.schemas.detection import DetectionResult, DetectorCategory, Evidence

_PATTERNS = (
    ("instruction_override", re.compile(r"\b(ignore|disregard|forget|override)\b.{0,80}\b(instruction|system|policy|previous)\b", re.IGNORECASE), 0.72),
    ("role_impersonation", re.compile(r"\b(system message|developer message|you are now|act as|jailbreak|dan mode)\b", re.IGNORECASE), 0.58),
    ("secret_exfiltration", re.compile(r"\b(reveal|print|show|leak|exfiltrate)\b.{0,80}\b(system prompt|secret|token|password|credential)\b", re.IGNORECASE), 0.82),
    ("tool_abuse", re.compile(r"\b(call|invoke|execute|run)\b.{0,60}\b(tool|function|command|shell)\b", re.IGNORECASE), 0.45),
)


class PromptInjectionDetector(BaseDetector):
    name = "PromptInjectionDetector"
    version = "0.1.0"
    category = DetectorCategory.PROMPT_INJECTION
    applicable_event_types = frozenset({SecurityEventType.PROMPT_ANALYSIS, SecurityEventType.GMAIL_MESSAGE, SecurityEventType.TELEGRAM_MESSAGE, SecurityEventType.WHATSAPP_MESSAGE})

    async def is_available(self) -> DetectorAvailability:
        return DetectorAvailability(status=AvailabilityStatus.AVAILABLE, detail="Heuristic prompt-injection rules loaded")

    async def analyze(self, event: SecurityEvent) -> DetectionResult:
        text = event_text(event)
        if not text:
            return safe_result(self.name, self.category, confidence=0.78, model_version=self.version)
        report = inspect_hidden_text(text)
        evidence: list[Evidence] = []
        strengths: list[float] = []
        matched: set[str] = set()
        for view in build_views(text):
            for name, pattern, weight in _PATTERNS:
                if name == "tool_abuse":
                    continue
                if name in matched or not pattern.search(view.text):
                    continue
                matched.add(name)
                strengths.append(weight)
                evidence.append(Evidence(type=f"prompt:{name}", detail=f"Prompt injection heuristic matched in {view.name}: {name}", weight=weight))
        if matched and (report.anything_hidden or report.confusable_count):
            weight = min(0.55, 0.2 + 0.1 * int(report.anything_hidden) + 0.05 * min(report.confusable_count, 3))
            strengths.append(weight)
            evidence.append(Evidence(type="unicode_obfuscation", detail=f"Obfuscation accompanied a prompt signal; hidden={report.anything_hidden}; confusables={report.confusable_count}", weight=weight))
        score = noisy_or(strengths)
        if not score:
            return safe_result(self.name, self.category, confidence=0.78, model_version=self.version)
        severity = severity_from_score(score)
        return DetectionResult(detector=self.name, category=self.category, severity=severity, score=round(score, 4), confidence=round(min(.86, .62 + .06 * len(evidence)), 2), evidence=evidence, recommended_action=action_for(severity), model_version=self.version)
