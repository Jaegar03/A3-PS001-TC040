"""Local URL heuristics. URLs are parsed only; they are never fetched."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

import tldextract

from app.detectors.base import AvailabilityStatus, BaseDetector, DetectorAvailability
from app.detectors.common import action_for, event_text, event_urls, noisy_or, safe_result, severity_from_score
from app.events.schema import SecurityEvent, SecurityEventType
from app.schemas.detection import DetectionResult, DetectorCategory, Evidence

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())


class URLDetector(BaseDetector):
    name = "URLDetector"
    version = "0.1.0"
    category = DetectorCategory.PHISHING
    applicable_event_types = frozenset({SecurityEventType.URL_ANALYSIS, SecurityEventType.BROWSER_URL, SecurityEventType.GMAIL_MESSAGE, SecurityEventType.TELEGRAM_MESSAGE, SecurityEventType.WHATSAPP_MESSAGE})

    async def is_available(self) -> DetectorAvailability:
        return DetectorAvailability(status=AvailabilityStatus.AVAILABLE, detail="Local URL parser and heuristic rules loaded")

    async def analyze(self, event: SecurityEvent) -> DetectionResult:
        urls = event_urls(event)
        if not urls:
            urls = re.findall(r"https?://[^\s<>\"']+", event_text(event), flags=re.IGNORECASE)[:32]
        if not urls:
            return safe_result(self.name, self.category, confidence=.72, model_version=self.version)
        signals: list[tuple[str, float]] = []
        for url in urls:
            parsed = urlparse(url)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                signals.append(("invalid_or_unsupported_url", .25))
                continue
            host = (parsed.hostname or "").lower().rstrip(".")
            if "@" in parsed.netloc:
                signals.append(("userinfo_obfuscation", .65))
            if _is_ip(host):
                signals.append(("literal_ip_host", .35))
            elif host and not _EXTRACT(host).top_domain_under_public_suffix:
                signals.append(("unregistered_or_local_domain", .25))
            if host.count(".") >= 4 or len(host) > 60:
                signals.append(("unusually_complex_host", .4))
            if len(url) > 240 or re.search(r"(?:%25){2,}|%00", url, re.I):
                signals.append(("encoded_or_oversized_url", .35))
            if parsed.scheme == "http":
                signals.append(("unencrypted_transport", .15))
        score = noisy_or(weight for _, weight in signals)
        if not signals or score < .15:
            return safe_result(self.name, self.category, confidence=.72, model_version=self.version)
        evidence = [Evidence(type=f"url:{name}", detail=f"Local heuristic review: {name}; not proof of phishing", weight=weight) for name, weight in signals]
        severity = severity_from_score(score)
        return DetectionResult(detector=self.name, category=self.category, severity=severity, score=round(score, 4), confidence=.74, evidence=evidence, recommended_action=action_for(severity), model_version=self.version)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False
