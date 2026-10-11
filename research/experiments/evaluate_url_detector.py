"""Evaluate local URL heuristics on a deterministic stratified PhiUSIIL sample.

PhiUSIIL's label semantics are recorded in the report: label 1 is legitimate
and is inverted to ``is_phishing`` for this evaluation. This is a dataset
benchmark, not a production reputation claim.
"""
from __future__ import annotations

import asyncio
import csv
import hashlib
import json
import time
from pathlib import Path

import numpy as np
from app.detectors.url_detector import URLDetector
from app.events.schema import SecurityEvent, SecurityEventType, SourceType
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

ROOT = Path(__file__).resolve().parents[2]
CSV_PATH = next((ROOT / "research/datasets/raw/phiusiil").glob("*.csv"))
SEED = 20261011
SAMPLE_PER_CLASS = 10_000


async def main() -> None:
    rows: list[tuple[str, int]] = []
    with CSV_PATH.open(encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            url = row.get("URL", "").strip()
            if url:
                rows.append((url, int(row["label"])))
    rng = np.random.default_rng(SEED)
    sample: list[tuple[str, int]] = []
    for label in (0, 1):
        group = [r for r in rows if r[1] == label]
        sample.extend(group[i] for i in rng.permutation(len(group))[:SAMPLE_PER_CLASS])

    detector = URLDetector()
    y: list[int] = []
    scores: list[float] = []
    latencies: list[float] = []
    for url, source_label in sample:
        event = SecurityEvent(event_type=SecurityEventType.URL_ANALYSIS, source="research", source_type=SourceType.LIVE, metadata={"analysis_url": url})
        started = time.perf_counter()
        result = await detector.analyze(event)
        latencies.append((time.perf_counter() - started) * 1000)
        # PhiUSIIL label 1 is legitimate; detection target is phishing.
        y.append(1 - source_label)
        scores.append(result.score)
    y_arr, score_arr = np.asarray(y), np.asarray(scores)
    # No learned threshold exists; the detector's score becomes a finding at >0.
    pred = (score_arr > 0).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_arr, pred, labels=[0, 1]).ravel()
    report = {
        "dataset": "PhiUSIIL Phishing URL Dataset",
        "source_sha256": hashlib.sha256(CSV_PATH.read_bytes()).hexdigest(),
        "license": "CC BY 4.0",
        "label_note": "source label 1 is legitimate; evaluation target is_phishing = 1 - source label",
        "sample": {"per_class": SAMPLE_PER_CLASS, "total": len(sample), "seed": SEED, "not_full_dataset": True},
        "threshold": "score > 0 (deterministic heuristic finding)",
        "metrics": {
            "precision": round(float(precision_score(y_arr, pred, zero_division=0)), 4),
            "recall": round(float(recall_score(y_arr, pred, zero_division=0)), 4),
            "f1": round(float(f1_score(y_arr, pred, zero_division=0)), 4),
            "fpr": round(float(fp / max(fp + tn, 1)), 4),
            "pr_auc": round(float(average_precision_score(y_arr, score_arr)), 4),
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
            "latency_ms": {"p50": round(float(np.percentile(latencies, 50)), 4), "p95": round(float(np.percentile(latencies, 95)), 4)},
        },
        "limitations": ["PhiUSIIL legitimate examples are homepage-heavy and may not represent legitimate deep links.", "This local detector does not fetch URLs, resolve DNS, or use reputation feeds.", "The score is a triage heuristic, not calibrated phishing probability."],
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    out = ROOT / "research/evaluation/text/url_report.json"
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {out}")


if __name__ == "__main__":
    asyncio.run(main())
