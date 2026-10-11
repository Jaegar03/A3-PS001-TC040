"""Evaluate existing text rules against small local datasets and linear baselines.

No model is promoted to ``models/`` by this script. It writes measured
comparisons and keeps the rule path as the baseline. Run from the repository:

    backend/.venv-audit/Scripts/python research/experiments/evaluate_text_detectors.py
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import statistics
import time
from pathlib import Path

import numpy as np
from app.detectors.prompt_detector import PromptInjectionDetector
from app.detectors.sqli_detector import SQLInjectionDetector
from app.events.schema import SecurityEvent, SecurityEventType, SourceType
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.pipeline import FeatureUnion

ROOT = Path(__file__).resolve().parents[2]
RAW = ROOT / "research/datasets/raw"
OUT = ROOT / "research/evaluation/text"
SEED = 20261011


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def threshold_at_fpr(y: np.ndarray, scores: np.ndarray, max_fpr: float = .01) -> float:
    candidates = sorted({float(x) for x in scores}, reverse=True)
    for threshold in candidates:
        pred = scores >= threshold
        negatives = y == 0
        if negatives.sum() and float(pred[negatives].mean()) <= max_fpr:
            return threshold
    return float("inf")


def score(y: np.ndarray, pred: np.ndarray, scores: np.ndarray, threshold: float | None = None) -> dict:
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {
        "precision": round(float(precision_score(y, pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y, pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y, pred, zero_division=0)), 4),
        "fpr": round(float(fp / max(fp + tn, 1)), 4),
        "pr_auc": round(float(average_precision_score(y, scores)), 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "threshold": threshold,
    }


def vectorizer() -> FeatureUnion:
    return FeatureUnion([
        ("word", TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True, max_features=80_000)),
        ("char", TfidfVectorizer(analyzer="char", ngram_range=(3, 5), min_df=1, sublinear_tf=True, max_features=80_000)),
    ])


def train_linear(train_text: list[str], train_y: np.ndarray, val_text: list[str], val_y: np.ndarray, test_text: list[str], test_y: np.ndarray) -> dict:
    features = vectorizer()
    x_train = features.fit_transform(train_text)
    x_val = features.transform(val_text)
    x_test = features.transform(test_text)
    model = LogisticRegression(max_iter=500, class_weight="balanced", random_state=SEED, solver="liblinear")
    model.fit(x_train, train_y)
    val_scores = model.predict_proba(x_val)[:, 1]
    threshold = threshold_at_fpr(val_y, val_scores)
    test_scores = model.predict_proba(x_test)[:, 1]
    return score(test_y, (test_scores >= threshold).astype(int), test_scores, threshold)


async def detector_scores(detector, texts: list[str], event_type: SecurityEventType) -> tuple[np.ndarray, float]:
    scores: list[float] = []
    elapsed: list[float] = []
    for text in texts:
        event = SecurityEvent(event_type=event_type, source="research", source_type=SourceType.LIVE, metadata={"analysis_text": text})
        started = time.perf_counter()
        result = await detector.analyze(event)
        elapsed.append((time.perf_counter() - started) * 1000)
        scores.append(result.score)
    return np.asarray(scores), statistics.median(elapsed) if elapsed else 0.0


def prompt_data() -> tuple[list[str], np.ndarray, list[str], np.ndarray, list[str]]:
    base = RAW / "deepset_prompt_injections"
    train = [json.loads(line) for line in (base / "train.jsonl").read_text(encoding="utf-8").splitlines()]
    test = [json.loads(line) for line in (base / "test.jsonl").read_text(encoding="utf-8").splitlines()]
    rng = np.random.default_rng(SEED)
    indices = rng.permutation(len(train))
    cut = int(len(indices) * .8)
    tr, va = indices[:cut], indices[cut:]
    return ([train[i]["text"] for i in tr], np.asarray([train[i]["label"] for i in tr]),
            [train[i]["text"] for i in va], np.asarray([train[i]["label"] for i in va]),
            [json.dumps(x, ensure_ascii=False) for x in test])


def sql_data() -> tuple[list[str], np.ndarray, list[str], np.ndarray, list[str], np.ndarray]:
    source_files = sorted((RAW / "seclists_sqli").glob("*.txt"))
    held_out = source_files[-1]
    train_pos = [x.strip() for p in source_files if p != held_out for x in p.read_text(encoding="utf-8", errors="replace").splitlines() if x.strip()]
    test_pos = [x.strip() for x in held_out.read_text(encoding="utf-8", errors="replace").splitlines() if x.strip()]
    negatives = [
        "SELECT name FROM users WHERE id = ?",
        "The report says SELECT and UNION are SQL keywords.",
        "https://example.com/search?q=union+station",
        "Database error: column not found in requested projection",
        "O'Brien visited the UNION station and selected a plan.",
        "UPDATE the documentation after review; do not execute this text.",
        "SELECT * FROM inventory WHERE sku = :sku",
        "The word OR appears in ordinary prose.",
    ] * 20
    rng = np.random.default_rng(SEED)
    rng.shuffle(negatives)
    train_neg, test_neg = negatives[:120], negatives[120:]
    val_pos = train_pos[: max(1, len(train_pos) // 5)]
    fit_pos = train_pos[max(1, len(train_pos) // 5):]
    return (fit_pos + train_neg[:80], np.r_[np.ones(len(fit_pos), dtype=int), np.zeros(80, dtype=int)],
            val_pos + train_neg[80:120], np.r_[np.ones(len(val_pos), dtype=int), np.zeros(40, dtype=int)],
            test_pos + test_neg, np.r_[np.ones(len(test_pos), dtype=int), np.zeros(len(test_neg), dtype=int)])


async def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((RAW / "MANIFEST.json").read_text(encoding="utf-8"))
    report: dict = {"seed": SEED, "datasets": manifest, "notes": ["No model artifacts are promoted by this evaluation script."]}

    if (RAW / "deepset_prompt_injections/test.jsonl").exists():
        train_x, train_y, val_x, val_y, test_rows = prompt_data()
        test = [json.loads(x) for x in test_rows]
        test_x, test_y = [r["text"] for r in test], np.asarray([r["label"] for r in test])
        detector = PromptInjectionDetector()
        rule_scores, rule_p50 = await detector_scores(detector, test_x, SecurityEventType.PROMPT_ANALYSIS)
        report["prompt_injection"] = {
            "dataset": "deepset/prompt-injections",
            "split": "publisher train/test; 80/20 validation slice from train, seed 20261011",
            "rules": score(test_y, (rule_scores > 0).astype(int), rule_scores),
            "linear_tfidf": train_linear(train_x, train_y, val_x, val_y, test_x, test_y),
            "rule_latency_p50_ms": round(rule_p50, 4),
            "limitations": ["Small publisher dataset; paraphrase/source leakage cannot be ruled out from the published files.", "Rules and model scores are triage signals, not authorization decisions."],
        }

    if (RAW / "seclists_sqli").exists():
        train_x, train_y, val_x, val_y, test_x, test_y = sql_data()
        detector = SQLInjectionDetector()
        rule_scores, rule_p50 = await detector_scores(detector, test_x, SecurityEventType.SQL_ANALYSIS)
        report["sql_injection"] = {
            "dataset": "SecLists SQLi payload lists plus authored benign controls",
            "split": "one source file held out; negatives authored locally; seed 20261011",
            "rules": score(test_y, (rule_scores > 0).astype(int), rule_scores),
            "linear_tfidf": train_linear(train_x, train_y, val_x, val_y, test_x, test_y),
            "rule_latency_p50_ms": round(rule_p50, 4),
            "limitations": ["Positive source lists are attack-only and not representative of production traffic.", "No classifier is promoted without a stronger grouped benchmark and license review."],
        }

    report["generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    (OUT / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote {OUT / 'report.json'}")


if __name__ == "__main__":
    asyncio.run(main())
