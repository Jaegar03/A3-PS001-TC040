"""Local reproducibility entry point for audit experiments.

This deliberately fails closed when a requested public dataset is unavailable.
It never uploads data, uses hosted notebooks, or invents a result. The current
checkout can reproduce the synthetic network baseline and the local dataset
manifest; public network evaluation is reported as pending until its files are
present and checksummed.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _run(label: str, command: list[str]) -> dict:
    print(f"[{label}] {' '.join(command)}")
    completed = subprocess.run(command, check=False, cwd=ROOT, text=True)
    return {"label": label, "command": command, "returncode": completed.returncode}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--network-synthetic", action="store_true")
    parser.add_argument("--download-phase4", action="store_true")
    args = parser.parse_args()
    python = sys.executable
    results: list[dict] = []
    if args.download_phase4:
        results.append(_run("download-phase4", [python, "research/datasets/fetch_datasets.py", "deepset", "seclists", "phiusiil"]))
    if args.network_synthetic:
        results.append(_run("network-synthetic", [python, "research/experiments/train_network_models.py"]))
    network_files = list((ROOT / "research/datasets/raw/cicids2017").glob("**/*")) + list((ROOT / "research/datasets/raw/unsw_nb15").glob("**/*"))
    results.append({"label": "public-network-data", "available": bool(network_files), "status": "available" if network_files else "blocked_pending_download_and_checksum"})
    report = {"generated_at": datetime.now(UTC).isoformat(), "results": results}
    out = ROOT / "research/evaluation/run_all_report.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {out.relative_to(ROOT)}")
    return 1 if any(r.get("returncode", 0) != 0 for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
