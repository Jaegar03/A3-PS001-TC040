"""Idempotent local dataset acquisition helper.

Phase-4 sources are downloaded by the existing verified fetcher. Network
sources intentionally stop with manual instructions because their archives and
terms change; this script never guesses a URL or bypasses registration.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", choices=("phase4", "cicids2017", "unsw_nb15"))
    args = parser.parse_args()
    if args.source == "phase4":
        return subprocess.call([sys.executable, str(ROOT / "research/datasets/fetch_datasets.py"), "deepset", "seclists", "phiusiil"], cwd=ROOT)
    if args.source == "cicids2017":
        print("Manual step required: obtain CICIDS2017 from https://www.unb.ca/cic/datasets/ids-2017.html")
        print("Place the licensed CICFlowMeter CSV files under research/datasets/raw/cicids2017/ and record SHA-256 in MANIFEST.csv.")
    else:
        print("Manual step required: obtain UNSW-NB15 from https://research.unsw.edu.au/projects/unsw-nb15-dataset")
        print("Place the licensed files under research/datasets/raw/unsw_nb15/ and record SHA-256 in MANIFEST.csv.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
