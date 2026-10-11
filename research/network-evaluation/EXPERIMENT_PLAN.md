# Network Public-Data Experiment Plan

## Hypothesis

The current synthetic-trained network artifacts demonstrate plumbing but do not
establish external validity. Training/evaluating on CICIDS2017 and evaluating
UNSW-NB15 independently may expose feature-schema and distribution failures.

## Split and preprocessing

- CICIDS2017: chronological/day-aware split; benign-only training for
  unsupervised layers; attack-family holdout for the supervised layer.
- UNSW-NB15: independent in-dataset benchmark unless a documented common
  feature subset is proven compatible. No blind dataset merge.
- Fit scalers and feature transforms on train only. Thresholds are selected on
  calibration only; test is scored once.

## Metrics and budget

Report precision, recall, F1, FPR, PR-AUC, recall at FPR 1%, confusion matrix,
p50/p95 CPU latency, memory, artifact size, and load time. Include bootstrap
95% intervals where the sample design supports it.

## Current status

The public network files are not yet present in this checkout. The existing
synthetic report remains the before baseline; no external-data metric may be
written until the downloader, checksum manifest, and evaluation script produce
it locally.
