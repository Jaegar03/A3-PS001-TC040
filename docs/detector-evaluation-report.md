# Detector Evaluation Report (Audit Branch)

Generated from local runs on 2026-10-11. Raw third-party data is present only
under gitignored `research/datasets/raw/`; checksums are recorded in the
manifest. No hosted service or telemetry was used.

## Text detector results

Command:

```powershell
backend\.venv-audit\Scripts\python research\experiments\evaluate_text_detectors.py
backend\.venv-audit\Scripts\python research\experiments\evaluate_url_detector.py
```

Reports: `research/evaluation/text/report.json` and
`research/evaluation/text/url_report.json`.

| Task / evaluated path | Precision | Recall | F1 | FPR | Interpretation |
|---|---:|---:|---:|---:|---|
| Prompt rules / deepset publisher test | 1.0000 | 0.0667 | 0.1250 | 0.0000 | Very conservative; misses most held-out positives in this small benchmark |
| Prompt TF-IDF linear baseline | 1.0000 | 0.0167 | 0.0328 | 0.0000 | Does not improve the rules baseline at the 1% FPR threshold |
| SQL rules / held-out SecLists source + authored negatives | 1.0000 | 1.0000 | 1.0000 | 0.0000 | Strong on this attack-list benchmark only; not a production FPR estimate |
| SQL TF-IDF linear baseline | 1.0000 | 0.0938 | 0.1714 | 0.0000 | Worse than rules on this held-out source split |
| URL local heuristic / 20,000 PhiUSIIL sample | 0.9764 | 0.5537 | 0.7067 | 0.0134 | Misses many positives and exceeds a 1% FPR budget at score > 0 |

The prompt and SQL classifiers were trained in memory for comparison only. No
ML artifact was promoted to `models/`: the measured baselines did not justify
replacing the transparent rule paths, and the datasets have known coverage and
sampling limitations. The URL result uses a deterministic score and a
stratified sample; it is not calibrated probability or reputation evidence.

## Network

The synthetic network training script was rerun locally through:

```powershell
backend\.venv-audit\Scripts\python research\run_all.py --network-synthetic
```

The measured synthetic fused-model result was precision 0.915, recall 0.849,
F1 0.881, FPR 0.0070; fused models plus behavior rules measured precision
0.927, recall 1.000, F1 0.962, FPR 0.0070. These are synthetic-generator
results only. CICIDS2017 and UNSW-NB15 public-data evaluation remains pending;
no real-traffic performance claim is made.
