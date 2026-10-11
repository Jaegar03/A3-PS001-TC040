# Prompt-Injection Experiment Plan

## Hypothesis

The existing bounded heuristic detector will provide a transparent baseline.
A character/word TF-IDF linear classifier may improve recall on the publisher's
held-out examples, but its result must be compared with source and attack-family
limitations rather than treated as a general security guarantee.

## Data and split

- `deepset/prompt-injections`, Apache-2.0, publisher `train` and `test` files
  downloaded into `research/datasets/raw/deepset_prompt_injections/`.
- The publisher split is preserved; no row is moved between train and test.
- The small dataset and unknown paraphrase/template overlap are explicit
  limitations. Authored hard negatives are evaluated separately and are not
  silently mixed into the publisher test score.
- Prompt Guard references are not downloaded or bundled by this branch.

## Metrics and budget

Primary: recall at FPR <= 1% on the held-out test set. Secondary: precision,
F1, PR-AUC, confusion matrix, p50/p95 CPU latency, and model size. Thresholds
are selected on a validation slice of the published training split only.

## Release rule

Do not replace the heuristic detector with a model based on a small or leaky
benchmark. If ML is retained, it remains a separate attributable signal and
the rule path remains available.
