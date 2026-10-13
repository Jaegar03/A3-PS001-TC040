# Bounded scientific evaluation plan

## Scope and acceptance criteria

- Evaluate the existing local SQL-injection and prompt-injection detectors as
  deployed code, alongside one train-only character TF-IDF logistic-regression
  baseline and a validation-frozen hybrid selector.
- Use only existing local datasets when present and license metadata is
  available; otherwise use clearly authored, grouped fixtures. Do not download
  data, alter the database, or promote a model artifact.
- Normalize and exact-deduplicate records inside their source groups before any
  split. Keep every group in exactly one of train/validation/test using a
  deterministic seed; never row-randomize related records across splits.
- Fit the character TF-IDF vectorizer and logistic regression on train only.
  Choose the *lowest* validation score threshold whose validation FPR is at or
  below the configured budget. Freeze the selected hybrid method and threshold
  from validation, then evaluate rules, ML, and hybrid on the same untouched
  test records.
- Report per-method counts, confusion matrix, precision, recall, F1, average
  precision, continuous scores, threshold provenance, dataset file hashes,
  detector/model versions, git commit, and random seeds, plus explicit
  limitations and fallback-fixture status.
- Write JSON reports only to a new path and refuse to overwrite an existing
  output. No model files are written or copied to a promotion directory.

## Bounded procedure

1. Discover `research/datasets/raw/deepset_prompt_injections` and
   `research/datasets/raw/seclists_sqli` locally. Read only the files already
   present; otherwise construct small in-code authored fixtures with stable
   group ids and document that substitution.
2. Convert each record to `(text, label, group, source)`; normalize whitespace,
   Unicode compatibility form, and case for deduplication while retaining the
   original text for detector execution. Deduplicate within group, then make a
   seeded group split with non-empty class coverage where possible.
3. Score all split records through the actual async detector classes. Fit the
   baseline only on train text/labels. On validation, select the lowest
   score threshold meeting `FPR <= 0.01` (or report no feasible threshold),
   and select the hybrid policy/threshold on validation only.
4. Run the frozen rule, ML, and hybrid methods over the identical test split;
   calculate deterministic integer counts and metrics from continuous scores.
5. Write an immutable report under `research/validation/reports/`, print its
   path and exact measured summary, and retain no trained artifact.

## Checks

- Unit tests cover grouped normalized deduplication, split disjointness and
  determinism, lowest-feasible threshold selection, and metric/count
  calculation including continuous average precision.
- Run the focused framework tests and the CLI with
  `backend/.venv-audit/Scripts/python.exe`; inspect the resulting report and
  verify a second write to the same path is rejected.

## Known limits

The prompt corpus is a small publisher train/test dataset and SQL positives
are attack-list payloads rather than production traffic. Authored benign SQL
controls are not a representative negative distribution. Group identifiers are
source/fixture groupings, not a claim of semantic independence. Detector
scores are triage signals, not authorization decisions, and this bounded run
does not establish deployment readiness or promote a classifier.
