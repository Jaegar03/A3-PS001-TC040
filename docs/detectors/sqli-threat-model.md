# SQL Injection Detector Threat Model

## In scope

The detector receives one bounded text value through `/api/v1/analyze/sql`, or
the text attached to a normalized text-analysis event. It performs URL/HTML/
Unicode normalization, timeout-bounded rule matching, and lexical structure
analysis. It does not execute SQL, connect to a database, or prove that an
application concatenated the value into a query.

## Signals and failure modes

- Rules catch common boolean, UNION, stacked-query, time/error-based, schema,
  file/command and NoSQL operator patterns.
- The lexer catches structure that does not depend on one exact spelling.
- Attack-only public lists are useful for regression coverage but do not model
  benign application traffic. The local report therefore is not a production
  FPR estimate.
- A novel dialect, second-order construction, server-side concatenation, or a
  payload assembled from multiple fields can evade single-input analysis.
- A match is a triage signal. Prevention still requires parameterized queries,
  allowlists for identifiers, least privilege, and safe database APIs.

## Evidence status

`research/evaluation/text/report.json` records the locally run comparison of
rules and a non-shipped character/word TF-IDF baseline. The classifier is not
registered because it did not beat the rules baseline on the held-out source
split under a meaningful generalization claim.
