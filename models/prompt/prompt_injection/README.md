# Prompt-injection classifier: not trained

The deepset/prompt-injections dataset (Apache-2.0) is downloaded, but no model is trained. The runtime detector is a bounded, explainable heuristic layer; it does not claim trained-model accuracy.

This folder is tracked so the model registry lists the model as `trained: false` (Models page, `GET /api/v1/models`) on every checkout. A model becomes available only when its training script writes `metadata.json` with the artifact's SHA-256 next to the artifact.
