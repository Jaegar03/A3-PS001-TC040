# Prompt-Injection Detector Threat Model

## In scope

The detector receives bounded prompt or message text. It checks direct
instruction overrides, role impersonation, secret/system-prompt extraction,
tool-abuse language, and selected Unicode/invisible-text obfuscation. The same
path analyzes webhook content in memory; message bodies are not persisted.

## Direct and indirect content

Direct prompts and untrusted text embedded in email/message content share the
same detector, but the detector cannot establish the trust boundary by itself.
Applications must keep trusted instructions separate from untrusted content,
validate tool arguments outside the model, and require human approval for
consequential actions. Sentivra performs no autonomous action.

## Limits

- The current implementation is a bounded heuristic layer, not a trained
  language model and not a safety guarantee.
- The deepset benchmark is small and its publisher split is retained; source
  and paraphrase leakage cannot be ruled out from the files alone.
- Multilingual, long-document, multimodal, indirect RAG, and novel paraphrase
  coverage are incomplete.
- Encoded payload detection is limited to the transformations implemented by
  the detector; successful decoding is evidence, not proof of intent.

The measured rules-vs-linear-baseline result is in
`research/evaluation/text/report.json`. No gated Prompt Guard weights are
downloaded or bundled.
