# Open Questions / Owner Decisions

These items are intentionally not guessed or silently worked around.

1. **Dataset access and licensing.** CICIDS2017, UNSW-NB15, Mendeley SQLi,
   and several Hugging Face/Kaggle sources have dataset-specific terms,
   registration, or account requirements. The audit branch will not accept
   licenses, use credentials, or bypass gated access on the owner's behalf.
   If a source is blocked, it will be recorded as unavailable and no metric
   will be fabricated.
2. **Target remote mismatch.** The first-action remote in this checkout is the
   fetch-only URL `https://github.com/Jaegar03/A3-PS001-TC040.git`; its push URL
   is disabled as required by the audit task. The owner must decide whether
   this local branch should eventually be reviewed against that repository or
   another checkout such as `Jaegar03/Sentivra`. No remote will be contacted
   by this branch.
3. **Network benchmark resource budget.** The host had about 2.3 GiB free RAM
   at environment capture. Full CICIDS2017/UNSW-NB15 processing may require a
   documented stratified/subsampled plan rather than loading all CSVs at once.
4. **Reference prompt models.** Meta Prompt Guard is gated. If owner access is
   not already available locally, use an openly licensed reference only after
   its card/license is verified, or record the reference comparison as
   unavailable.
