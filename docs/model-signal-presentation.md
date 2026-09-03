# Model self-assessment and decision checks

The providers generate `ClassificationOutput.confidence` in the structured response. The schema limits it to 0–1; it does not calculate empirical correctness. The V2 finalizer copies the score to `model_confidence`. Evidence gates can modify the final fields without recalculating that score.

The catalog and comparison UI therefore present recorded validator results, the separate semantic check, human review state, and canonical field decisions. Field completion is descriptive, not a quality score. Abstention does not lower an invented reliability score or create a manual review requirement.

The raw model value remains under **Technical details · model self-assessment**, without percentage formatting, progress bars or LOW/MEDIUM/HIGH bands. Failed classifications display **Unavailable**, not a fabricated zero-confidence decision. Missing historical field decisions remain **Unavailable**; the frontend never infers abstention from null values.

MITRE retrieval relevance and the existing MITRE evidence indicator stay in the provenance panel. The latter is derived from source/final mapping presence and equality; it is not an overall evidence-quality assessment. Validator PASS does not prove classification correctness. Gemini and Qwen self-assessment values are not a calibrated common comparison scale.

No prompts, classifier thresholds, model outputs, database records or benchmark labels were changed. Existing API fields and historical scores remain available for compatibility. A calibrated correctness estimate would require independent held-out reviewed data and validation specific to the provider/model/version; the current UI makes no such estimate.
