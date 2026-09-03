# Qwen V2.2 Hardening Plan

- Existing path: `ClassificationService` parses and enriches a rule, dispatches to the selected provider, then applies the shared V2 finalizer and validator.
- Gemini isolation: Gemini keeps its existing `SYSTEM_PROMPT`, context payload, provider settings, normalization, cache semantics, and `v2.1` records.
- Qwen input: `qwen_semantic_input_v2` adds a compact observation/protocol contract, evidence, entity candidates, controlled taxonomy and MITRE candidate allowlists, CVEs, and audited similar rules.
- Qwen prompt: evidence-first, structured-only, no hidden reasoning; explicit protocol, DNS lookup versus DNS C2, IOC association, uncertainty, and abstention constraints.
- Output normalization: Qwen proposals are canonicalized before the existing finalizer; category/subcategory and protocol contradictions are rejected, and MITRE fields are resolved atomically from the local repository.
- MITRE: Qwen selects an allowlisted technique ID or null. Technique name and tactic come from the local repository. ID-less or inconsistent tuples become all-null.
- Entity/IOC: the existing strong-evidence gate remains in force; association is not treated as a direct fingerprint.
- Kill Chain: no forced assignment; unsupported phases remain null.
- Version/cache: `qwen-v2.2` is a separate classifier version, so Qwen V2.1 and Gemini cache/results remain immutable.
- Regression: run the frozen operational-250 and reviewed-50 SID/REV cohort, compare Qwen V2.1 versus V2.2, and verify Gemini semantic fingerprints remain identical.
