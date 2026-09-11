# Model Lab

Open `/models` after starting the frontend. The page exposes allowlisted runtime settings, provider connectivity tests, helper-provider selection, and side-by-side comparisons against the local Qwen reference for one SID/REV.

Runtime precedence is: UI setting, then environment variable, then application default. Non-secret settings are stored in `application_settings`; Gemini, Claude, and OpenAI keys are stored only in the ignored local `.runtime-secrets.json` file and are never returned by the API or written to logs. This local-development store should be replaced by an OS/secret manager before production deployment.

The helper provider is independent of the bulk/default classifier. Catalog question planning, UI translation, and user-forced MITRE mapping use the selected configured cloud provider; the normal Qwen classification pipeline is not changed. A forced MITRE mapping is stored separately, clearly warned as best-effort, and its technique ID is checked against the local ATT&CK repository before it is saved.

The comparison endpoint is `POST /api/model-lab/compare`. It reuses the existing classification service and creates separate provider/model/version records; it never overwrites historical results. Comparison preferences are stored separately in `comparison_reviews` and do not change manual review or golden labels.

Ollama health and model availability are checked through the backend (`/api/tags` and the provider test). No arbitrary shell execution is exposed; start Ollama from a terminal with `ollama serve` and install models with `ollama pull qwen3:8b`.
