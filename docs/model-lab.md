# Model Lab

Open `/models` after starting the frontend. The page exposes allowlisted runtime settings, provider connectivity tests, and a side-by-side Gemini/Ollama comparison for one SID/REV.

Runtime precedence is: UI setting, then environment variable, then application default. Non-secret settings are stored in `application_settings`; the Gemini key is stored only in the ignored local `.runtime-secrets.json` file and is never returned by the API or written to logs. This local-development store should be replaced by an OS/secret manager before production deployment.

The comparison endpoint is `POST /api/model-lab/compare`. It reuses the existing classification service and creates separate provider/model/version records; it never overwrites historical results. Comparison preferences are stored separately in `comparison_reviews` and do not change manual review or golden labels.

Ollama health and model availability are checked through the backend (`/api/tags` and the provider test). No arbitrary shell execution is exposed; start Ollama from a terminal with `ollama serve` and install models with `ollama pull qwen3:8b`.
