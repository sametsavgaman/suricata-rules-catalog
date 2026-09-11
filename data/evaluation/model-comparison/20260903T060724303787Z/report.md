# Gemini / Qwen production pipeline comparison

Accuracy applies only to reviewed audited records. Fresh cohort has no ground truth. Smoke metrics are not representative. Similar-rule retrieval uses other reviewed benchmark examples (existing V2 policy); this is not a fully held-out benchmark. Model confidence is uncalibrated. Token counts use different tokenizers.

Rules: 250; sample SHA256: `c7fadde78e84014abc822675ed61e63b3d480374c342741c1be9a6f83fc377b3`

| Provider | Model | Succeeded | Failed | Mean seconds | Input tokens | Output tokens |
|---|---|---:|---:|---:|---:|---:|
| ollama | qwen3:8b | 250 | 0 | 6.54 | 256051 | 57675 |
| gemini | gemini-3.5-flash-lite | 250 | 0 | 2.45 | 265540 | 54727 |

## Audited metrics / fresh descriptive results

See report.json. No accuracy is calculated for fresh rules.

Cost: COST_NOT_CALCULATED. Local electricity and hardware costs have not been measured.
