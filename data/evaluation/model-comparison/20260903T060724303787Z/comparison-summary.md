# Gemini / Qwen3-8B comparison

Status: **COMPLETE** · successful pairs: 250/250

| Model | Succeeded | Failed | Average sec/rule | P50 | P95 | Input tokens | Output tokens |
|---|---:|---:|---:|---:|---:|---:|---:|
| gemini-3.5-flash-lite | 250 | 0 | 2.45 | 1.46 | 6.83 | 265540 | 54727 |
| qwen3:8b | 250 | 0 | 6.54 | 6.19 | 9.38 | 256051 | 57675 |

## Reviewed audited records only

| Field | Gemini exact accuracy | Qwen exact accuracy |
|---|---:|---:|
| detected_behavior | 8.2% (n=97) | 26.8% (n=97) |
| detected_entity | 95.9% (n=97) | 95.9% (n=97) |
| entity_type | 93.8% (n=97) | 93.8% (n=97) |
| category | 80.4% (n=97) | 78.4% (n=97) |
| subcategory | 64.9% (n=97) | 60.8% (n=97) |
| mitre_tactic | 64.9% (n=97) | 60.8% (n=97) |
| mitre_technique | 62.9% (n=97) | 58.8% (n=97) |
| mitre_technique_id | 67.0% (n=97) | 67.0% (n=97) |
| cyber_kill_chain_phase | 76.3% (n=97) | 73.2% (n=97) |
| Behavior normalized by existing heuristic | 20.6% | 36.1% |

Behavior exact match is text equality; normalized behavior uses the existing project heuristic, not an independent semantic judge.

## Fresh operational rules (no accuracy)

| Model | Total | Successful | Entity assigned | MITRE assigned |
|---|---:|---:|---:|---:|
| gemini | 153 | 153 | 33 | 32 |
| ollama | 153 | 153 | 33 | 31 |

## Inspect disagreements

| SID / REV | Cohort | Different fields |
|---|---|---|
| 2010494 / 5 | AUDITED_BENCHMARK | detected_behavior, category, subcategory, mitre_tactic, mitre_technique, mitre_technique_id, cyber_kill_chain_phase |
| 2043898 / 2 | FRESH_OPERATIONAL | detected_behavior, category, subcategory, mitre_tactic, mitre_technique, mitre_technique_id, cyber_kill_chain_phase |
| 2012255 / 5 | FRESH_OPERATIONAL | detected_behavior, category, subcategory, mitre_tactic, mitre_technique, cyber_kill_chain_phase |
| 2037615 / 2 | FRESH_OPERATIONAL | detected_behavior, category, subcategory, mitre_tactic, mitre_technique, cyber_kill_chain_phase |
| 2028372 / 2 | FRESH_OPERATIONAL | detected_behavior, category, subcategory, mitre_tactic, mitre_technique, mitre_technique_id |
| 2103271 / 5 | AUDITED_BENCHMARK | detected_behavior, category, subcategory, mitre_tactic, mitre_technique |
| 2103162 / 5 | AUDITED_BENCHMARK | detected_behavior, category, subcategory, mitre_tactic, mitre_technique |
| 2060849 / 2 | AUDITED_BENCHMARK | mitre_tactic, mitre_technique, mitre_technique_id, cyber_kill_chain_phase |
| 2012060 / 2 | FRESH_OPERATIONAL | detected_behavior, subcategory, mitre_tactic, mitre_technique, cyber_kill_chain_phase |
| 2031305 / 2 | FRESH_OPERATIONAL | detected_behavior, category, subcategory, mitre_tactic, mitre_technique |
| 2045262 / 3 | AUDITED_BENCHMARK | detected_behavior, category, subcategory, cyber_kill_chain_phase |
| 2048071 / 2 | AUDITED_BENCHMARK | detected_behavior, category, subcategory, cyber_kill_chain_phase |
| 2049581 / 1 | AUDITED_BENCHMARK | detected_behavior, category, subcategory, cyber_kill_chain_phase |
| 2068124 / 1 | AUDITED_BENCHMARK | category, subcategory, cyber_kill_chain_phase |
| 2011286 / 7 | AUDITED_BENCHMARK | detected_behavior, subcategory, mitre_tactic, mitre_technique |
| 2066004 / 1 | AUDITED_BENCHMARK | detected_behavior, mitre_tactic, mitre_technique, mitre_technique_id |
| 2066414 / 1 | AUDITED_BENCHMARK | detected_behavior, category, subcategory, cyber_kill_chain_phase |
| 2026337 / 4 | AUDITED_BENCHMARK | detected_behavior, mitre_tactic, mitre_technique, cyber_kill_chain_phase |
| 2066757 / 1 | AUDITED_BENCHMARK | detected_behavior, category, subcategory, cyber_kill_chain_phase |
| 2043750 / 3 | AUDITED_BENCHMARK | detected_behavior, category, subcategory, cyber_kill_chain_phase |

## Interpretation limits

- Accuracy applies only to the reviewed audited cohort; fresh agreement is not accuracy.
- Existing similar-rule retrieval can use other reviewed benchmark examples; not a fully held-out benchmark.
- Token counts use different tokenizers. Local hardware/electricity and API cost not calculated.
- Reported latency is end-to-end per-rule wall time, including provider retries and any cold loading.
- No fine-tuning was performed. Model confidence is uncalibrated.

Prompt/context mismatched pairs: 0

Cost: COST_NOT_CALCULATED.
