# V1 Audited vs V2

| Metric | V1 Audited | V2 | Delta |
|---|---:|---:|---:|
| detected_entity | 38.1% | 89.7% | +51.5% |
| entity_type | 34.0% | 89.7% | +55.7% |
| category | 56.7% | 84.5% | +27.8% |
| subcategory | 5.2% | 74.2% | +69.1% |
| mitre_tactic | 63.9% | 78.4% | +14.4% |
| mitre_technique | 58.8% | 78.4% | +19.6% |
| mitre_technique_id | 59.8% | 78.4% | +18.6% |
| cyber_kill_chain_phase | 58.8% | 83.5% | +24.7% |
| behavior semantic normalized | 0.0% | 23.7% | +23.7% |
| entity null hallucination | 88.9% | 0.0% | -88.9% |

## Tool Usage

{
  "rates": {
    "entity_candidates": 1.0,
    "search_mitre": 1.0,
    "search_similar_rules": 0.8556701030927835,
    "lookup_cve": 0.14432989690721648
  },
  "average_tool_calls_per_rule": 3.0,
  "semantic_verifier_rate": 1.0,
  "average_llm_calls_per_rule": 1.0
}