# Operational 250 Test

## Run Configuration

- Provider: `gemini`
- Model: `gemini-flash-lite-latest`
- Classifier version: `v2.1`
- Seed: `42`
- Total: 250
- Duration: 485.1s

## Cohorts

- Audited benchmark: 97
- Fresh operational: 153

## Audited Benchmark Accuracy

Evaluated: **97**.

```json
{
  "detected_behavior": {
    "count": 97,
    "exact_accuracy": 0.10309278350515463,
    "normalized_accuracy": 0.10309278350515463
  },
  "detected_entity": {
    "count": 97,
    "exact_accuracy": 0.8969072164948454,
    "normalized_accuracy": 0.8969072164948454
  },
  "entity_type": {
    "count": 97,
    "exact_accuracy": 0.8969072164948454,
    "normalized_accuracy": 0.8969072164948454
  },
  "category": {
    "count": 97,
    "exact_accuracy": 0.845360824742268,
    "normalized_accuracy": 0.845360824742268
  },
  "subcategory": {
    "count": 97,
    "exact_accuracy": 0.7422680412371134,
    "normalized_accuracy": 0.7422680412371134
  },
  "mitre_tactic": {
    "count": 97,
    "exact_accuracy": 0.7835051546391752,
    "normalized_accuracy": 0.7835051546391752
  },
  "mitre_technique": {
    "count": 97,
    "exact_accuracy": 0.7835051546391752,
    "normalized_accuracy": 0.7835051546391752
  },
  "mitre_technique_id": {
    "count": 97,
    "exact_accuracy": 0.7835051546391752,
    "normalized_accuracy": 0.7835051546391752
  },
  "cyber_kill_chain_phase": {
    "count": 97,
    "exact_accuracy": 0.8350515463917526,
    "normalized_accuracy": 0.8350515463917526
  }
}
```

## Fresh Operational Summary

- Succeeded: 153
- Failed: 0
- Entity assigned: 12
- MITRE assigned: 10
- Kill Chain assigned: 76
- Average confidence: 0.705

## Category Distribution

```json
{
  "Exploitation": 19,
  "Policy Violation": 13,
  "Command and Control": 13,
  "Network Abuse": 15,
  "Malware": 21,
  "Credential Access": 5,
  "Suspicious DNS": 6,
  "Denial of Service": 7,
  "<null>": 23,
  "Other": 11,
  "Remote Access": 3,
  "Discovery": 2,
  "Reconnaissance": 6,
  "Web Attack": 6,
  "Defense Evasion": 2,
  "Impact": 1
}
```

## Confidence Distribution

```json
{
  "<0.50": 121,
  "0.90-1.00": 35,
  "0.80-0.89": 89,
  "0.70-0.79": 4,
  "0.50-0.69": 1
}
```

## Tool / Token Usage

```json
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
```

## Important Notice

> The 153 fresh operational rules do not have independently verified ground-truth labels. Their correctness must be assessed through manual inspection. Accuracy metrics apply only to the 97 audited benchmark records.
