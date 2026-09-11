# Evaluation Summary

**Status:** `COMPLETED`
**Provider:** `gemini`
**Model:** `v2:gemini-flash-lite-latest`

- Golden samples: 97
- Evaluated: 97
- Failed: 0

## Golden Provenance

- CLAUDE_INDEPENDENT_REVIEW: 97

## Accuracy

| Field | Exact | Normalized |
|---|---:|---:|
| detected_behavior | 10.3% | 10.3% |
| detected_entity | 89.7% | 89.7% |
| entity_type | 89.7% | 89.7% |
| category | 84.5% | 84.5% |
| subcategory | 74.2% | 74.2% |
| mitre_tactic | 78.4% | 78.4% |
| mitre_technique | 78.4% | 78.4% |
| mitre_technique_id | 78.4% | 78.4% |
| cyber_kill_chain_phase | 83.5% | 83.5% |

## Null Safety

| Field | Null preserved | NULL_HALLUCINATION_RATE | Unexpected null |
|---|---:|---:|---:|
| detected_behavior | 0.0% | 0.0% | 0.0% |
| detected_entity | 100.0% | 0.0% | 29.4% |
| entity_type | 100.0% | 0.0% | 29.4% |
| category | 0.0% | 0.0% | 0.0% |
| subcategory | 60.0% | 40.0% | 2.2% |
| mitre_tactic | 100.0% | 0.0% | 44.7% |
| mitre_technique | 100.0% | 0.0% | 44.7% |
| mitre_technique_id | 100.0% | 0.0% | 44.7% |
| cyber_kill_chain_phase | 77.1% | 22.9% | 4.1% |

## Confidence Calibration

| Bucket | Count | Actual field accuracy |
|---|---:|---:|
| 0.90-1.00 | 44 | 77.3% |
| 0.80-0.89 | 51 | 71.5% |
| 0.70-0.79 | 1 | 77.8% |
| <0.50 | 1 | 66.7% |

## Most Common Errors

| Error | Count |
|---|---:|
| OTHER | 87 |
| UNEXPECTED_NULL | 32 |
| SUBCATEGORY_ERROR | 25 |
| MITRE_TACTIC_ERROR | 21 |
| MITRE_TECHNIQUE_ERROR | 21 |
| KILL_CHAIN_ERROR | 16 |
| CATEGORY_ERROR | 15 |
| NULL_HALLUCINATION | 13 |
| ENTITY_ERROR | 10 |
| VALIDATION_FAILURE | 6 |

## Lowest Performing Categories

| Category | Count | Accuracy |
|---|---:|---:|
| Discovery | 4 | 50.0% |
| Credential Access | 3 | 66.7% |
| Network Abuse | 19 | 68.4% |
| Suspicious DNS | 4 | 75.0% |
| Command and Control | 11 | 81.8% |
| Remote Access | 6 | 83.3% |
| Other | 7 | 85.7% |
| Web Attack | 13 | 92.3% |
| Malware | 11 | 100.0% |
| Exploitation | 7 | 100.0% |

## Token and Cost Analysis

- Total tokens: 1616
- Average tokens/rule: 16.7
- Cost status: `COST_NOT_CALCULATED`

## Sample Errors

### SID 2010935

- Message: ET SCAN Suspicious inbound to MSSQL port 1433
- Confidence: 0.80
- Error types: OTHER, UNEXPECTED_NULL, MITRE_TACTIC_ERROR, MITRE_TECHNIQUE_ERROR

```json
{
  "expected": {
    "detected_behavior": "Network service scanning",
    "detected_entity": null,
    "entity_type": null,
    "category": "Reconnaissance",
    "subcategory": "Service Scan",
    "mitre_tactic": "Discovery",
    "mitre_technique": "Network Service Scanning",
    "mitre_technique_id": "T1046",
    "cyber_kill_chain_phase": "Reconnaissance"
  },
  "actual": {
    "detected_behavior": "Suspicious inbound connection attempt to MSSQL port",
    "detected_entity": null,
    "entity_type": null,
    "category": "Reconnaissance",
    "subcategory": "Service Scan",
    "mitre_tactic": null,
    "mitre_technique": null,
    "mitre_technique_id": null,
    "cyber_kill_chain_phase": "Reconnaissance"
  }
}
```

### SID 2021837

- Message: ET MALWARE r0 CnC Architecture POST 4
- Confidence: 0.85
- Error types: OTHER, UNEXPECTED_NULL, MITRE_TACTIC_ERROR, MITRE_TECHNIQUE_ERROR

```json
{
  "expected": {
    "detected_behavior": "HTTP command-and-control communication",
    "detected_entity": null,
    "entity_type": null,
    "category": "Command and Control",
    "subcategory": "HTTP C2 Communication",
    "mitre_tactic": "Command and Control",
    "mitre_technique": "Web Protocols",
    "mitre_technique_id": "T1071.001",
    "cyber_kill_chain_phase": "Command and Control"
  },
  "actual": {
    "detected_behavior": "r0 bot command-and-control communication",
    "detected_entity": null,
    "entity_type": null,
    "category": "Command and Control",
    "subcategory": "HTTP C2 Communication",
    "mitre_tactic": null,
    "mitre_technique": null,
    "mitre_technique_id": null,
    "cyber_kill_chain_phase": "Command and Control"
  }
}
```

### SID 2056356

- Message: ET EXPLOIT Zimbra postjournal RCE Attempt Inbound (CVE-2024-45519)
- Confidence: 0.95
- Error types: OTHER

```json
{
  "expected": {
    "detected_behavior": "Exploit attempt against a network-accessible service",
    "detected_entity": null,
    "entity_type": null,
    "category": "Exploitation",
    "subcategory": "Exploit Attempt",
    "mitre_tactic": "Initial Access",
    "mitre_technique": "Exploit Public-Facing Application",
    "mitre_technique_id": "T1190",
    "cyber_kill_chain_phase": "Exploitation"
  },
  "actual": {
    "detected_behavior": "Remote Code Execution",
    "detected_entity": null,
    "entity_type": null,
    "category": "Exploitation",
    "subcategory": "Exploit Attempt",
    "mitre_tactic": "Initial Access",
    "mitre_technique": "Exploit Public-Facing Application",
    "mitre_technique_id": "T1190",
    "cyber_kill_chain_phase": "Exploitation"
  }
}
```

### SID 2059511

- Message: ET INFO Observed Smart Chain Domain in DNS Lookup (gnfd-testnet-sp1 .nodereal .io)
- Confidence: 0.90
- Error types: OTHER

```json
{
  "expected": {
    "detected_behavior": "Informational network activity",
    "detected_entity": null,
    "entity_type": null,
    "category": "Other",
    "subcategory": "Informational Activity",
    "mitre_tactic": null,
    "mitre_technique": null,
    "mitre_technique_id": null,
    "cyber_kill_chain_phase": null
  },
  "actual": {
    "detected_behavior": "Observed domain lookup for a Smart Chain service",
    "detected_entity": null,
    "entity_type": null,
    "category": "Other",
    "subcategory": "Informational Activity",
    "mitre_tactic": null,
    "mitre_technique": null,
    "mitre_technique_id": null,
    "cyber_kill_chain_phase": null
  }
}
```

### SID 2045262

- Message: ET DYN_DNS DYNAMIC_DNS HTTP Request to a *.codingtheworld .com Domain
- Confidence: 0.80
- Error types: CATEGORY_ERROR, SUBCATEGORY_ERROR

```json
{
  "expected": {
    "detected_behavior": "HTTP request to a dynamic DNS domain",
    "detected_entity": null,
    "entity_type": null,
    "category": "Suspicious DNS",
    "subcategory": "Unusual DNS Query",
    "mitre_tactic": null,
    "mitre_technique": null,
    "mitre_technique_id": null,
    "cyber_kill_chain_phase": null
  },
  "actual": {
    "detected_behavior": "HTTP request to a dynamic DNS domain",
    "detected_entity": null,
    "entity_type": null,
    "category": "Command and Control",
    "subcategory": "HTTP C2 Communication",
    "mitre_tactic": null,
    "mitre_technique": null,
    "mitre_technique_id": null,
    "cyber_kill_chain_phase": null
  }
}
```

### SID 2019842

- Message: ET WEB_CLIENT Possible Internet Explorer VBscript CVE-2014-6332 multiple redim preserve
- Confidence: 0.80
- Error types: OTHER, UNEXPECTED_NULL, ENTITY_ERROR, MITRE_TACTIC_ERROR, MITRE_TECHNIQUE_ERROR, VALIDATION_FAILURE

```json
{
  "expected": {
    "detected_behavior": "Internet Explorer VBScript CVE-2014-6332 exploit attempt",
    "detected_entity": "Internet Explorer",
    "entity_type": "Product",
    "category": "Web Attack",
    "subcategory": "Web Exploit Attempt",
    "mitre_tactic": "Initial Access",
    "mitre_technique": "Drive-by Compromise",
    "mitre_technique_id": "T1189",
    "cyber_kill_chain_phase": "Exploitation"
  },
  "actual": {
    "detected_behavior": "Possible Internet Explorer VBscript CVE-2014-6332 multiple redim preserve exploit attempt",
    "detected_entity": null,
    "entity_type": null,
    "category": "Web Attack",
    "subcategory": "Web Exploit Attempt",
    "mitre_tactic": null,
    "mitre_technique": null,
    "mitre_technique_id": null,
    "cyber_kill_chain_phase": "Exploitation"
  }
}
```

### SID 2046466

- Message: ET MOBILE_MALWARE Android Spy PREDATOR CnC Domain in DNS Lookup
- Confidence: 0.85
- Error types: OTHER

```json
{
  "expected": {
    "detected_behavior": "Predator command-and-control communication",
    "detected_entity": "Predator",
    "entity_type": "Malware",
    "category": "Command and Control",
    "subcategory": "DNS C2 Communication",
    "mitre_tactic": "Command and Control",
    "mitre_technique": "DNS",
    "mitre_technique_id": "T1071.004",
    "cyber_kill_chain_phase": "Command and Control"
  },
  "actual": {
    "detected_behavior": "Android Spy PREDATOR CnC Domain in DNS Lookup",
    "detected_entity": "Predator",
    "entity_type": "Malware",
    "category": "Command and Control",
    "subcategory": "DNS C2 Communication",
    "mitre_tactic": "Command and Control",
    "mitre_technique": "DNS",
    "mitre_technique_id": "T1071.004",
    "cyber_kill_chain_phase": "Command and Control"
  }
}
```

### SID 2060513

- Message: ET REMOTE_ACCESS Observed Anydesk Domain (boot .net .anydesk .com) in TLS SNI
- Confidence: 1.00
- Error types: OTHER, SUBCATEGORY_ERROR

```json
{
  "expected": {
    "detected_behavior": "AnyDesk remote access software communication",
    "detected_entity": "AnyDesk",
    "entity_type": "Remote Access Tool",
    "category": "Remote Access",
    "subcategory": "Remote Administration Tool",
    "mitre_tactic": "Command and Control",
    "mitre_technique": "Remote Access Software",
    "mitre_technique_id": "T1219",
    "cyber_kill_chain_phase": "Command and Control"
  },
  "actual": {
    "detected_behavior": "Observed AnyDesk domain connection in TLS SNI",
    "detected_entity": "AnyDesk",
    "entity_type": "Remote Access Tool",
    "category": "Remote Access",
    "subcategory": "Remote Access Software",
    "mitre_tactic": "Command and Control",
    "mitre_technique": "Remote Access Software",
    "mitre_technique_id": "T1219",
    "cyber_kill_chain_phase": "Command and Control"
  }
}
```

### SID 2048071

- Message: ET RETIRED [TW] Observed Microsoft Credential Phish V3 Domain (bc1qc230lt32ey73qlaj9rkujm0ujtv090 .com in TLS SNI)
- Confidence: 0.85
- Error types: OTHER

```json
{
  "expected": {
    "detected_behavior": "TLS SNI observation of credential-phishing infrastructure",
    "detected_entity": null,
    "entity_type": null,
    "category": "Network Abuse",
    "subcategory": "Phishing Infrastructure",
    "mitre_tactic": null,
    "mitre_technique": null,
    "mitre_technique_id": null,
    "cyber_kill_chain_phase": "Delivery"
  },
  "actual": {
    "detected_behavior": "Phishing domain observed in TLS SNI",
    "detected_entity": null,
    "entity_type": null,
    "category": "Network Abuse",
    "subcategory": "Phishing Infrastructure",
    "mitre_tactic": null,
    "mitre_technique": null,
    "mitre_technique_id": null,
    "cyber_kill_chain_phase": "Delivery"
  }
}
```

### SID 2046259

- Message: ET RETIRED Kimsuky ReconShark Related APT Activity
- Confidence: 0.85
- Error types: OTHER, CATEGORY_ERROR, SUBCATEGORY_ERROR, UNEXPECTED_NULL, MITRE_TACTIC_ERROR, MITRE_TECHNIQUE_ERROR, KILL_CHAIN_ERROR

```json
{
  "expected": {
    "detected_behavior": "ReconShark HTTP command-and-control communication",
    "detected_entity": "ReconShark",
    "entity_type": "Malware",
    "category": "Command and Control",
    "subcategory": "HTTP C2 Communication",
    "mitre_tactic": "Command and Control",
    "mitre_technique": "Web Protocols",
    "mitre_technique_id": "T1071.001",
    "cyber_kill_chain_phase": "Command and Control"
  },
  "actual": {
    "detected_behavior": "ReconShark related APT activity",
    "detected_entity": "ReconShark",
    "entity_type": "Malware",
    "category": "Malware",
    "subcategory": "Malware Network Activity",
    "mitre_tactic": null,
    "mitre_technique": null,
    "mitre_technique_id": null,
    "cyber_kill_chain_phase": "Installation"
  }
}
```
