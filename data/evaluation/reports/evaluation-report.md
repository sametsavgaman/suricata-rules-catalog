# Evaluation Summary

**Status:** `COMPLETED`
**Provider:** `gemini`
**Model:** `gemini-flash-lite-latest`

## Parser

- Total rules: 52155
- Parsed successfully: 52155
- Failed parsing: 0
- Success rate: 100.00%

- Golden samples: 100
- Evaluated: 100
- Failed: 0

## Golden Provenance

- CLAUDE_INDEPENDENT_REVIEW: 100

## Accuracy

| Field | Exact | Normalized |
|---|---:|---:|
| detected_behavior | 0.0% | 0.0% |
| detected_entity | 31.0% | 33.0% |
| entity_type | 29.0% | 29.0% |
| category | 48.0% | 48.0% |
| subcategory | 4.0% | 4.0% |
| mitre_tactic | 58.0% | 58.0% |
| mitre_technique | 53.0% | 53.0% |
| mitre_technique_id | 54.0% | 54.0% |
| cyber_kill_chain_phase | 55.0% | 55.0% |

## Null Safety

| Field | Null preserved | NULL_HALLUCINATION_RATE | Unexpected null |
|---|---:|---:|---:|
| detected_behavior | 0.0% | 0.0% | 0.0% |
| detected_entity | 10.0% | 90.0% | 0.0% |
| entity_type | 10.0% | 90.0% | 0.0% |
| category | 0.0% | 0.0% | 0.0% |
| subcategory | 0.0% | 100.0% | 0.0% |
| mitre_tactic | 44.0% | 56.0% | 20.0% |
| mitre_technique | 44.0% | 56.0% | 20.0% |
| mitre_technique_id | 44.0% | 56.0% | 20.0% |
| cyber_kill_chain_phase | 19.6% | 80.4% | 0.0% |

## Confidence Calibration

| Bucket | Count | Actual field accuracy |
|---|---:|---:|
| 0.90-1.00 | 60 | 42.8% |
| 0.80-0.89 | 38 | 28.1% |
| 0.70-0.79 | 1 | 11.1% |
| 0.50-0.69 | 1 | 44.4% |

## Most Common Errors

| Error | Count |
|---|---:|
| OTHER | 100 |
| SUBCATEGORY_ERROR | 96 |
| NULL_HALLUCINATION | 83 |
| ENTITY_ERROR | 75 |
| CATEGORY_ERROR | 52 |
| MITRE_TECHNIQUE_ERROR | 47 |
| KILL_CHAIN_ERROR | 45 |
| MITRE_TACTIC_ERROR | 42 |
| UNEXPECTED_NULL | 10 |
| VALIDATION_FAILURE | 7 |

## Lowest Performing Categories

| Category | Count | Accuracy |
|---|---:|---:|
| Network Abuse | 25 | 0.0% |
| Credential Access | 1 | 0.0% |
| Malware | 11 | 9.1% |
| Other | 7 | 14.3% |
| Policy Violation | 6 | 33.3% |
| Remote Access | 7 | 57.1% |
| Exploitation | 8 | 75.0% |
| Reconnaissance | 7 | 85.7% |
| Command and Control | 10 | 100.0% |
| Web Attack | 9 | 100.0% |

## Token and Cost Analysis

- Total tokens: 13820
- Average tokens/rule: 138.2
- Cost status: `COST_NOT_CALCULATED`

## Sample Errors

### SID 2010935

- Message: ET SCAN Suspicious inbound to MSSQL port 1433
- Confidence: 0.80
- Error types: OTHER, NULL_HALLUCINATION, ENTITY_ERROR, SUBCATEGORY_ERROR

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
    "detected_entity": "MSSQL",
    "entity_type": "Product",
    "category": "Reconnaissance",
    "subcategory": "Port Scan",
    "mitre_tactic": "Discovery",
    "mitre_technique": "Network Service Scanning",
    "mitre_technique_id": "T1046",
    "cyber_kill_chain_phase": "Reconnaissance"
  }
}
```

### SID 2021837

- Message: ET MALWARE r0 CnC Architecture POST 4
- Confidence: 0.90
- Error types: OTHER, NULL_HALLUCINATION, ENTITY_ERROR, SUBCATEGORY_ERROR

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
    "detected_behavior": "Command and Control communication using HTTP POST requests",
    "detected_entity": "r0 bot",
    "entity_type": "Malware",
    "category": "Command and Control",
    "subcategory": "HTTP C2",
    "mitre_tactic": "Command and Control",
    "mitre_technique": "Web Protocols",
    "mitre_technique_id": "T1071.001",
    "cyber_kill_chain_phase": "Command and Control"
  }
}
```

### SID 2056356

- Message: ET EXPLOIT Zimbra postjournal RCE Attempt Inbound (CVE-2024-45519)
- Confidence: 1.00
- Error types: OTHER, NULL_HALLUCINATION, ENTITY_ERROR, SUBCATEGORY_ERROR

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
    "detected_behavior": "Remote Code Execution attempt against Zimbra postjournal via CVE-2024-45519",
    "detected_entity": "Zimbra postjournal",
    "entity_type": "Product",
    "category": "Exploitation",
    "subcategory": "Remote Code Execution",
    "mitre_tactic": "Initial Access",
    "mitre_technique": "Exploit Public-Facing Application",
    "mitre_technique_id": "T1190",
    "cyber_kill_chain_phase": "Exploitation"
  }
}
```

### SID 2059511

- Message: ET INFO Observed Smart Chain Domain in DNS Lookup (gnfd-testnet-sp1 .nodereal .io)
- Confidence: 0.80
- Error types: OTHER, NULL_HALLUCINATION, ENTITY_ERROR, CATEGORY_ERROR, SUBCATEGORY_ERROR, MITRE_TACTIC_ERROR, MITRE_TECHNIQUE_ERROR, KILL_CHAIN_ERROR

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
    "detected_behavior": "DNS query for Smart Chain Domain",
    "detected_entity": "gnfd-testnet-sp1.nodereal.io",
    "entity_type": "Other",
    "category": "Suspicious DNS",
    "subcategory": "DNS Lookup",
    "mitre_tactic": "Command and Control",
    "mitre_technique": "DNS",
    "mitre_technique_id": "T1071.004",
    "cyber_kill_chain_phase": "Command and Control"
  }
}
```

### SID 2045262

- Message: ET DYN_DNS DYNAMIC_DNS HTTP Request to a *.codingtheworld .com Domain
- Confidence: 0.80
- Error types: OTHER, NULL_HALLUCINATION, ENTITY_ERROR, SUBCATEGORY_ERROR, KILL_CHAIN_ERROR

```json
{
  "expected": {
    "detected_behavior": "DNS query to dynamic DNS domain",
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
    "detected_entity": "codingtheworld.com",
    "entity_type": "Other",
    "category": "Suspicious DNS",
    "subcategory": "Dynamic DNS",
    "mitre_tactic": null,
    "mitre_technique": null,
    "mitre_technique_id": null,
    "cyber_kill_chain_phase": "Command and Control"
  }
}
```

### SID 2019842

- Message: ET WEB_CLIENT Possible Internet Explorer VBscript CVE-2014-6332 multiple redim preserve
- Confidence: 0.95
- Error types: OTHER, NULL_HALLUCINATION, ENTITY_ERROR, CATEGORY_ERROR, SUBCATEGORY_ERROR, MITRE_TACTIC_ERROR, MITRE_TECHNIQUE_ERROR, KILL_CHAIN_ERROR

```json
{
  "expected": {
    "detected_behavior": "Suspicious network activity",
    "detected_entity": null,
    "entity_type": null,
    "category": "Network Abuse",
    "subcategory": "Suspicious HTTP Activity",
    "mitre_tactic": null,
    "mitre_technique": null,
    "mitre_technique_id": null,
    "cyber_kill_chain_phase": null
  },
  "actual": {
    "detected_behavior": "Exploitation of CVE-2014-6332 in Internet Explorer via VBScript ReDim Preserve",
    "detected_entity": "Internet Explorer",
    "entity_type": "Product",
    "category": "Web Attack",
    "subcategory": "Browser Exploit",
    "mitre_tactic": "Initial Access",
    "mitre_technique": "Drive-by Compromise",
    "mitre_technique_id": "T1189",
    "cyber_kill_chain_phase": "Exploitation"
  }
}
```

### SID 2046466

- Message: ET MOBILE_MALWARE Android Spy PREDATOR CnC Domain in DNS Lookup
- Confidence: 0.90
- Error types: OTHER, ENTITY_ERROR, SUBCATEGORY_ERROR, UNEXPECTED_NULL, MITRE_TACTIC_ERROR, MITRE_TECHNIQUE_ERROR

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
    "detected_behavior": "DNS lookup for Predator spyware command and control domain",
    "detected_entity": "PREDATOR",
    "entity_type": "Malware",
    "category": "Command and Control",
    "subcategory": "DNS",
    "mitre_tactic": null,
    "mitre_technique": null,
    "mitre_technique_id": null,
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
    "detected_behavior": "Observed AnyDesk domain connection attempt via TLS SNI",
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
- Confidence: 0.80
- Error types: OTHER, NULL_HALLUCINATION, ENTITY_ERROR, CATEGORY_ERROR, SUBCATEGORY_ERROR, UNEXPECTED_NULL, MITRE_TACTIC_ERROR, MITRE_TECHNIQUE_ERROR

```json
{
  "expected": {
    "detected_behavior": "Credential phishing attempt",
    "detected_entity": null,
    "entity_type": null,
    "category": "Network Abuse",
    "subcategory": "Phishing Infrastructure",
    "mitre_tactic": "Initial Access",
    "mitre_technique": "Spearphishing Attachment",
    "mitre_technique_id": "T1566.001",
    "cyber_kill_chain_phase": "Delivery"
  },
  "actual": {
    "detected_behavior": "Phishing domain access via TLS SNI",
    "detected_entity": "Microsoft Credential Phish V3 Domain",
    "entity_type": "Other",
    "category": "Web Attack",
    "subcategory": "Phishing",
    "mitre_tactic": null,
    "mitre_technique": null,
    "mitre_technique_id": null,
    "cyber_kill_chain_phase": "Delivery"
  }
}
```

### SID 2046259

- Message: ET RETIRED Kimsuky ReconShark Related APT Activity
- Confidence: 0.90
- Error types: OTHER, CATEGORY_ERROR, SUBCATEGORY_ERROR, NULL_HALLUCINATION, MITRE_TACTIC_ERROR, MITRE_TECHNIQUE_ERROR, KILL_CHAIN_ERROR

```json
{
  "expected": {
    "detected_behavior": "Suspicious network activity",
    "detected_entity": "ReconShark",
    "entity_type": "Malware",
    "category": "Network Abuse",
    "subcategory": "Suspicious HTTP Activity",
    "mitre_tactic": null,
    "mitre_technique": null,
    "mitre_technique_id": null,
    "cyber_kill_chain_phase": null
  },
  "actual": {
    "detected_behavior": "ReconShark APT activity communication over HTTP POST to /r.php",
    "detected_entity": "ReconShark",
    "entity_type": "Malware",
    "category": "Command and Control",
    "subcategory": "Web Communications",
    "mitre_tactic": "Command and Control",
    "mitre_technique": "Web Protocols",
    "mitre_technique_id": "T1071.001",
    "cyber_kill_chain_phase": "Command and Control"
  }
}
```
