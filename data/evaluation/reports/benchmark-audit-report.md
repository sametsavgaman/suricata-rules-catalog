# Benchmark Audit Summary

- Total: 100
- EXPECTED_CORRECT: 51
- ACTUAL_CORRECT: 10
- BOTH_ACCEPTABLE: 31
- BOTH_INCORRECT: 5
- AMBIGUOUS: 3

## Field Corrections

- detected_behavior: 15
- detected_entity: 4
- entity_type: 4
- category: 9
- subcategory: 9
- mitre_tactic: 7
- mitre_technique: 7
- mitre_technique_id: 7
- cyber_kill_chain_phase: 10

## Benchmark Problems Found

- Behavior exact matching penalizes semantically equivalent wording.
- Subcategory is not consistently controlled between benchmark and classifier.
- Domain strings are frequently promoted to entities.
- DNS/TLS observation is sometimes over-mapped to C2 MITRE techniques.
- Several phishing signatures were incorrectly mapped to Spearphishing Attachment.

## Evaluation Metric Problems

Behavior exact-match is lexical, not semantic. Subcategory accuracy is dominated by vocabulary mismatch.

- Expected unique subcategories: 25
- Actual unique subcategories: 62
- Most common mismatches:
  - Phishing Infrastructure ↔ Phishing: 8
  - Unusual DNS Query ↔ Dynamic DNS: 4
  - Malware Network Activity ↔ Exploit Kit: 4
  - Exploit Attempt ↔ Remote Code Execution: 3
  - DNS C2 Communication ↔ DNS: 3
  - Remote Administration Tool ↔ Remote Access Software: 3
  - None ↔ Network Service Discovery: 3
  - Web Scan ↔ Scanning: 3
  - Prohibited Application or Protocol ↔ Proxy: 2
  - Service Scan ↔ Brute Force: 2

## Most Important Corrections

### SID 2045262

- MSG: ET DYN_DNS DYNAMIC_DNS HTTP Request to a *.codingtheworld .com Domain
- RAW evidence: `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET DYN_DNS DYNAMIC_DNS HTTP Request to a *.codingtheworld .com Domain"; flow:established,to_server; http.host; content:".codingtheworld.com"; endswith; reference:url,freedns.afraid.org/domain/registry/page-10.html; classtype:bad-unknown; sid:2045262; rev:3; metadata:attack_target Client_and_Server, created_at 2023_05_01, deployment Perimeter, former_category INFO, performance_impact Low, confidence High, signature_severity Informational, update`
- Decision: BOTH_INCORRECT
- Reason: Raw protocol/content/metadata supports the audited values; the model output was used only as a comparison candidate.

Original Claude expected:
```json
{
  "detected_behavior": "DNS query to dynamic DNS domain",
  "detected_entity": null,
  "entity_type": null,
  "category": "Suspicious DNS",
  "subcategory": "Unusual DNS Query",
  "mitre_tactic": null,
  "mitre_technique": null,
  "mitre_technique_id": null,
  "cyber_kill_chain_phase": null
}
```
Gemini actual:
```json
{
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
```
Final audited expected:
```json
{
  "detected_behavior": "HTTP request to a dynamic DNS domain",
  "detected_entity": null,
  "entity_type": null,
  "category": "Suspicious DNS",
  "subcategory": "Unusual DNS Query",
  "mitre_tactic": null,
  "mitre_technique": null,
  "mitre_technique_id": null,
  "cyber_kill_chain_phase": null
}
```

### SID 2019842

- MSG: ET WEB_CLIENT Possible Internet Explorer VBscript CVE-2014-6332 multiple redim preserve
- RAW evidence: `alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_CLIENT Possible Internet Explorer VBscript CVE-2014-6332 multiple redim preserve"; flow:established,to_client; http.content_type; content:!"text/xml"; content:!"application/xml"; file.data; content:"preserve"; nocase; content:"redim|20|"; nocase; fast_pattern; pcre:"/^\s*?Preserve\s*?(?P<var1>[a-z]\w{0,254}+)\s*?\x28\s*?[^\x29]+?\x29.*?redim\s*?Preserve\s*?(?P=var1)/Rsi"; reference:cve,2014-6332; classtype:attempted-user; sid:2019842; re`
- Decision: ACTUAL_CORRECT
- Reason: Raw protocol/content/metadata supports the audited values; the model output was used only as a comparison candidate.

Original Claude expected:
```json
{
  "detected_behavior": "Suspicious network activity",
  "detected_entity": null,
  "entity_type": null,
  "category": "Network Abuse",
  "subcategory": "Suspicious HTTP Activity",
  "mitre_tactic": null,
  "mitre_technique": null,
  "mitre_technique_id": null,
  "cyber_kill_chain_phase": null
}
```
Gemini actual:
```json
{
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
```
Final audited expected:
```json
{
  "detected_behavior": "Internet Explorer VBScript CVE-2014-6332 exploit attempt",
  "detected_entity": "Internet Explorer",
  "entity_type": "Product",
  "category": "Web Attack",
  "subcategory": "Web Exploit Attempt",
  "mitre_tactic": "Initial Access",
  "mitre_technique": "Drive-by Compromise",
  "mitre_technique_id": "T1189",
  "cyber_kill_chain_phase": "Exploitation"
}
```

### SID 2048071

- MSG: ET RETIRED [TW] Observed Microsoft Credential Phish V3 Domain (bc1qc230lt32ey73qlaj9rkujm0ujtv090 .com in TLS SNI)
- RAW evidence: `alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"ET RETIRED [TW] Observed Microsoft Credential Phish V3 Domain (bc1qc230lt32ey73qlaj9rkujm0ujtv090 .com in TLS SNI)"; flow:established,to_server; tls.sni; dotprefix; content:".bc1qc230lt32ey73qlaj9rkujm0ujtv090.com"; endswith; fast_pattern; classtype:trojan-activity; sid:2048071; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, created_at 2023_09_13, deployment Perimeter, former_category PH`
- Decision: BOTH_INCORRECT
- Reason: Raw protocol/content/metadata supports the audited values; the model output was used only as a comparison candidate.

Original Claude expected:
```json
{
  "detected_behavior": "Credential phishing attempt",
  "detected_entity": null,
  "entity_type": null,
  "category": "Network Abuse",
  "subcategory": "Phishing Infrastructure",
  "mitre_tactic": "Initial Access",
  "mitre_technique": "Spearphishing Attachment",
  "mitre_technique_id": "T1566.001",
  "cyber_kill_chain_phase": "Delivery"
}
```
Gemini actual:
```json
{
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
```
Final audited expected:
```json
{
  "detected_behavior": "TLS SNI observation of credential-phishing infrastructure",
  "detected_entity": null,
  "entity_type": null,
  "category": "Network Abuse",
  "subcategory": "Phishing Infrastructure",
  "mitre_tactic": null,
  "mitre_technique": null,
  "mitre_technique_id": null,
  "cyber_kill_chain_phase": "Delivery"
}
```

### SID 2046259

- MSG: ET RETIRED Kimsuky ReconShark Related APT Activity
- RAW evidence: `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET RETIRED Kimsuky ReconShark Related APT Activity"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/r.php"; fast_pattern; endswith; http.host; content:!".foxitservice.com"; http.header_names; to_lowercase; content:!"|0d 0a|referer|0d 0a|"; content:"|0d 0a|content-type|0d 0a|"; reference:url,www.sentinelone.com/labs/kimsuky-evolves-reconnaissance-capabilities-in-new-global-campaign/; classtype:trojan-activity; sid:2`
- Decision: ACTUAL_CORRECT
- Reason: Raw protocol/content/metadata supports the audited values; the model output was used only as a comparison candidate.

Original Claude expected:
```json
{
  "detected_behavior": "Suspicious network activity",
  "detected_entity": "ReconShark",
  "entity_type": "Malware",
  "category": "Network Abuse",
  "subcategory": "Suspicious HTTP Activity",
  "mitre_tactic": null,
  "mitre_technique": null,
  "mitre_technique_id": null,
  "cyber_kill_chain_phase": null
}
```
Gemini actual:
```json
{
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
```
Final audited expected:
```json
{
  "detected_behavior": "ReconShark HTTP command-and-control communication",
  "detected_entity": "ReconShark",
  "entity_type": "Malware",
  "category": "Command and Control",
  "subcategory": "HTTP C2 Communication",
  "mitre_tactic": "Command and Control",
  "mitre_technique": "Web Protocols",
  "mitre_technique_id": "T1071.001",
  "cyber_kill_chain_phase": "Command and Control"
}
```

### SID 2002383

- MSG: ET SCAN Potential FTP Brute-Force attempt response
- RAW evidence: `alert tcp $HOME_NET 21 -> $EXTERNAL_NET any (msg:"ET SCAN Potential FTP Brute-Force attempt response"; flow:established,to_client; dsize:<100; content:"530 "; depth:4; pcre:"/530\s+(Login|User|Failed|Not)/smi"; threshold: type threshold, track by_dst, count 5, seconds 300; classtype:unsuccessful-user; sid:2002383; rev:13; metadata:created_at 2010_07_30, confidence Medium, signature_severity Informational, updated_at 2024_03_06;)`
- Decision: ACTUAL_CORRECT
- Reason: Raw protocol/content/metadata supports the audited values; the model output was used only as a comparison candidate.

Original Claude expected:
```json
{
  "detected_behavior": "Brute-force login attempt detection",
  "detected_entity": null,
  "entity_type": null,
  "category": "Reconnaissance",
  "subcategory": "Service Scan",
  "mitre_tactic": "Discovery",
  "mitre_technique": "Network Service Scanning",
  "mitre_technique_id": "T1046",
  "cyber_kill_chain_phase": "Reconnaissance"
}
```
Gemini actual:
```json
{
  "detected_behavior": "Potential FTP brute-force attempt response indicating login or authentication failure",
  "detected_entity": "FTP",
  "entity_type": "Protocol",
  "category": "Credential Access",
  "subcategory": "Brute Force",
  "mitre_tactic": null,
  "mitre_technique": null,
  "mitre_technique_id": null,
  "cyber_kill_chain_phase": "Reconnaissance"
}
```
Final audited expected:
```json
{
  "detected_behavior": "Possible FTP brute-force activity",
  "detected_entity": null,
  "entity_type": null,
  "category": "Credential Access",
  "subcategory": "Credential Activity",
  "mitre_tactic": null,
  "mitre_technique": null,
  "mitre_technique_id": null,
  "cyber_kill_chain_phase": null
}
```

### SID 2049581

- MSG: ET PHISHING TA444 Domain in TLS SNI (meeting-online .site)
- RAW evidence: `alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"ET PHISHING TA444 Domain in TLS SNI (meeting-online .site)"; flow:established,to_server; tls.sni; dotprefix; content:".meeting-online.site"; endswith; fast_pattern; reference:url,twitter.com/SlowMist_Team/status/1732311816557269067; classtype:social-engineering; sid:2049581; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, created_at 2023_12_06, deployment Perimeter, performance_impact Low`
- Decision: BOTH_INCORRECT
- Reason: Raw protocol/content/metadata supports the audited values; the model output was used only as a comparison candidate.

Original Claude expected:
```json
{
  "detected_behavior": "Credential phishing attempt",
  "detected_entity": null,
  "entity_type": null,
  "category": "Network Abuse",
  "subcategory": "Phishing Infrastructure",
  "mitre_tactic": "Initial Access",
  "mitre_technique": "Spearphishing Attachment",
  "mitre_technique_id": "T1566.001",
  "cyber_kill_chain_phase": "Delivery"
}
```
Gemini actual:
```json
{
  "detected_behavior": "Phishing domain access via TLS SNI",
  "detected_entity": "meeting-online.site",
  "entity_type": "Other",
  "category": "Suspicious DNS",
  "subcategory": "Phishing",
  "mitre_tactic": "Command and Control",
  "mitre_technique": "Web Protocols",
  "mitre_technique_id": "T1071.001",
  "cyber_kill_chain_phase": "Command and Control"
}
```
Final audited expected:
```json
{
  "detected_behavior": "TLS SNI observation of phishing infrastructure",
  "detected_entity": null,
  "entity_type": null,
  "category": "Network Abuse",
  "subcategory": "Phishing Infrastructure",
  "mitre_tactic": null,
  "mitre_technique": null,
  "mitre_technique_id": null,
  "cyber_kill_chain_phase": "Delivery"
}
```

### SID 2103271

- MSG: GPL NETBIOS SMB-DS IrotIsRunning unicode little endian andx attempt
- RAW evidence: `alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS IrotIsRunning unicode little endian andx attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.irot; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4`
- Decision: ACTUAL_CORRECT
- Reason: Raw protocol/content/metadata supports the audited values; the model output was used only as a comparison candidate.

Original Claude expected:
```json
{
  "detected_behavior": "Suspicious network activity",
  "detected_entity": null,
  "entity_type": null,
  "category": "Network Abuse",
  "subcategory": "Suspicious TCP Activity",
  "mitre_tactic": null,
  "mitre_technique": null,
  "mitre_technique_id": null,
  "cyber_kill_chain_phase": null
}
```
Gemini actual:
```json
{
  "detected_behavior": "SMB-DS IrotIsRunning unicode little endian andx attempt",
  "detected_entity": "SMB",
  "entity_type": "Protocol",
  "category": "Exploitation",
  "subcategory": "SMB Exploitation",
  "mitre_tactic": "Initial Access",
  "mitre_technique": "Exploit Public-Facing Application",
  "mitre_technique_id": "T1190",
  "cyber_kill_chain_phase": "Exploitation"
}
```
Final audited expected:
```json
{
  "detected_behavior": "SMB IrotIsRunning request attempt",
  "detected_entity": null,
  "entity_type": null,
  "category": "Network Abuse",
  "subcategory": "Suspicious TCP Activity",
  "mitre_tactic": null,
  "mitre_technique": null,
  "mitre_technique_id": null,
  "cyber_kill_chain_phase": null
}
```

### SID 2000564

- MSG: ET EXPLOIT Pwdump3e pwservice.exe Access port 445
- RAW evidence: `alert tcp any any -> $HOME_NET 445 (msg:"ET EXPLOIT Pwdump3e pwservice.exe Access port 445"; flow:established,to_server; content:"p|00|w|00|s|00|e|00|r|00|v|00|i|00|c|00|e|00|.|00|e|00|x|00|e"; classtype:misc-attack; sid:2000564; rev:10; metadata:created_at 2010_07_30, signature_severity Major, tag Description_Generated_By_Proofpoint_Nexus, updated_at 2024_03_07;)`
- Decision: ACTUAL_CORRECT
- Reason: Raw protocol/content/metadata supports the audited values; the model output was used only as a comparison candidate.

Original Claude expected:
```json
{
  "detected_behavior": "Exploit attempt against a network-accessible service",
  "detected_entity": null,
  "entity_type": null,
  "category": "Exploitation",
  "subcategory": "Exploit Attempt",
  "mitre_tactic": "Initial Access",
  "mitre_technique": "Exploit Public-Facing Application",
  "mitre_technique_id": "T1190",
  "cyber_kill_chain_phase": "Exploitation"
}
```
Gemini actual:
```json
{
  "detected_behavior": "Credential dumping utility execution and service access over port 445",
  "detected_entity": "Pwdump3e",
  "entity_type": "Attack Tool",
  "category": "Credential Access",
  "subcategory": "OS Credential Dumping",
  "mitre_tactic": "Credential Access",
  "mitre_technique": "OS Credential Dumping",
  "mitre_technique_id": "T1003",
  "cyber_kill_chain_phase": "Actions on Objectives"
}
```
Final audited expected:
```json
{
  "detected_behavior": "Pwdump3e credential-dumping activity over SMB",
  "detected_entity": "Pwdump3e",
  "entity_type": "Attack Tool",
  "category": "Credential Access",
  "subcategory": "Credential Dumping",
  "mitre_tactic": "Credential Access",
  "mitre_technique": "OS Credential Dumping",
  "mitre_technique_id": "T1003",
  "cyber_kill_chain_phase": null
}
```

### SID 2011286

- MSG: ET WEB_SERVER Bot Search RFI Scan (Casper-Like MaMa Cyber/ebes)
- RAW evidence: `alert http1 $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Bot Search RFI Scan (Casper-Like MaMa Cyber/ebes)"; flow:established,to_server; http.header; content:"|0d 0a|User-Agent|3a 20|MaMa|20|"; nocase; reference:url,eromang.zataz.com/2010/07/13/byroenet-casper-bot-search-e107-rce-scanner/; classtype:web-application-attack; sid:2011286; rev:7; metadata:created_at 2010_07_30, signature_severity Unknown, updated_at 2024_05_06;)`
- Decision: ACTUAL_CORRECT
- Reason: Raw protocol/content/metadata supports the audited values; the model output was used only as a comparison candidate.

Original Claude expected:
```json
{
  "detected_behavior": "Remote file inclusion scan",
  "detected_entity": null,
  "entity_type": null,
  "category": "Network Abuse",
  "subcategory": "Suspicious HTTP1 Activity",
  "mitre_tactic": null,
  "mitre_technique": null,
  "mitre_technique_id": null,
  "cyber_kill_chain_phase": null
}
```
Gemini actual:
```json
{
  "detected_behavior": "Bot Search RFI Scan",
  "detected_entity": "MaMa Cyber",
  "entity_type": "Attack Tool",
  "category": "Web Attack",
  "subcategory": "Remote File Inclusion",
  "mitre_tactic": "Initial Access",
  "mitre_technique": "Exploit Public-Facing Application",
  "mitre_technique_id": "T1190",
  "cyber_kill_chain_phase": "Exploitation"
}
```
Final audited expected:
```json
{
  "detected_behavior": "Remote file inclusion scan against a web server",
  "detected_entity": null,
  "entity_type": null,
  "category": "Web Attack",
  "subcategory": "Web Scan",
  "mitre_tactic": null,
  "mitre_technique": null,
  "mitre_technique_id": null,
  "cyber_kill_chain_phase": "Reconnaissance"
}
```

### SID 2010494

- MSG: ET SCAN Multiple MySQL Login Failures Possible Brute Force Attempt
- RAW evidence: `alert tcp $HOME_NET 3306 -> $EXTERNAL_NET any (msg:"ET SCAN Multiple MySQL Login Failures Possible Brute Force Attempt"; flow:established,to_client; dsize:<251; byte_test:1,<,0xfb,0,little; content:"|ff 15 04 23 32 38 30 30 30|"; offset:4; threshold: type threshold, track by_src, count 5, seconds 120; classtype:attempted-recon; sid:2010494; rev:5; metadata:created_at 2010_07_30, confidence Medium, signature_severity Informational, updated_at 2024_03_06;)`
- Decision: BOTH_INCORRECT
- Reason: Raw protocol/content/metadata supports the audited values; the model output was used only as a comparison candidate.

Original Claude expected:
```json
{
  "detected_behavior": "Brute-force login attempt detection",
  "detected_entity": null,
  "entity_type": null,
  "category": "Reconnaissance",
  "subcategory": "Service Scan",
  "mitre_tactic": "Discovery",
  "mitre_technique": "Network Service Scanning",
  "mitre_technique_id": "T1046",
  "cyber_kill_chain_phase": "Reconnaissance"
}
```
Gemini actual:
```json
{
  "detected_behavior": "Multiple MySQL Login Failures Brute Force Attempt",
  "detected_entity": "MySQL",
  "entity_type": "Product",
  "category": "Reconnaissance",
  "subcategory": "Brute Force",
  "mitre_tactic": null,
  "mitre_technique": null,
  "mitre_technique_id": null,
  "cyber_kill_chain_phase": "Reconnaissance"
}
```
Final audited expected:
```json
{
  "detected_behavior": "Possible MySQL brute-force login activity",
  "detected_entity": null,
  "entity_type": null,
  "category": "Credential Access",
  "subcategory": "Credential Activity",
  "mitre_tactic": null,
  "mitre_technique": null,
  "mitre_technique_id": null,
  "cyber_kill_chain_phase": null
}
```

### SID 2103162

- MSG: GPL NETBIOS SMB msqueue unicode bind attempt
- RAW evidence: `alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB msqueue unicode bind attempt"; flow:established,to_server; flowbits:set,smb.tree.bind.msqueue; flowbits:noalert; content:"|00|"; depth:1; content:"|FF|SMB%"; within:5; distance:3; byte_test:1,&,128,6,relative; content:"&|00|"; within:2; distance:56; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; content:"|05|"; distance:4; within:1; byte_test:1,!&,16,3,relati`
- Decision: ACTUAL_CORRECT
- Reason: Raw protocol/content/metadata supports the audited values; the model output was used only as a comparison candidate.

Original Claude expected:
```json
{
  "detected_behavior": "Suspicious network activity",
  "detected_entity": null,
  "entity_type": null,
  "category": "Network Abuse",
  "subcategory": "Suspicious TCP Activity",
  "mitre_tactic": null,
  "mitre_technique": null,
  "mitre_technique_id": null,
  "cyber_kill_chain_phase": null
}
```
Gemini actual:
```json
{
  "detected_behavior": "SMB unicode bind attempt against msqueue",
  "detected_entity": "CVE-2003-0995",
  "entity_type": "Other",
  "category": "Exploitation",
  "subcategory": "SMB Exploitation",
  "mitre_tactic": "Initial Access",
  "mitre_technique": "Exploit Public-Facing Application",
  "mitre_technique_id": "T1190",
  "cyber_kill_chain_phase": "Exploitation"
}
```
Final audited expected:
```json
{
  "detected_behavior": "SMB msqueue bind attempt",
  "detected_entity": null,
  "entity_type": null,
  "category": "Network Abuse",
  "subcategory": "Suspicious TCP Activity",
  "mitre_tactic": null,
  "mitre_technique": null,
  "mitre_technique_id": null,
  "cyber_kill_chain_phase": null
}
```

### SID 2063279

- MSG: ET HUNTING ConnectWise ScreenConnect Revoked Code Signing Certificate M1
- RAW evidence: `alert tcp any any -> $HOME_NET any (msg:"ET HUNTING ConnectWise ScreenConnect Revoked Code Signing Certificate M1"; flow:established,to_client; content:"Connectwise, LLC"; content:"|30 82 07 60 30 82 05 48 A0 03 02 01 02 02 10 0B 93 60 05 1B CC F6 66 42 99 89 98 D5 BA 97 CE|"; fast_pattern; reference:url,www.gdatasoftware.com/blog/2025/06/38218-connectwise-abuse-malware; classtype:bad-unknown; sid:2063279; rev:1; metadata:attack_target Client_Endpoint, created_at 2025_07_03, deployment Perimeter`
- Decision: BOTH_INCORRECT
- Reason: Raw protocol/content/metadata supports the audited values; the model output was used only as a comparison candidate.

Original Claude expected:
```json
{
  "detected_behavior": "ScreenConnect remote access software communication",
  "detected_entity": "ScreenConnect",
  "entity_type": "Remote Access Tool",
  "category": "Remote Access",
  "subcategory": "Remote Administration Tool",
  "mitre_tactic": null,
  "mitre_technique": null,
  "mitre_technique_id": null,
  "cyber_kill_chain_phase": "Command and Control"
}
```
Gemini actual:
```json
{
  "detected_behavior": "ConnectWise ScreenConnect Revoked Code Signing Certificate M1",
  "detected_entity": "ConnectWise ScreenConnect",
  "entity_type": "Product",
  "category": "Defense Evasion",
  "subcategory": "Masquerading",
  "mitre_tactic": "Defense Evasion",
  "mitre_technique": "Masquerading",
  "mitre_technique_id": "T1036",
  "cyber_kill_chain_phase": "Installation"
}
```
Final audited expected:
```json
{
  "detected_behavior": "Observation of a revoked ScreenConnect code-signing certificate",
  "detected_entity": "ScreenConnect",
  "entity_type": "Remote Access Tool",
  "category": "Remote Access",
  "subcategory": "Remote Administration Tool",
  "mitre_tactic": null,
  "mitre_technique": null,
  "mitre_technique_id": null,
  "cyber_kill_chain_phase": null
}
```

### SID 2103120

- MSG: GPL NETBIOS SMB llsrconnect unicode andx overflow attempt
- RAW evidence: `alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB llsrconnect unicode andx overflow attempt"; flow:established,to_server; flowbits:isset,smb.tree.bind.llsrpc; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C 00|P|00|I|00|P|00|E|00 5C 00 00 00|"; distance:4; nocase`
- Decision: ACTUAL_CORRECT
- Reason: Raw protocol/content/metadata supports the audited values; the model output was used only as a comparison candidate.

Original Claude expected:
```json
{
  "detected_behavior": "Suspicious network activity",
  "detected_entity": null,
  "entity_type": null,
  "category": "Network Abuse",
  "subcategory": "Suspicious TCP Activity",
  "mitre_tactic": null,
  "mitre_technique": null,
  "mitre_technique_id": null,
  "cyber_kill_chain_phase": null
}
```
Gemini actual:
```json
{
  "detected_behavior": "Buffer overflow attempt via NETBIOS SMB",
  "detected_entity": "SMB",
  "entity_type": "Protocol",
  "category": "Exploitation",
  "subcategory": "Buffer Overflow",
  "mitre_tactic": null,
  "mitre_technique": null,
  "mitre_technique_id": null,
  "cyber_kill_chain_phase": "Exploitation"
}
```
Final audited expected:
```json
{
  "detected_behavior": "SMB llsrconnect overflow attempt",
  "detected_entity": null,
  "entity_type": null,
  "category": "Exploitation",
  "subcategory": "Exploit Attempt",
  "mitre_tactic": null,
  "mitre_technique": null,
  "mitre_technique_id": null,
  "cyber_kill_chain_phase": "Exploitation"
}
```

### SID 2005279

- MSG: ET WEB_SPECIFIC_APPS Easebay Resources Login Manager SQL Injection Attempt -- memberlist.php init_row UPDATE
- RAW evidence: `alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SPECIFIC_APPS Easebay Resources Login Manager SQL Injection Attempt -- memberlist.php init_row UPDATE"; flow:established,to_server; http.uri; content:"/admin/memberlist.php?"; nocase; content:"init_row="; nocase; content:"UPDATE"; nocase; content:"SET"; nocase; distance:0; reference:cve,CVE-2007-0401; reference:url,www.securityfocus.com/archive/1/archive/1/457505/100/0/threaded; classtype:web-application-attack; sid:2005279; rev:9; m`
- Decision: ACTUAL_CORRECT
- Reason: Raw protocol/content/metadata supports the audited values; the model output was used only as a comparison candidate.

Original Claude expected:
```json
{
  "detected_behavior": "Credential access-related network activity",
  "detected_entity": null,
  "entity_type": null,
  "category": "Credential Access",
  "subcategory": "Credential Activity",
  "mitre_tactic": "Initial Access",
  "mitre_technique": "Exploit Public-Facing Application",
  "mitre_technique_id": "T1190",
  "cyber_kill_chain_phase": null
}
```
Gemini actual:
```json
{
  "detected_behavior": "SQL Injection Attempt",
  "detected_entity": "Easebay Resources Login Manager",
  "entity_type": "Product",
  "category": "Web Attack",
  "subcategory": "SQL Injection",
  "mitre_tactic": "Initial Access",
  "mitre_technique": "Exploit Public-Facing Application",
  "mitre_technique_id": "T1190",
  "cyber_kill_chain_phase": "Exploitation"
}
```
Final audited expected:
```json
{
  "detected_behavior": "SQL injection attempt against Easebay Resources Login Manager",
  "detected_entity": "Easebay Resources Login Manager",
  "entity_type": "Product",
  "category": "Web Attack",
  "subcategory": "SQL Injection",
  "mitre_tactic": "Initial Access",
  "mitre_technique": "Exploit Public-Facing Application",
  "mitre_technique_id": "T1190",
  "cyber_kill_chain_phase": "Exploitation"
}
```

### SID 2013682

- MSG: ET WEB_SPECIFIC_APPS Simplis CMS download_file Parameter Local File Inclusion Attempt
- RAW evidence: `alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SPECIFIC_APPS Simplis CMS download_file Parameter Local File Inclusion Attempt"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/index.php?"; nocase; content:"action=do_download"; fast_pattern; nocase; content:"download_file="; nocase; http.uri.raw; url_decode; content:"|2e 2e 2f|"; reference:url,packetstormsecurity.org/files/view/99797/simpliscms-disclose.txt; classtype:web-application-attack; sid:2013682`
- Decision: ACTUAL_CORRECT
- Reason: Raw protocol/content/metadata supports the audited values; the model output was used only as a comparison candidate.

Original Claude expected:
```json
{
  "detected_behavior": "Suspicious network activity",
  "detected_entity": null,
  "entity_type": null,
  "category": "Network Abuse",
  "subcategory": "Suspicious HTTP Activity",
  "mitre_tactic": "Initial Access",
  "mitre_technique": "Exploit Public-Facing Application",
  "mitre_technique_id": "T1190",
  "cyber_kill_chain_phase": null
}
```
Gemini actual:
```json
{
  "detected_behavior": "Local File Inclusion Attempt",
  "detected_entity": "Simplis CMS",
  "entity_type": "Product",
  "category": "Web Attack",
  "subcategory": "Local File Inclusion",
  "mitre_tactic": "Initial Access",
  "mitre_technique": "Exploit Public-Facing Application",
  "mitre_technique_id": "T1190",
  "cyber_kill_chain_phase": "Exploitation"
}
```
Final audited expected:
```json
{
  "detected_behavior": "Local file inclusion attempt against Simplis CMS",
  "detected_entity": "Simplis CMS",
  "entity_type": "Product",
  "category": "Web Attack",
  "subcategory": "Web Exploit Attempt",
  "mitre_tactic": "Initial Access",
  "mitre_technique": "Exploit Public-Facing Application",
  "mitre_technique_id": "T1190",
  "cyber_kill_chain_phase": "Exploitation"
}
```

## Before vs After Evaluation

| Metric | Before | After | Delta |
|---|---:|---:|---:|
| detected_behavior | 0.0% | 1.0% | +1.0% |
| detected_entity | 33.0% | 38.1% | +5.1% |
| entity_type | 29.0% | 34.0% | +5.0% |
| category | 48.0% | 56.7% | +8.7% |
| subcategory | 4.0% | 5.2% | +1.2% |
| mitre_tactic | 58.0% | 63.9% | +5.9% |
| mitre_technique | 53.0% | 58.8% | +5.8% |
| mitre_technique_id | 54.0% | 59.8% | +5.8% |
| cyber_kill_chain_phase | 55.0% | 58.8% | +3.8% |
| entity null hallucination | 90.0% | 88.9% | -1.1% |

- Before evaluated: 100
- After evaluated: 97

> This remains an AI-assisted benchmark (Claude initial review + Codex secondary audit), not expert-human ground truth.