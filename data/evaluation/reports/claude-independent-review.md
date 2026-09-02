# Claude Independent Review Report

**Review Date**: 2026-09-01 12:40:01 UTC
**Review Method**: CLAUDE_INDEPENDENT_REVIEW
**Reviewer**: claude_independent_reviewer

---

## Summary

| Metric | Count |
|---|---|
| Total samples | 100 |
| APPROVED | 20 |
| EDITED | 80 |
| DISPUTED | 0 |
| FAILED | 0 |

---

## MITRE Mapping Quality

| Metric | Count |
|---|---|
| MITRE mappings retained | 35 |
| MITRE mappings removed | 4 |
| MITRE mappings corrected | 0 |
| MITRE mappings added | 15 |

---

## Entity Quality

| Metric | Count |
|---|---|
| Entities retained | 20 |
| Entities removed | 2 |
| Entities corrected | 2 |
| Entities added | 8 |

---

## Kill Chain Mapping Quality

| Metric | Count |
|---|---|
| Kill Chain mappings retained | 45 |
| Kill Chain mappings removed | 0 |
| Kill Chain mappings corrected | 4 |

---

## Verifier Agreement Comparison

| Previous Verifier | Claude Decision | Count |
|---|---|---|
| AGREE | APPROVE | 20 |
| AGREE | EDIT | 79 |
| AGREE | DISPUTE | 0 |
| PARTIAL | APPROVE | 0 |
| PARTIAL | EDIT | 0 |
| PARTIAL | DISPUTE | 0 |
| DISAGREE | APPROVE | 0 |
| DISAGREE | EDIT | 1 |
| DISAGREE | DISPUTE | 0 |

---

## Most Important Corrections

### SID 2060849
**MSG**: ET EXPLOIT_KIT Observed ClickFix Domain (authentication-to .help) in DNS Lookup
**Decision**: EDIT
**Changes**:
- **detected_behavior**: `DNS lookup for suspicious infrastructure` → `ClickFix malware-related network activity`
  - Reason: Behavior description adjusted for accuracy
- **category**: `Suspicious DNS` → `Malware`
  - Reason: Category changed from 'Suspicious DNS' to 'Malware' based on rule semantics and ET prefix
- **subcategory**: `Malicious Domain` → `Malware Network Activity`
  - Reason: Subcategory refined to better match rule behavior
- **mitre_tactic**: `None` → `Initial Access`
  - Reason: MITRE fields corrected to match canonical local repository
- **mitre_technique**: `None` → `Drive-by Compromise`
  - Reason: MITRE fields corrected to match canonical local repository
- **mitre_technique_id**: `None` → `T1189`
  - Reason: T1189 is defensible based on rule behavior

### SID 2522039
**MSG**: ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 40
**Decision**: EDIT
**Changes**:
- **detected_behavior**: `Suspicious TCP Activity` → `Tor anonymity network usage`
  - Reason: Behavior description adjusted for accuracy
- **detected_entity**: `None` → `Tor`
  - Reason: 'Tor' appears directly in rule message/content
- **entity_type**: `None` → `Software`
  - Reason: Corrected entity type to match entity classification
- **category**: `Network Abuse` → `Policy Violation`
  - Reason: Category changed from 'Network Abuse' to 'Policy Violation' based on rule semantics and ET prefix
- **subcategory**: `Suspicious TCP Activity` → `Prohibited Application or Protocol`
  - Reason: Subcategory refined to better match rule behavior

### SID 2023535
**MSG**: ET WEB_SERVER Possible Apache Struts OGNL Expression Injection
**Decision**: EDIT
**Changes**:
- **detected_entity**: `Apache HTTP server` → `None`
  - Reason: Rule does not meaningfully identify 'Apache HTTP server'; port/protocol alone is insufficient
- **entity_type**: `Product` → `None`
  - Reason: Entity type removed because entity is null
- **mitre_tactic**: `None` → `Initial Access`
  - Reason: MITRE fields corrected to match canonical local repository
- **mitre_technique**: `None` → `Exploit Public-Facing Application`
  - Reason: MITRE fields corrected to match canonical local repository
- **mitre_technique_id**: `None` → `T1190`
  - Reason: T1190 is defensible based on rule behavior

### SID 2522034
**MSG**: ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 35
**Decision**: EDIT
**Changes**:
- **detected_behavior**: `Suspicious TCP Activity` → `Tor anonymity network usage`
  - Reason: Behavior description adjusted for accuracy
- **detected_entity**: `None` → `Tor`
  - Reason: 'Tor' appears directly in rule message/content
- **entity_type**: `None` → `Software`
  - Reason: Corrected entity type to match entity classification
- **category**: `Network Abuse` → `Policy Violation`
  - Reason: Category changed from 'Network Abuse' to 'Policy Violation' based on rule semantics and ET prefix
- **subcategory**: `Suspicious TCP Activity` → `Prohibited Application or Protocol`
  - Reason: Subcategory refined to better match rule behavior

### SID 2008228
**MSG**: ET SCAN Suspicious User-Agent inbound (bot)
**Decision**: EDIT
**Changes**:
- **detected_behavior**: `Network service scanning` → `Web scanning activity`
  - Reason: Behavior description adjusted for accuracy
- **subcategory**: `Service Scan` → `Web Scan`
  - Reason: Subcategory refined to better match rule behavior
- **mitre_tactic**: `Discovery` → `None`
  - Reason: MITRE fields corrected to match canonical local repository
- **mitre_technique**: `Network Service Scanning` → `None`
  - Reason: MITRE fields corrected to match canonical local repository
- **mitre_technique_id**: `T1046` → `None`
  - Reason: T1046 not supported by rule behavior or not in local repository

### SID 2069316
**MSG**: ET EXPLOIT_KIT ClickFix Domain in DNS Lookup (silenttunnelzone .top)
**Decision**: EDIT
**Changes**:
- **detected_behavior**: `DNS lookup for suspicious infrastructure` → `PowerShell malware-related network activity`
  - Reason: Behavior description adjusted for accuracy
- **detected_entity**: `None` → `PowerShell`
  - Reason: 'PowerShell' appears directly in rule message/content
- **entity_type**: `None` → `Software`
  - Reason: Corrected entity type to match entity classification
- **category**: `Suspicious DNS` → `Malware`
  - Reason: Category changed from 'Suspicious DNS' to 'Malware' based on rule semantics and ET prefix
- **subcategory**: `Malicious Domain` → `Malware Network Activity`
  - Reason: Subcategory refined to better match rule behavior

### SID 2520089
**MSG**: ET TOR Known Tor Exit Node Traffic group 90
**Decision**: EDIT
**Changes**:
- **detected_behavior**: `Suspicious TCP Activity` → `Tor anonymity network usage`
  - Reason: Behavior description adjusted for accuracy
- **detected_entity**: `None` → `Tor`
  - Reason: 'Tor' appears directly in rule message/content
- **entity_type**: `None` → `Software`
  - Reason: Corrected entity type to match entity classification
- **category**: `Network Abuse` → `Policy Violation`
  - Reason: Category changed from 'Network Abuse' to 'Policy Violation' based on rule semantics and ET prefix
- **subcategory**: `Suspicious TCP Activity` → `Prohibited Application or Protocol`
  - Reason: Subcategory refined to better match rule behavior

### SID 2025461
**MSG**: ET SCAN NYU Internet Census UA Inbound
**Decision**: EDIT
**Changes**:
- **detected_behavior**: `Network service scanning` → `Web scanning activity`
  - Reason: Behavior description adjusted for accuracy
- **subcategory**: `Service Scan` → `Web Scan`
  - Reason: Subcategory refined to better match rule behavior
- **mitre_tactic**: `Discovery` → `None`
  - Reason: MITRE fields corrected to match canonical local repository
- **mitre_technique**: `Network Service Scanning` → `None`
  - Reason: MITRE fields corrected to match canonical local repository
- **mitre_technique_id**: `T1046` → `None`
  - Reason: T1046 not supported by rule behavior or not in local repository

### SID 2522714
**MSG**: ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 715
**Decision**: EDIT
**Changes**:
- **detected_behavior**: `Suspicious TCP Activity` → `Tor anonymity network usage`
  - Reason: Behavior description adjusted for accuracy
- **detected_entity**: `None` → `Tor`
  - Reason: 'Tor' appears directly in rule message/content
- **entity_type**: `None` → `Software`
  - Reason: Corrected entity type to match entity classification
- **category**: `Network Abuse` → `Policy Violation`
  - Reason: Category changed from 'Network Abuse' to 'Policy Violation' based on rule semantics and ET prefix
- **subcategory**: `Suspicious TCP Activity` → `Prohibited Application or Protocol`
  - Reason: Subcategory refined to better match rule behavior

### SID 2002953
**MSG**: ET P2P TOR 1.0 Outbound Circuit Traffic
**Decision**: EDIT
**Changes**:
- **detected_behavior**: `Suspicious TCP Activity` → `Tor anonymity network usage`
  - Reason: Behavior description adjusted for accuracy
- **detected_entity**: `None` → `Tor`
  - Reason: 'Tor' appears directly in rule message/content
- **entity_type**: `None` → `Software`
  - Reason: Corrected entity type to match entity classification
- **category**: `Network Abuse` → `Policy Violation`
  - Reason: Category changed from 'Network Abuse' to 'Policy Violation' based on rule semantics and ET prefix
- **subcategory**: `Suspicious TCP Activity` → `Prohibited Application or Protocol`
  - Reason: Subcategory refined to better match rule behavior

### SID 2024364
**MSG**: ET SCAN Possible Nmap User-Agent Observed
**Decision**: EDIT
**Changes**:
- **detected_behavior**: `Network service scanning` → `Web scanning activity`
  - Reason: Behavior description adjusted for accuracy
- **subcategory**: `Service Scan` → `Web Scan`
  - Reason: Subcategory refined to better match rule behavior
- **mitre_tactic**: `Discovery` → `None`
  - Reason: MITRE fields corrected to match canonical local repository
- **mitre_technique**: `Network Service Scanning` → `None`
  - Reason: MITRE fields corrected to match canonical local repository
- **mitre_technique_id**: `T1046` → `None`
  - Reason: T1046 not supported by rule behavior or not in local repository

### SID 2009159
**MSG**: ET SCAN Toata Scanner User-Agent Detected
**Decision**: EDIT
**Changes**:
- **detected_behavior**: `Network service scanning` → `Web scanning activity`
  - Reason: Behavior description adjusted for accuracy
- **subcategory**: `Service Scan` → `Web Scan`
  - Reason: Subcategory refined to better match rule behavior
- **mitre_tactic**: `Discovery` → `None`
  - Reason: MITRE fields corrected to match canonical local repository
- **mitre_technique**: `Network Service Scanning` → `None`
  - Reason: MITRE fields corrected to match canonical local repository
- **mitre_technique_id**: `T1046` → `None`
  - Reason: T1046 not supported by rule behavior or not in local repository

### SID 2048071
**MSG**: ET RETIRED [TW] Observed Microsoft Credential Phish V3 Domain (bc1qc230lt32ey73qlaj9rkujm0ujtv090 .com in TLS SNI)
**Decision**: EDIT
**Changes**:
- **detected_behavior**: `Phishing Infrastructure` → `Credential phishing attempt`
  - Reason: Behavior description adjusted for accuracy
- **mitre_tactic**: `None` → `Initial Access`
  - Reason: MITRE fields corrected to match canonical local repository
- **mitre_technique**: `None` → `Spearphishing Attachment`
  - Reason: MITRE fields corrected to match canonical local repository
- **mitre_technique_id**: `None` → `T1566.001`
  - Reason: T1566.001 is defensible based on rule behavior

### SID 2032178
**MSG**: ET PHISHING Successful Apple Phish 2016-03-09
**Decision**: EDIT
**Changes**:
- **detected_behavior**: `Phishing Infrastructure` → `Credential phishing attempt`
  - Reason: Behavior description adjusted for accuracy
- **mitre_tactic**: `None` → `Initial Access`
  - Reason: MITRE fields corrected to match canonical local repository
- **mitre_technique**: `None` → `Spearphishing Attachment`
  - Reason: MITRE fields corrected to match canonical local repository
- **mitre_technique_id**: `None` → `T1566.001`
  - Reason: T1566.001 is defensible based on rule behavior

### SID 2049581
**MSG**: ET PHISHING TA444 Domain in TLS SNI (meeting-online .site)
**Decision**: EDIT
**Changes**:
- **detected_behavior**: `Phishing Infrastructure` → `Credential phishing attempt`
  - Reason: Behavior description adjusted for accuracy
- **mitre_tactic**: `None` → `Initial Access`
  - Reason: MITRE fields corrected to match canonical local repository
- **mitre_technique**: `None` → `Spearphishing Attachment`
  - Reason: MITRE fields corrected to match canonical local repository
- **mitre_technique_id**: `None` → `T1566.001`
  - Reason: T1566.001 is defensible based on rule behavior

### SID 2031797
**MSG**: ET PHISHING Successful Dropbox Phish 2015-12-10
**Decision**: EDIT
**Changes**:
- **detected_behavior**: `Phishing Infrastructure` → `Credential phishing attempt`
  - Reason: Behavior description adjusted for accuracy
- **mitre_tactic**: `None` → `Initial Access`
  - Reason: MITRE fields corrected to match canonical local repository
- **mitre_technique**: `None` → `Spearphishing Attachment`
  - Reason: MITRE fields corrected to match canonical local repository
- **mitre_technique_id**: `None` → `T1566.001`
  - Reason: T1566.001 is defensible based on rule behavior

### SID 2100652
**MSG**: GPL SHELLCODE Linux shellcode
**Decision**: EDIT
**Changes**:
- **detected_behavior**: `Suspicious IP Activity` → `Exploit attempt against a network-accessible service`
  - Reason: Behavior description adjusted for accuracy
- **category**: `Network Abuse` → `Exploitation`
  - Reason: Category changed from 'Network Abuse' to 'Exploitation' based on rule semantics and ET prefix
- **subcategory**: `Suspicious IP Activity` → `Exploit Attempt`
  - Reason: Subcategory refined to better match rule behavior
- **cyber_kill_chain_phase**: `None` → `Exploitation`
  - Reason: Kill Chain phase adjusted to match rule behavior

### SID 2025524
**MSG**: ET PHISHING MyADP Phishing Landing 2018-04-19
**Decision**: EDIT
**Changes**:
- **detected_behavior**: `Phishing Infrastructure` → `Credential phishing attempt`
  - Reason: Behavior description adjusted for accuracy
- **mitre_tactic**: `None` → `Initial Access`
  - Reason: MITRE fields corrected to match canonical local repository
- **mitre_technique**: `None` → `Spearphishing Attachment`
  - Reason: MITRE fields corrected to match canonical local repository
- **mitre_technique_id**: `None` → `T1566.001`
  - Reason: T1566.001 is defensible based on rule behavior

### SID 2066004
**MSG**: ET WEB_SPECIFIC_APPS AvTech PwdGrp.cgi user Parameter Cross Site Scripting Attempt (CVE-2025-57202)
**Decision**: EDIT
**Changes**:
- **detected_behavior**: `Suspicious HTTP Activity` → `Web attack attempt: Cross-Site Scripting`
  - Reason: Behavior description adjusted for accuracy
- **category**: `Network Abuse` → `Web Attack`
  - Reason: Category changed from 'Network Abuse' to 'Web Attack' based on rule semantics and ET prefix
- **subcategory**: `Suspicious HTTP Activity` → `Cross-Site Scripting`
  - Reason: Subcategory refined to better match rule behavior
- **cyber_kill_chain_phase**: `None` → `Exploitation`
  - Reason: Kill Chain phase adjusted to match rule behavior

### SID 2031901
**MSG**: ET PHISHING Successful Wildblue Phishing M1 2015-11-24
**Decision**: EDIT
**Changes**:
- **detected_behavior**: `Phishing Infrastructure` → `Credential phishing attempt`
  - Reason: Behavior description adjusted for accuracy
- **mitre_tactic**: `None` → `Initial Access`
  - Reason: MITRE fields corrected to match canonical local repository
- **mitre_technique**: `None` → `Spearphishing Attachment`
  - Reason: MITRE fields corrected to match canonical local repository
- **mitre_technique_id**: `None` → `T1566.001`
  - Reason: T1566.001 is defensible based on rule behavior

---

## All Review Decisions

| SID | Decision | Confidence | Changes | MSG (truncated) |
|---|---|---|---|---|
| 2010935 | APPROVE | 0.9 | 0 | ET SCAN Suspicious inbound to MSSQL port 1433 |
| 2021837 | APPROVE | 0.9 | 0 | ET MALWARE r0 CnC Architecture POST 4 |
| 2056356 | APPROVE | 0.9 | 0 | ET EXPLOIT Zimbra postjournal RCE Attempt Inbound (CVE-2024- |
| 2059511 | APPROVE | 0.82 | 0 | ET INFO Observed Smart Chain Domain in DNS Lookup (gnfd-test |
| 2045262 | EDIT | 0.88 | 2 | ET DYN_DNS DYNAMIC_DNS HTTP Request to a *.codingtheworld .c |
| 2019842 | EDIT | 0.88 | 1 | ET WEB_CLIENT Possible Internet Explorer VBscript CVE-2014-6 |
| 2046466 | EDIT | 0.88 | 1 | ET MOBILE_MALWARE Android Spy PREDATOR CnC Domain in DNS Loo |
| 2060513 | EDIT | 0.88 | 1 | ET REMOTE_ACCESS Observed Anydesk Domain (boot .net .anydesk |
| 2048071 | EDIT | 0.85 | 4 | ET RETIRED [TW] Observed Microsoft Credential Phish V3 Domai |
| 2046259 | EDIT | 0.85 | 1 | ET RETIRED Kimsuky ReconShark Related APT Activity |
| 2028779 | EDIT | 0.88 | 1 | ET JA3 Hash - [Abuse.ch] Possible Adware |
| 2102510 | EDIT | 0.88 | 1 | GPL NETBIOS SMB DCERPC LSASS bind attempt |
| 2522039 | EDIT | 0.82 | 5 | ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group  |
| 2009698 | EDIT | 0.82 | 3 | ET VOIP INVITE Message Flood UDP |
| 2403330 | EDIT | 0.82 | 1 | ET CINS Active Threat Intelligence Poor Reputation IP group  |
| 2002383 | EDIT | 0.88 | 1 | ET SCAN Potential FTP Brute-Force attempt response |
| 2062681 | EDIT | 0.88 | 1 | ET MALWARE Win32/Lumma Stealer Related CnC Domain in DNS Loo |
| 2023995 | APPROVE | 0.9 | 0 | ET EXPLOIT TP-LINK DNS Change GET Request (DNSChanger EK) |
| 2021371 | APPROVE | 0.82 | 0 | ET INFO Possible External IP Lookup www.whatsmyip.us |
| 2045845 | EDIT | 0.88 | 2 | ET DYN_DNS DYNAMIC_DNS Query to a *.ilovetkd .com Domain |
| 2023535 | EDIT | 0.85 | 5 | ET WEB_SERVER Possible Apache Struts OGNL Expression Injecti |
| 2030024 | EDIT | 0.85 | 3 | ET MOBILE_MALWARE NSO Group CnC Domain in DNS Lookup |
| 2050707 | EDIT | 0.88 | 1 | ET REMOTE_ACCESS AnyDesk Revoked Code Signing Certificate Ob |
| 2032178 | EDIT | 0.85 | 4 | ET PHISHING Successful Apple Phish 2016-03-09 |
| 2064098 | EDIT | 0.85 | 2 | ET WEB_SPECIFIC_APPS Tenda getMasterPassengerAnalyseData tim |
| 2049581 | EDIT | 0.85 | 4 | ET PHISHING TA444 Domain in TLS SNI (meeting-online .site) |
| 2103245 | EDIT | 0.88 | 1 | GPL NETBIOS SMB irot little endian andx bind attempt |
| 2522034 | EDIT | 0.82 | 5 | ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group  |
| 2101923 | EDIT | 0.82 | 3 | GPL RPC portmap proxy attempt UDP |
| 2400049 | EDIT | 0.82 | 1 | ET DROP Spamhaus DROP Listed Traffic Inbound group 50 |
| 2008228 | EDIT | 0.85 | 5 | ET SCAN Suspicious User-Agent inbound (bot) |
| 2068124 | EDIT | 0.88 | 1 | ET MALWARE Observed Win32/Lumma Stealer Related Domain (genu |
| 2044010 | APPROVE | 0.9 | 0 | ET EXPLOIT Possible Oracle E-Business RCE Attempt Inbound M1 |
| 2039495 | APPROVE | 0.82 | 0 | ET INFO IQDNS DNS Over HTTPS Certificate Inbound |
| 2069316 | EDIT | 0.85 | 5 | ET EXPLOIT_KIT ClickFix Domain in DNS Lookup (silenttunnelzo |
| 2025062 | EDIT | 0.88 | 1 | ET WEB_CLIENT PowerShell call in script 2 |
| 2016711 | APPROVE | 0.9 | 0 | ET MOBILE_MALWARE DNS Query Targeted Tibetan Android Malware |
| 2027413 | APPROVE | 0.9 | 0 | ET REMOTE_ACCESS Inbound RDP Connection with Minimal Securit |
| 2031797 | EDIT | 0.85 | 4 | ET PHISHING Successful Dropbox Phish 2015-12-10 |
| 2007299 | APPROVE | 0.9 | 0 | ET WEB_SPECIFIC_APPS Doug Luxem Liberum Help Desk SQL Inject |
| 2071589 | EDIT | 0.85 | 3 | ET EXPLOIT_KIT LandUpdate808 Domain in TLS SNI (randenbrink  |
| 2103271 | EDIT | 0.88 | 1 | GPL NETBIOS SMB-DS IrotIsRunning unicode little endian andx  |
| 2520089 | EDIT | 0.82 | 5 | ET TOR Known Tor Exit Node Traffic group 90 |
| 2100580 | EDIT | 0.82 | 3 | GPL RPC portmap nisd request UDP |
| 2100652 | EDIT | 0.82 | 4 | GPL SHELLCODE Linux shellcode |
| 2025461 | EDIT | 0.85 | 5 | ET SCAN NYU Internet Census UA Inbound |
| 2045426 | EDIT | 0.88 | 1 | ET MALWARE DNS Query to Raspberry Robin Domain (66j .me) |
| 2000564 | EDIT | 0.85 | 3 | ET EXPLOIT Pwdump3e pwservice.exe Access port 445 |
| 2052166 | APPROVE | 0.82 | 0 | ET INFO Observed URL Shortening Service Domain (trimmer .to  |
| 2041326 | EDIT | 0.88 | 2 | ET DYN_DNS DYNAMIC_DNS Query to a *.neoneptune .com Domain |
| 2011286 | EDIT | 0.88 | 1 | ET WEB_SERVER Bot Search RFI Scan (Casper-Like MaMa Cyber/eb |
| 2048086 | EDIT | 0.88 | 1 | ET MOBILE_MALWARE Android/MMRAT CnC Checkin M2 |
| 2060508 | EDIT | 0.88 | 1 | ET REMOTE_ACCESS Observed Anydesk Relay Domain (net .anydesk |
| 2025524 | EDIT | 0.85 | 4 | ET PHISHING MyADP Phishing Landing 2018-04-19 |
| 2066004 | EDIT | 0.85 | 4 | ET WEB_SPECIFIC_APPS AvTech PwdGrp.cgi user Parameter Cross  |
| 2064683 | EDIT | 0.85 | 3 | ET EXPLOIT_KIT LandUpdate808 Domain (math1st .com) in TLS SN |
| 2102994 | EDIT | 0.88 | 1 | GPL NETBIOS SMB InitiateSystemShutdown unicode andx attempt |
| 2522714 | EDIT | 0.82 | 5 | ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group  |
| 2015857 | EDIT | 0.82 | 3 | ET TFTP Outbound TFTP Data Transfer with Cisco config |
| 2500000 | EDIT | 0.82 | 1 | ET COMPROMISED Known Compromised or Hostile Host Traffic gro |
| 2010494 | EDIT | 0.88 | 1 | ET SCAN Multiple MySQL Login Failures Possible Brute Force A |
| 2066414 | EDIT | 0.88 | 1 | ET MALWARE Observed Win32/Lumma Stealer Related Domain (almz |
| 2019089 | EDIT | 0.85 | 3 | ET EXPLOIT F5 BIG-IP rsync cmi authorized_keys successful ex |
| 2053543 | APPROVE | 0.82 | 0 | ET INFO DNS Over HTTPS Domain in DNS Lookup (dns .esnube .es |
| 2059953 | EDIT | 0.85 | 3 | ET EXPLOIT_KIT LandUpdate808 Domain in DNS Lookup (telback . |
| 2026337 | EDIT | 0.85 | 3 | ET WEB_SERVER JSP.SJavaWebManage WebShell Pass 20-09-2018 1 |
| 2035500 | EDIT | 0.88 | 1 | ET MOBILE_MALWARE Trojan-Spy.AndroidOS.Realrat.c (DNS Lookup |
| 2014385 | APPROVE | 0.9 | 0 | ET DOS Microsoft Remote Desktop (RDP) Syn/Ack Outbound Flowb |
| 2031901 | EDIT | 0.85 | 4 | ET PHISHING Successful Wildblue Phishing M1 2015-11-24 |
| 2007184 | APPROVE | 0.9 | 0 | ET WEB_SPECIFIC_APPS Fixit iDMS Pro Image Gallery SQL Inject |
| 2046734 | EDIT | 0.85 | 4 | ET RETIRED Observed GobRAT Domain (wpksi .mefound .com) in T |
| 2103162 | EDIT | 0.88 | 1 | GPL NETBIOS SMB msqueue unicode bind attempt |
| 2002953 | EDIT | 0.82 | 5 | ET P2P TOR 1.0 Outbound Circuit Traffic |
| 2101732 | EDIT | 0.82 | 3 | GPL RPC portmap rwalld request UDP |
| 2029780 | EDIT | 0.82 | 1 | ET HUNTING Possible Covid19 Themed Email Spam Outbound M5 |
| 2024364 | EDIT | 0.85 | 5 | ET SCAN Possible Nmap User-Agent Observed |
| 2066757 | EDIT | 0.88 | 1 | ET MALWARE Observed Win32/Lumma Stealer Related Domain (poss |
| 2067417 | APPROVE | 0.9 | 0 | ET EXPLOIT Quest KACE Desktop Authority Insecure Named Pipe  |
| 2012900 | APPROVE | 0.82 | 0 | ET INFO DNS Query for a Suspicious *.ae.am domain |
| 2043750 | EDIT | 0.88 | 2 | ET DYN_DNS DYNAMIC_DNS HTTP Request to a *.vasilevsky .org D |
| 2016841 | EDIT | 0.85 | 3 | ET WEB_SERVER  ColdFusion path disclosure to get the absolut |
| 2034598 | EDIT | 0.88 | 1 | ET MOBILE_MALWARE Android Brunhilda Dropper (multifuctionsca |
| 2063279 | EDIT | 0.85 | 2 | ET HUNTING ConnectWise ScreenConnect Revoked Code Signing Ce |
| 2037271 | EDIT | 0.85 | 4 | ET PHISHING Caixa Credential Phish Landing Page 2022-07-05 |
| 2047979 | EDIT | 0.85 | 4 | ET PHISHING [TW] NOTG Obfuscation Redirect Observed M2 |
| 2066325 | EDIT | 0.85 | 3 | ET EXPLOIT_KIT LandUpdate808 Domain (fsglobe .com) in TLS SN |
| 2103120 | EDIT | 0.88 | 1 | GPL NETBIOS SMB llsrconnect unicode andx overflow attempt |
| 2009985 | EDIT | 0.82 | 4 | ET FTP Possible FTP Daemon Username UNION SELECT SQL Injecti |
| 2101280 | EDIT | 0.82 | 3 | GPL RPC portmap listing UDP 111 |
| 2400004 | EDIT | 0.82 | 1 | ET DROP Spamhaus DROP Listed Traffic Inbound group 5 |
| 2009159 | EDIT | 0.85 | 5 | ET SCAN Toata Scanner User-Agent Detected |
| 2056218 | EDIT | 0.88 | 1 | ET MALWARE Observed DNS Query to SloppyLemming/UNK_SloppyDis |
| 2033307 | APPROVE | 0.9 | 0 | ET EXPLOIT UDP Technology Firmware (IP Cam) - tmpapp.cgi RCE |
| 2047872 | APPROVE | 0.82 | 0 | ET INFO DNS Query for Port Mapping/Tunneling Service Domain  |
| 2060849 | EDIT | 0.85 | 6 | ET EXPLOIT_KIT Observed ClickFix Domain (authentication-to . |
| 2013940 | EDIT | 0.85 | 3 | ET WEB_SERVER Weevely PHP backdoor detected (proc_open() fun |
| 2033221 | EDIT | 0.85 | 4 | ET ADWARE_PUP Nivesro Cheat CnC Activity M1 |
| 2060632 | EDIT | 0.88 | 1 | ET REMOTE_ACCESS Observed TeamViewer RMM Related Domain (tea |
| 2005279 | APPROVE | 0.9 | 0 | ET WEB_SPECIFIC_APPS Easebay Resources Login Manager SQL Inj |
| 2013682 | EDIT | 0.88 | 1 | ET WEB_SPECIFIC_APPS Simplis CMS download_file Parameter Loc |
