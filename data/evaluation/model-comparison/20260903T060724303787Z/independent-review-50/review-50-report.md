# 50 Rule — Gemini / Qwen Bağımsız İnceleme

Bu rapor AI incelemesidir; human-reviewed ground truth veya accuracy raporu değildir. Hiçbir kayıt otomatik onaylanmadı.

## Yöntem

250 sabit SID/REV çifti sıralandı, Python random.Random(42).sample(..., 50) ile seçildi. 16 audited + 34 fresh. Disagreement/confidence oranına göre örnek seçilmedi. Aynı raw rule ve context hash kullanan tamamlanmış run sonuçları incelendi; 100 classification ID SQLite ile read-only doğrulandı. Model adları A/B olarak maskelendi, kanıt incelemesi ve kaynak doğrulaması sonrasında karar dosyası hash ile kilitlenip kimlikler açıldı. Bu iki bağımsız insan hakemi anlamına gelmez; tek AI reviewer iki çıktıyı da rule evidence ve local MITRE ile kontrol etti.

Dokuz alan birlikte incelendi: behavior, entity, entity type, category, subcategory, tactic, technique, technique ID, Kill Chain. Semantik tercih: belirgin yanlış/kanıtsız iddia veya geçersiz MITRE tuple açısından göreli üstünlük. Katalog tercihi: güvenliği gözeterek daha somut, filtrelenebilir ve denetlenebilir anlatım. Null alan tek başına hata değildir; daha dolu/uzun çıktı otomatik daha doğru değildir. Source ATT&CK association gözlenmiş saldırı başarısı değildir. Model confidence ve validator PASS hakem olarak kullanılmadı.

## Sonuç

| Ölçüm | Gemini | Qwen | Eşit |
|---|---:|---:|---:|
| Kanıta göre belirgin doğruluk üstünlüğü | 12 | 3 | 35 |
| Katalog kullanılabilirliği tercihi | 36 | 5 | 9 |

| Kontrol (her model 50 kayıt) | Gemini | Qwen |
|---|---:|---:|
| En az bir önemli bulgu taşıyan kayıt | 7 | 15 |
| Canonical MITRE tuple hatası | 0 | 8 |
| Validator PASS olmasına rağmen önemli bulgu | 7 | 7 |
| Entity atanmış (kalite puanı değil) | 14 | 14 |
| MITRE ID atanmış (kalite puanı değil) | 15 | 16 |
| Kill Chain atanmış (kalite puanı değil) | 33 | 9 |

Modeller: `gemini-3.5-flash-lite` ve `qwen3:8b`. Her ikisi mevcut V2.1 pipeline sonucu; raw model performansı izole edilmedi.

Bu 50 kural ve mevcut konfigürasyonda Gemini daha güçlü katalog baseline adayıdır: hem belirgin doğruluk farkı olan karşılaştırmalarda hem somut davranış açıklamalarında öndedir. Qwen bazı örneklerde daha temkinli/doğru ve kullanılabilir bir local alternatiftir; sonuç genel model ailesine değil bu kaydedilmiş run’a aittir. Qwen’in sekiz partial MITRE problemi kaydedilmiş validator tarafından REVIEW olarak yakalanmıştır; buna karşılık iki tarafta da PASS alıp bu incelemede önemli bulgu taşıyan yedişer kayıt vardır.

İki modelde de önemli bulgu: 2050707, 2003657, 2056218, 2103244. Eşitlik içinde ortak hata: 2050707, 2056218, 2103244.

**Bu sayılardan 50−bulgu = doğru sayısı veya accuracy üretilmemelidir.** Belirsiz/contextual kararlar notlarda açıklandı. Generic ama savunulabilir açıklamaları semantik hata saymamak çok sayıda eşitlik üretir; katalog tercihi bu farkı ayrıca görünür kılar.

## Operasyonel çıkarım

Öncelik sırası: (1) ATT&CK ID/name/tactic alanlarının atomik tutarlılığı; (2) HTTP host, DNS lookup ve DNS C2 ayrımı; (3) source IOC association ile doğrudan ürün/tool fingerprint ayrımı; (4) noalert/helper kurallarının katalog rolü; (5) protocol, method, CVE ve olasılık niteliğini kaybetmeyen behavior açıklamaları. Önce bu somut bulgular insan tarafından karara bağlanmalı. Fine-tuning gerekliliği bu 50 kayıttan tek başına çıkarılamaz. Classifier, prompt, taxonomy, model ayarları, DB, golden dataset ve benchmark değiştirilmedi.

## Kural bazlı kısa indeks

| # | SID/REV | Doğruluk tercihi | Katalog tercihi |
|---:|---|---|---|
| 1 | 2064637/1 | gemini-3.5-flash-lite | gemini-3.5-flash-lite |
| 2 | 2012060/2 | gemini-3.5-flash-lite | gemini-3.5-flash-lite |
| 3 | 2003194/7 | Eşit / kesin üstünlük yok | gemini-3.5-flash-lite |
| 4 | 2101388/14 | gemini-3.5-flash-lite | gemini-3.5-flash-lite |
| 5 | 2025067/3 | Eşit / kesin üstünlük yok | gemini-3.5-flash-lite |
| 6 | 2023019/4 | Eşit / kesin üstünlük yok | Eşit / kesin üstünlük yok |
| 7 | 2020702/5 | Eşit / kesin üstünlük yok | gemini-3.5-flash-lite |
| 8 | 2013682/5 | Eşit / kesin üstünlük yok | gemini-3.5-flash-lite |
| 9 | 2101280/10 | Eşit / kesin üstünlük yok | gemini-3.5-flash-lite |
| 10 | 2011286/7 | gemini-3.5-flash-lite | gemini-3.5-flash-lite |
| 11 | 2068435/1 | qwen3:8b | qwen3:8b |
| 12 | 2527005/1715 | gemini-3.5-flash-lite | gemini-3.5-flash-lite |
| 13 | 2403415/111389 | Eşit / kesin üstünlük yok | Eşit / kesin üstünlük yok |
| 14 | 2050707/2 | Eşit / kesin üstünlük yok | Eşit / kesin üstünlük yok |
| 15 | 2009985/2 | Eşit / kesin üstünlük yok | gemini-3.5-flash-lite |
| 16 | 2060513/2 | Eşit / kesin üstünlük yok | Eşit / kesin üstünlük yok |
| 17 | 2038015/2 | Eşit / kesin üstünlük yok | gemini-3.5-flash-lite |
| 18 | 2005279/9 | Eşit / kesin üstünlük yok | gemini-3.5-flash-lite |
| 19 | 2003657/21 | gemini-3.5-flash-lite | gemini-3.5-flash-lite |
| 20 | 2010494/5 | qwen3:8b | qwen3:8b |
| 21 | 2019089/6 | Eşit / kesin üstünlük yok | gemini-3.5-flash-lite |
| 22 | 2021371/7 | Eşit / kesin üstünlük yok | gemini-3.5-flash-lite |
| 23 | 2047740/1 | Eşit / kesin üstünlük yok | gemini-3.5-flash-lite |
| 24 | 2060760/1 | Eşit / kesin üstünlük yok | qwen3:8b |
| 25 | 2527010/1715 | gemini-3.5-flash-lite | gemini-3.5-flash-lite |
| 26 | 2056218/1 | Eşit / kesin üstünlük yok | Eşit / kesin üstünlük yok |
| 27 | 2017873/3 | gemini-3.5-flash-lite | gemini-3.5-flash-lite |
| 28 | 2100606/7 | Eşit / kesin üstünlük yok | gemini-3.5-flash-lite |
| 29 | 2066004/1 | Eşit / kesin üstünlük yok | Eşit / kesin üstünlük yok |
| 30 | 2100366/8 | Eşit / kesin üstünlük yok | gemini-3.5-flash-lite |
| 31 | 2500010/7731 | Eşit / kesin üstünlük yok | Eşit / kesin üstünlük yok |
| 32 | 2037772/2 | qwen3:8b | qwen3:8b |
| 33 | 2019842/7 | Eşit / kesin üstünlük yok | gemini-3.5-flash-lite |
| 34 | 2040009/3 | gemini-3.5-flash-lite | gemini-3.5-flash-lite |
| 35 | 2060508/2 | Eşit / kesin üstünlük yok | Eşit / kesin üstünlük yok |
| 36 | 2025094/7 | Eşit / kesin üstünlük yok | qwen3:8b |
| 37 | 2102809/5 | Eşit / kesin üstünlük yok | gemini-3.5-flash-lite |
| 38 | 2001581/15 | Eşit / kesin üstünlük yok | gemini-3.5-flash-lite |
| 39 | 2101640/12 | gemini-3.5-flash-lite | gemini-3.5-flash-lite |
| 40 | 2102785/5 | Eşit / kesin üstünlük yok | gemini-3.5-flash-lite |
| 41 | 2014649/7 | Eşit / kesin üstünlük yok | gemini-3.5-flash-lite |
| 42 | 2100289/12 | gemini-3.5-flash-lite | gemini-3.5-flash-lite |
| 43 | 2404304/8031 | Eşit / kesin üstünlük yok | gemini-3.5-flash-lite |
| 44 | 2029780/3 | Eşit / kesin üstünlük yok | gemini-3.5-flash-lite |
| 45 | 2103244/5 | Eşit / kesin üstünlük yok | gemini-3.5-flash-lite |
| 46 | 2014402/3 | gemini-3.5-flash-lite | gemini-3.5-flash-lite |
| 47 | 2403426/111389 | Eşit / kesin üstünlük yok | gemini-3.5-flash-lite |
| 48 | 2101732/10 | Eşit / kesin üstünlük yok | gemini-3.5-flash-lite |
| 49 | 2029645/2 | Eşit / kesin üstünlük yok | gemini-3.5-flash-lite |
| 50 | 2520127/6363 | Eşit / kesin üstünlük yok | Eşit / kesin üstünlük yok |

## 50 kuralın ayrıntılı incelemesi

### 1. SID 2064637 / REV 1

Cohort: FRESH_OPERATIONAL — Source: `data\rules\et-open\emerging-dyn_dns.rules`

```text
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET DYN_DNS DYNAMIC_DNS HTTP Request to a *.gsxpress .com .my domain"; flow:established,to_server; http.host; content:".gsxpress.com.my"; endswith; fast_pattern; reference:url,freedns.afraid.org/domain/registry/page-6.html; classtype:bad-unknown; sid:2064637; rev:1; metadata:attack_target Client_and_Server, created_at 2025_09_14, deployment Perimeter, confidence High, signature_severity Informational, updated_at 2025_09_14, mitre_tactic_id TA0011, mitre_tactic_name Command_And_Control, mitre_technique_id T1568, mitre_technique_name Dynamic_Resolution;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | HTTP Request to a dynamic DNS domain | HTTP request to a dynamic DNS domain |
| detected_entity | null | null |
| entity_type | null | null |
| category | Command and Control | Suspicious DNS |
| subcategory | HTTP C2 Communication | Unusual DNS Query |
| mitre_tactic | Command And Control | Command And Control |
| mitre_technique | Dynamic Resolution | Dynamic Resolution |
| mitre_technique_id | T1568 | T1568 |
| cyber_kill_chain_phase | Command and Control | null |
| model_confidence (hakem puanı değil) | 0.9 | 0.9 |

**gemini-3.5-flash-lite — kör etiket A, classification ID 1343**

Kaydedilmiş validator: PASS; MITRE provenance: EXACT_SOURCE_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET DYN_DNS DYNAMIC_DNS HTTP Request to a *.gsxpress .com .my domain", "content: .gsxpress.com.my", "metadata: mitre_technique_id T1568", "metadata: mitre_tactic_id TA0011", "mitre_candidate:T1568:0.90"]

**qwen3:8b — kör etiket B, classification ID 1347**

Kaydedilmiş validator: PASS; MITRE provenance: EXACT_SOURCE_MAPPING; önemli bulgu alanları: subcategory.

Evidence: ["content: .gsxpress.com.my", "metadata: mitre_tactic_id TA0011, mitre_technique_id T1568", "mitre_candidates: T1568 (Dynamic Resolution)", "mitre_candidate:T1568:0.90"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

http.host .gsxpress.com.my eşleşmesi HTTP gözlemidir. A HTTP davranışını ve canonical source T1568'i koruyor; HTTP C2/Kill Chain yalnız olası source ilişkisi, doğrulanmış C2 oturumu değil. B behavior'da HTTP derken Unusual DNS Query alt kategorisi atayarak protokolle çelişiyor. Her iki entity null savunulabilir.

Doğruluk tercihi: **gemini-3.5-flash-lite**. Katalog tercihi: **gemini-3.5-flash-lite**.

### 2. SID 2012060 / REV 2

Cohort: FRESH_OPERATIONAL — Source: `data\rules\et-open\emerging-web_client.rules`

```text
alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET WEB_CLIENT Hex Obfuscation of document.write %u UTF-8 Encoding"; flow:established,to_client; content:"%u64%u6f%u63%u75%u6d%u65%u6e%u74%u2e%u77%u72%u69%u74%u65"; nocase; reference:url,cansecwest.com/slides07/csw07-nazario.pdf; reference:url,www.sophos.com/security/technical-papers/malware_with_your_mocha.html; classtype:bad-unknown; sid:2012060; rev:2; metadata:affected_product Web_Browsers, affected_product Web_Browser_Plugins, attack_target Client_Endpoint, created_at 2010_12_15, deployment Perimeter, signature_severity Major, tag Web_Client_Attacks, updated_at 2019_07_26;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | Hex obfuscation of document.write using UTF-8 encoding targeting web clients | Web Attack |
| detected_entity | null | null |
| entity_type | null | null |
| category | Web Attack | Web Attack |
| subcategory | null | Web Shell |
| mitre_tactic | null | Web Attack |
| mitre_technique | null | Web Shell |
| mitre_technique_id | null | null |
| cyber_kill_chain_phase | Exploitation | null |
| model_confidence (hakem puanı değil) | 0.85 | 0.8 |

**gemini-3.5-flash-lite — kör etiket A, classification ID 1311**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET WEB_CLIENT Hex Obfuscation of document.write %u UTF-8 Encoding", "content: %u64%u6f%u63%u75%u6d%u65%u6e%u74%u2e%u77%u72%u69%u74%u65"]

**qwen3:8b — kör etiket B, classification ID 1320**

Kaydedilmiş validator: REVIEW; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: subcategory, mitre_tactic, mitre_technique.

Evidence: ["content: \"%u64%u6f%u63%u75%u6d%u65%u6e%u74%u2e%u77%u72%u69%u74%u65\" (hex obfuscation of document.write)", "category_hint: \"Web Attack\""]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

Sunucu cevabında %u64%u6f... document.write obfuscation dizisi var, web-shell kanıtı yok. A obfuscation'ı doğru tanıyor; msg'den aldığı UTF-8 açıklaması ayrıca doğrulanmış encoding bilgisi sayılmamalı, Exploitation da potansiyel amaçtır. B generic Web Attack yanında kanıtsız Web Shell ve ID'siz, canonical olmayan MITRE tuple üretiyor.

Doğruluk tercihi: **gemini-3.5-flash-lite**. Katalog tercihi: **gemini-3.5-flash-lite**.

### 3. SID 2003194 / REV 7

Cohort: FRESH_OPERATIONAL — Source: `data\rules\et-open\emerging-voip.rules`

```text
alert tcp $HOME_NET 5060 -> $EXTERNAL_NET any (msg:"ET VOIP Multiple Unauthorized SIP Responses TCP"; flow:established,to_client; content:"SIP/2.0 401 Unauthorized"; depth:24; threshold: type both, track by_src, count 5, seconds 360; classtype:attempted-dos; sid:2003194; rev:7; metadata:created_at 2010_07_30, confidence Medium, signature_severity Informational, tag Description_Generated_By_Proofpoint_Nexus, updated_at 2024_03_06;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | Multiple Unauthorized SIP Responses | Suspicious TCP Activity |
| detected_entity | null | null |
| entity_type | null | null |
| category | Denial of Service | Network Abuse |
| subcategory | null | Suspicious TCP Activity |
| mitre_tactic | null | null |
| mitre_technique | null | null |
| mitre_technique_id | null | null |
| cyber_kill_chain_phase | null | null |
| model_confidence (hakem puanı değil) | 0.8 | 0.5 |

**gemini-3.5-flash-lite — kör etiket B, classification ID 1490**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: \"ET VOIP Multiple Unauthorized SIP Responses TCP\"", "classtype: attempted-dos", "content: \"SIP/2.0 401 Unauthorized\""]

**qwen3:8b — kör etiket A, classification ID 1509**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["protocol: tcp", "classtype: attempted-dos", "content: SIP/2.0 401 Unauthorized", "flow: established, to_client"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

SIP/2.0 401, src5060, threshold both 5/360. A'nın Suspicious TCP seçimi yanlış değil ama SIP/authentication ayrıntısını kaybediyor. B Multiple Unauthorized SIP Responses ile daha iyi anlatıyor; DoS source classtype'a dayanan olası niyet, servis kesintisi kanıtı değil. RFC3261'e göre 401 normal authentication challenge da olabilir. Null entity/MITRE/KC her ikisinde uygun.

Doğruluk tercihi: **Eşit / kesin üstünlük yok**. Katalog tercihi: **gemini-3.5-flash-lite**.

Teknik kaynak: [RFC 3261: SIP 401 authentication](https://www.rfc-editor.org/info/rfc3261/), [Suricata threshold semantics](https://docs.suricata.io/en/latest/rules/thresholding.html)

### 4. SID 2101388 / REV 14

Cohort: FRESH_OPERATIONAL — Source: `data\rules\et-open\emerging-misc.rules`

```text
alert udp $EXTERNAL_NET any -> $HOME_NET 1900 (msg:"GPL MISC UPnP Location overflow"; content:"Location|3A|"; nocase; isdataat:128,relative; pcre:"/^Location\x3a[^\n]{128}/smi"; reference:bugtraq,3723; reference:cve,2001-0876; classtype:misc-attack; sid:2101388; rev:14; metadata:created_at 2010_09_23, cve CVE_2001_0876, signature_severity Informational, tag Description_Generated_By_Proofpoint_Nexus, updated_at 2019_07_26;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | Buffer Overflow | Buffer Overflow |
| detected_entity | null | null |
| entity_type | null | null |
| category | Exploitation | Exploitation |
| subcategory | Exploit Attempt | Exploit Attempt |
| mitre_tactic | null | Exploitation |
| mitre_technique | null | Exploit Attempt |
| mitre_technique_id | null | null |
| cyber_kill_chain_phase | Exploitation | null |
| model_confidence (hakem puanı değil) | 0.85 | 0.8 |

**gemini-3.5-flash-lite — kör etiket B, classification ID 1276**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: GPL MISC UPnP Location overflow", "classtype: misc-attack", "content: Location\|3A\|", "pcre: /^Location\\x3a[^\\n]{128}/smi", "reference: cve,2001-0876"]

**qwen3:8b — kör etiket A, classification ID 1282**

Kaydedilmiş validator: REVIEW; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: mitre_tactic, mitre_technique.

Evidence: ["content: \"Location\|3A\|\"", "pcre: /^Location\\x3a[^\\n]{128}/smi", "metadata: cve CVE_2001_0876", "references: cve,2001-0876"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

UPnP Location uzunluk PCRE'si, UDP1900 ve CVE-2001-0876 overflow bağlamını destekliyor. İki modelin Exploitation/Exploit Attempt seçimi uygun. A Exploitation ve Exploit Attempt'i ID'siz MITRE alanlarına da yazmış: geçerli ATT&CK değil. B MITRE tuple'ı null tutuyor. Ürün/tool atamamak savunulabilir.

Doğruluk tercihi: **gemini-3.5-flash-lite**. Katalog tercihi: **gemini-3.5-flash-lite**.

### 5. SID 2025067 / REV 3

Cohort: FRESH_OPERATIONAL — Source: `data\rules\et-open\emerging-chat.rules`

```text
alert tcp any any -> any !6666:7000 (msg:"ET CHAT IRC USER Off-port Likely bot with 0 0 colon checkin"; flow:established,to_server; flowbits:set,is_proto_irc; content:"USER|20|"; nocase; content:" 0 0 |3a|"; within:40; content:"|0a|"; within:40; classtype:misc-activity; sid:2025067; rev:3; metadata:created_at 2013_07_13, confidence Medium, signature_severity Informational, updated_at 2024_03_14;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | IRC bot checkin pattern | Informational Activity |
| detected_entity | null | null |
| entity_type | null | null |
| category | Command and Control | Other |
| subcategory | C2 Communication | Informational Activity |
| mitre_tactic | null | null |
| mitre_technique | null | null |
| mitre_technique_id | null | null |
| cyber_kill_chain_phase | Command and Control | null |
| model_confidence (hakem puanı değil) | 0.7 | 0.5 |

**gemini-3.5-flash-lite — kör etiket A, classification ID 1508**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET CHAT IRC USER Off-port Likely bot with 0 0 colon checkin", "flowbits: set,is_proto_irc", "content: USER\|20\|", "content:  0 0 \|3a\|"]

**qwen3:8b — kör etiket B, classification ID 1526**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["classtype: misc-activity", "msg: ET CHAT IRC USER Off-port Likely bot with 0 0 colon checkin", "flow: established, to_server", "flowbits: set,is_proto_irc", "content: USER\|20\|, 0 0 \|3a\|, \|0a\|"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

Off-port IRC USER ve 0 0 : paterni, msg Likely bot, classtype misc-activity. A olası IRC bot check-in/C2 niyetini koruyor; bu kesin bot fingerprint değildir. B Informational Activity ile güvenli fakat IRC/off-port bilgisini katalogdan siliyor. Bu nedenle A katalog tercihi; B'ye kesin semantik yanlış denmedi. Entity ve MITRE null doğru temkin.

Doğruluk tercihi: **Eşit / kesin üstünlük yok**. Katalog tercihi: **gemini-3.5-flash-lite**.

### 6. SID 2023019 / REV 4

Cohort: FRESH_OPERATIONAL — Source: `data\rules\et-open\emerging-telnet.rules`

```text
alert tcp $EXTERNAL_NET any -> $HOME_NET [23,2323,3323,4323] (msg:"ET TELNET busybox MIRAI hackers - Possible Brute Force Attack"; flow:established,to_server; flowbits:isset,ET.telnet.busybox; content:"MIRAI"; threshold:type limit, count 1, track by_src, seconds 30; reference:url,lists.emergingthreats.net/pipermail/emerging-sigs/2016-August/027524.html; classtype:attempted-admin; sid:2023019; rev:4; metadata:attack_target Server, created_at 2016_08_08, deployment Datacenter, performance_impact Low, confidence Medium, signature_severity Major, updated_at 2024_03_14;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | Brute Force Attack | Brute Force |
| detected_entity | null | null |
| entity_type | null | null |
| category | Credential Access | Credential Access |
| subcategory | Brute Force | Brute Force |
| mitre_tactic | Credential Access | Credential Access |
| mitre_technique | Brute Force | Brute Force |
| mitre_technique_id | T1110 | T1110 |
| cyber_kill_chain_phase | Exploitation | null |
| model_confidence (hakem puanı değil) | 0.85 | 0.55 |

**gemini-3.5-flash-lite — kör etiket A, classification ID 1303**

Kaydedilmiş validator: PASS; MITRE provenance: INFERRED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET TELNET busybox MIRAI hackers - Possible Brute Force Attack", "content: MIRAI", "mitre_candidate:T1110:0.55"]

**qwen3:8b — kör etiket B, classification ID 1315**

Kaydedilmiş validator: PASS; MITRE provenance: INFERRED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["content: MIRAI", "classtype: attempted-admin", "flowbits: isset,ET.telnet.busybox", "flow: to_server", "metadata: confidence Medium", "mitre_candidate:T1110:0.55"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

Busybox flowbit ve MIRAI içeriği, threshold LIMIT count1/30. Bu tekrar eden login sayacı değil, alert sınırlamasıdır. İkisi de source Possible Brute Force yorumunu T1110'a bağlıyor; canonical fakat koşullu. A'nın Attack ve KC Exploitation ifadesi daha kesin okunmamalı; B'nin KC null seçimi savunulabilir. MIRAI string'inden kesin malware entity üretmemeleri makul.

Doğruluk tercihi: **Eşit / kesin üstünlük yok**. Katalog tercihi: **Eşit / kesin üstünlük yok**.

Teknik kaynak: [Suricata threshold semantics](https://docs.suricata.io/en/latest/rules/thresholding.html)

### 7. SID 2020702 / REV 5

Cohort: FRESH_OPERATIONAL — Source: `data\rules\et-open\emerging-dos.rules`

```text
alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET DOS Bittorrent User-Agent inbound - possible DDOS"; flow:established,to_server; threshold: type both, count 1, seconds 60, track by_src; http.user_agent; content:"Bittorrent"; startswith; reference:url,torrentfreak.com/zombie-pirate-bay-tracker-fuels-chinese-ddos-attacks-150124/; classtype:attempted-dos; sid:2020702; rev:5; metadata:created_at 2015_03_18, confidence High, signature_severity Major, updated_at 2024_04_13;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | Bittorrent User-Agent inbound - possible DDOS | Suspicious HTTP Activity |
| detected_entity | null | null |
| entity_type | null | null |
| category | Denial of Service | Network Abuse |
| subcategory | null | Suspicious HTTP Activity |
| mitre_tactic | null | null |
| mitre_technique | null | null |
| mitre_technique_id | null | null |
| cyber_kill_chain_phase | Actions on Objectives | null |
| model_confidence (hakem puanı değil) | 0.8 | 0.8 |

**gemini-3.5-flash-lite — kör etiket B, classification ID 1519**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET DOS Bittorrent User-Agent inbound - possible DDOS", "classtype: attempted-dos", "content: Bittorrent", "app_layer: http.user_agent"]

**qwen3:8b — kör etiket A, classification ID 1532**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET DOS Bittorrent User-Agent inbound - possible DDOS", "classtype: attempted-dos", "content: Bittorrent", "protocol: http", "flow: to_server"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

HTTP User-Agent Bittorrent startswith, threshold both count1/60; trafik hacmi ölçülmüyor. A Suspicious HTTP ile güvenli ama olası DDoS bağlamını kaybediyor. B possible DDOS ifadesini koruyor; DoS/Actions on Objectives sadece source niyeti, kanıtlanmış etki değil. Daha ayrıntılı diye doğruluk zaferi sayılmadı.

Doğruluk tercihi: **Eşit / kesin üstünlük yok**. Katalog tercihi: **gemini-3.5-flash-lite**.

Teknik kaynak: [Suricata threshold semantics](https://docs.suricata.io/en/latest/rules/thresholding.html)

### 8. SID 2013682 / REV 5

Cohort: AUDITED_BENCHMARK — Source: `emerging-web_specific_apps.rules`

```text
alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SPECIFIC_APPS Simplis CMS download_file Parameter Local File Inclusion Attempt"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/index.php?"; nocase; content:"action=do_download"; fast_pattern; nocase; content:"download_file="; nocase; http.uri.raw; url_decode; content:"|2e 2e 2f|"; reference:url,packetstormsecurity.org/files/view/99797/simpliscms-disclose.txt; classtype:web-application-attack; sid:2013682; rev:5; metadata:affected_product Web_Server_Applications, attack_target Server, created_at 2011_09_19, deployment Perimeter, deployment Internal, deployment Datacenter, confidence High, signature_severity Major, tag Local_File_Inclusion, tag Exploit, tag LFI, tag RFI, tag Description_Generated_By_Proofpoint_Nexus, updated_at 2024_04_09, mitre_tactic_id TA0001, mitre_tactic_name Initial_Access, mitre_technique_id T1190, mitre_technique_name Exploit_Public_Facing_Application; target:dest_ip;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | Local File Inclusion Attempt | Web attack attempt: Local File Inclusion |
| detected_entity | Simplis CMS | Simplis CMS |
| entity_type | Product | Product |
| category | Web Attack | Web Attack |
| subcategory | Path Traversal | null |
| mitre_tactic | Initial Access | Initial Access |
| mitre_technique | Exploit Public-Facing Application | Exploit Public-Facing Application |
| mitre_technique_id | T1190 | T1190 |
| cyber_kill_chain_phase | Exploitation | null |
| model_confidence (hakem puanı değil) | 0.95 | 0.99 |

**gemini-3.5-flash-lite — kör etiket A, classification ID 1226**

Kaydedilmiş validator: PASS; MITRE provenance: EXACT_SOURCE_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET WEB_SPECIFIC_APPS Simplis CMS download_file Parameter Local File Inclusion Attempt", "classtype: web-application-attack", "content: action=do_download", "content: download_file=", "content: \|2e 2e 2f\|", "entity_candidate:Simplis CMS:EXPLICIT_RULE_NAME", "mitre_candidate:T1190:0.99"]

**qwen3:8b — kör etiket B, classification ID 1228**

Kaydedilmiş validator: PASS; MITRE provenance: EXACT_SOURCE_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET WEB_SPECIFIC_APPS Simplis CMS download_file Parameter Local File Inclusion Attempt", "content: \|2e 2e 2f\|", "entity_candidates: Simplis CMS (Product, explicit rule name)", "entity_candidate:Simplis CMS:EXPLICIT_RULE_NAME", "mitre_candidate:T1190:0.99"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

Simplis CMS download_file parametresinde URL decode sonrası ../ var. İkisi de product/LFI/source canonical T1190 bakımından uyumlu. A Path Traversal alt kategorisiyle somut mekanizmayı filtrelenebilir kılıyor. B subcategory null ile açık mekanizmayı kaybediyor ama yanlış iddia üretmiyor. KC null otomatik hata sayılmadı.

Doğruluk tercihi: **Eşit / kesin üstünlük yok**. Katalog tercihi: **gemini-3.5-flash-lite**.

### 9. SID 2101280 / REV 10

Cohort: AUDITED_BENCHMARK — Source: `emerging-rpc.rules`

```text
alert udp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap listing UDP 111"; content:"|00 01 86 A0|"; depth:4; offset:12; content:"|00 00 00 04|"; within:4; distance:4; content:"|00 00 00 00|"; depth:4; offset:4; reference:arachnids,428; classtype:rpc-portmap-decode; sid:2101280; rev:10; metadata:created_at 2010_09_23, signature_severity Informational, updated_at 2019_07_26;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | RPC portmap listing | RPC portmap enumeration |
| detected_entity | null | null |
| entity_type | null | null |
| category | Discovery | Other |
| subcategory | null | Informational Activity |
| mitre_tactic | null | null |
| mitre_technique | null | null |
| mitre_technique_id | null | null |
| cyber_kill_chain_phase | null | null |
| model_confidence (hakem puanı değil) | 0.8 | 0.5 |

**gemini-3.5-flash-lite — kör etiket A, classification ID 1204**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: GPL RPC portmap listing UDP 111", "classtype: rpc-portmap-decode", "content: \|00 01 86 A0\|"]

**qwen3:8b — kör etiket B, classification ID 1205**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: GPL RPC portmap listing UDP 111", "classtype: rpc-portmap-decode", "protocol: udp", "content: \|00 01 86 A0\|, \|00 00 00 04\|, \|00 00 00 00\|"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

Portmapper program100000 procedure4 DUMP servis kayıtlarını listeler. A RPC portmap listing/Discovery ile işlevi koruyor; Discovery saldırgan varlığı demek değildir. B enumeration davranışını doğru söylese de Other/Informational kategorisi keşif filtresi için daha az yararlı. MITRE/KC null ikisinde de makul.

Doğruluk tercihi: **Eşit / kesin üstünlük yok**. Katalog tercihi: **gemini-3.5-flash-lite**.

Teknik kaynak: [RFC 1833: Port Mapper GETPORT / DUMP](https://www.rfc-editor.org/rfc/rfc1833.html)

### 10. SID 2011286 / REV 7

Cohort: AUDITED_BENCHMARK — Source: `emerging-web_server.rules`

```text
alert http1 $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Bot Search RFI Scan (Casper-Like MaMa Cyber/ebes)"; flow:established,to_server; http.header; content:"|0d 0a|User-Agent|3a 20|MaMa|20|"; nocase; reference:url,eromang.zataz.com/2010/07/13/byroenet-casper-bot-search-e107-rce-scanner/; classtype:web-application-attack; sid:2011286; rev:7; metadata:created_at 2010_07_30, signature_severity Unknown, updated_at 2024_05_06;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | Web vulnerability or bot scanning activity | Web Attack |
| detected_entity | null | null |
| entity_type | null | null |
| category | Web Attack | Web Attack |
| subcategory | null | Web Shell |
| mitre_tactic | null | Web Attack |
| mitre_technique | null | Web Shell |
| mitre_technique_id | null | null |
| cyber_kill_chain_phase | null | null |
| model_confidence (hakem puanı değil) | 0.8 | 0.8 |

**gemini-3.5-flash-lite — kör etiket B, classification ID 1133**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET WEB_SERVER Bot Search RFI Scan (Casper-Like MaMa Cyber/ebes)", "classtype: web-application-attack", "content: \|0d 0a\|User-Agent\|3a 20\|MaMa\|20\|"]

**qwen3:8b — kör etiket A, classification ID 1132**

Kaydedilmiş validator: REVIEW; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: subcategory, mitre_tactic, mitre_technique.

Evidence: ["content: \|0d 0a\|User-Agent\|3a 20\|MaMa\|20\|", "classtype: web-application-attack", "category_hint: Web Attack", "controlled_subcategories: Web Attack -> Web Shell"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

HTTP MaMa User-Agent ve Casper-like RFI scanner msg; web-shell payload'ı yok. A kanıtsız Web Shell seçiyor ve taxonomy etiketlerini ID'siz ATT&CK tuple'a taşıyor. B scanning davranışını koruyup MITRE null bırakıyor. Casper-like ifadesinden kesin tool entity üretmemek doğru.

Doğruluk tercihi: **gemini-3.5-flash-lite**. Katalog tercihi: **gemini-3.5-flash-lite**.

### 11. SID 2068435 / REV 1

Cohort: FRESH_OPERATIONAL — Source: `data\rules\et-open\emerging-attack_response.rules`

```text
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ATTACK_RESPONSE InstallFix MacOS Payload Inbound"; flow:established,to_client; http.response_body; content:"|23 21 2f|bin|2f|zsh"; depth:15; content:"|3c 3c 27|PAYLOAD|5f|END|27|"; fast_pattern; reference:url,pushsecurity.com/blog/installfix; reference:url,x.com/anyrun_app/status/2036799880392265928; classtype:trojan-activity; sid:2068435; rev:1; metadata:affected_product Mac_OSX, attack_target Client_Endpoint, tls_state TLSDecrypt, created_at 2026_03_25, deployment Perimeter, deployment SSLDecrypt, malware_family installfix, confidence Medium, signature_severity Major, updated_at 2026_03_25, mitre_tactic_id TA0011, mitre_tactic_name Command_And_Control, mitre_technique_id T1105, mitre_technique_name Ingress_Tool_Transfer; target:dest_ip;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | InstallFix MacOS Payload Inbound | Ingress Tool Transfer |
| detected_entity | installfix | installfix |
| entity_type | Malware | Malware |
| category | Command and Control | Malware |
| subcategory | HTTP C2 Communication | Malware Network Activity |
| mitre_tactic | Command And Control | Command And Control |
| mitre_technique | Ingress Tool Transfer | Ingress Tool Transfer |
| mitre_technique_id | T1105 | T1105 |
| cyber_kill_chain_phase | Command and Control | null |
| model_confidence (hakem puanı değil) | 0.9 | 0.9 |

**gemini-3.5-flash-lite — kör etiket B, classification ID 1417**

Kaydedilmiş validator: PASS; MITRE provenance: EXACT_SOURCE_MAPPING; önemli bulgu alanları: subcategory.

Evidence: ["msg: ET ATTACK_RESPONSE InstallFix MacOS Payload Inbound", "metadata: malware_family installfix", "content: \|23 21 2f\|bin\|2f\|zsh", "entity_candidate:Mac OSX:SPECIFIC_AFFECTED_PRODUCT", "entity_candidate:installfix:EXPLICIT_MALWARE_NAME", "mitre_candidate:T1105:0.90"]

**qwen3:8b — kör etiket A, classification ID 1425**

Kaydedilmiş validator: PASS; MITRE provenance: EXACT_SOURCE_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["metadata.malware_family: installfix", "mitre_tactic_id: TA0011", "mitre_technique_id: T1105", "content: \|23 21 2f\|bin\|2f\|zsh", "content: \|3c 3c 27\|PAYLOAD\|5f\|END\|27\|", "entity_candidate:Mac OSX:SPECIFIC_AFFECTED_PRODUCT", "entity_candidate:installfix:EXPLICIT_MALWARE_NAME", "mitre_candidate:T1105:0.90"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

Inbound HTTP response içinde InstallFix zsh payload, malware_family installfix ve source T1105 var. A Malware/Ingress Tool Transfer ile transferi sınıflandırıyor. B behavior daha spesifik ama HTTP C2 Communication ile payload indirmeyi C2 kanalı sayıyor. T1105'in C2 tactic'ine ait olması HTTP C2 protokolünü ispatlamaz. Entity source/payload ilişkisi iki tarafta destekli.

Doğruluk tercihi: **qwen3:8b**. Katalog tercihi: **qwen3:8b**.

### 12. SID 2527005 / REV 1715

Cohort: FRESH_OPERATIONAL — Source: `data\rules\et-open\threatview_CS_c2.rules`

```text
alert ip [89.23.108.208,119.82.97.10,119.82.97.10,45.142.36.64,107.148.1.188,1.15.248.225,101.201.54.74,101.43.32.212,106.54.209.36,111.229.187.212,111.230.12.238,111.92.243.236,113.31.105.33,113.31.106.106,114.55.133.151,117.72.8.192,118.31.116.9,119.28.83.149,119.91.208.190,121.43.55.149,123.58.198.236,124.223.41.181,124.71.106.234,134.122.130.181,134.122.130.186,139.155.148.131,139.159.203.44,139.9.62.19,165.227.108.186,185.196.10.121,185.196.8.18,194.165.16.55,20.56.70.245,43.136.38.59,47.100.87.177,47.105.69.34,47.108.180.121,47.109.69.135,47.92.127.53,62.204.41.11,62.234.27.204,64.7.198.58,77.242.250.36,8.134.11.7,8.210.9.201,8.212.49.116,80.66.75.9,91.238.181.235,162.33.177.167,45.92.158.20] any -> $HOME_NET any (msg:"ET Threatview.io High Confidence Cobalt Strike C2 IP group 6"; reference:url,threatview.io/Downloads/High-Confidence-CobaltStrike-C2%20-Feeds.txt; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2527005; rev:1715; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag Threatview_CS, signature_severity Major, created_at 2021_12_09, updated_at 2026_08_31;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | Cobalt Strike C2 communication | Command and Control |
| detected_entity | Cobalt Strike | Cobalt Strike |
| entity_type | Attack Tool | Attack Tool |
| category | Command and Control | Command and Control |
| subcategory | C2 Communication | C2 Communication |
| mitre_tactic | null | Command and Control |
| mitre_technique | null | C2 Communication |
| mitre_technique_id | null | null |
| cyber_kill_chain_phase | Command and Control | null |
| model_confidence (hakem puanı değil) | 0.9 | 0.9 |

**gemini-3.5-flash-lite — kör etiket B, classification ID 1506**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET Threatview.io High Confidence Cobalt Strike C2 IP group 6", "entity_candidate:Cobalt Strike:EXPLICIT_RULE_NAME"]

**qwen3:8b — kör etiket A, classification ID 1525**

Kaydedilmiş validator: REVIEW; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: mitre_tactic, mitre_technique.

Evidence: ["msg: ET Threatview.io High Confidence Cobalt Strike C2 IP group 6", "entity_hint: Cobalt Strike", "entity_candidates: Cobalt Strike (Attack Tool)", "entity_candidate:Cobalt Strike:EXPLICIT_RULE_NAME"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

Threatview Cobalt Strike C2 IP listesi: entity tool fingerprint değil IOC association olarak kullanılabilir. A Command and Control/C2 Communication değerlerini technique ID null iken MITRE alanlarına yazıyor. B tutarlı null MITRE ve daha somut Cobalt Strike davranışı sunuyor. KC C2 yine source ilişkisi; gerçek endpoint oturumunun kanıtı değil.

Doğruluk tercihi: **gemini-3.5-flash-lite**. Katalog tercihi: **gemini-3.5-flash-lite**.

### 13. SID 2403415 / REV 111389

Cohort: FRESH_OPERATIONAL — Source: `data\rules\et-open\ciarmy.rules`

```text
alert ip [81.86.20.177,82.120.227.43,82.124.21.160,82.124.72.172,82.125.235.123,82.125.79.37,82.142.156.17,82.155.80.47,82.156.162.176,82.165.216.132,82.167.197.116,82.167.222.19,82.167.42.165,82.200.135.250,82.205.99.1,82.209.249.231,82.215.116.142,82.215.118.245,82.224.248.104,82.225.6.166,82.27.201.21,82.36.241.183,82.65.192.79,82.66.103.197,82.67.205.95,82.68.39.86,82.86.65.174,82.96.146.180,83.110.94.182,83.112.223.96,83.136.88.226,83.159.70.191,83.195.197.1,83.198.199.131,83.200.225.79,83.237.72.102,83.239.53.250,83.250.181.240,83.254.128.228,83.39.58.68,83.46.109.35,83.46.89.229,83.71.70.198,83.85.124.144,83.86.91.203,83.99.224.59,84.106.173.204,84.18.231.87,84.197.124.193,84.220.17.128] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 116"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403415; rev:111389; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_08_31;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | Traffic from known malicious infrastructure | Traffic from known malicious infrastructure |
| detected_entity | null | null |
| entity_type | null | null |
| category | Network Abuse | Network Abuse |
| subcategory | Suspicious IP Activity | Suspicious IP Activity |
| mitre_tactic | null | null |
| mitre_technique | null | null |
| mitre_technique_id | null | null |
| cyber_kill_chain_phase | null | null |
| model_confidence (hakem puanı değil) | 0.85 | 0.875 |

**gemini-3.5-flash-lite — kör etiket B, classification ID 1334**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET CINS Active Threat Intelligence Poor Reputation IP group 116", "tag CINS"]

**qwen3:8b — kör etiket A, classification ID 1339**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["similar_rules"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

CINS poor-reputation IP listesi. Final alanlar iki modelde aynı: suspicious IP, entity/MITRE/KC null; anlamlı üstünlük yok. Known malicious ifadesi reported poor reputation'dan daha kesin okunmamalı. A evidence yalnız similar_rules, B msg/tag içeriyor; B daha denetlenebilir ama final doğruluk farkı değil.

Doğruluk tercihi: **Eşit / kesin üstünlük yok**. Katalog tercihi: **Eşit / kesin üstünlük yok**.

### 14. SID 2050707 / REV 2

Cohort: AUDITED_BENCHMARK — Source: `emerging-remote_access.rules`

```text
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET REMOTE_ACCESS AnyDesk Revoked Code Signing Certificate Observed"; flow:established,to_client; content:"|30 82|"; content:"|0D BF 15 2D EA F0 B9 81 A8 A9 38 D5 3F 76 9D B8|"; distance:9; within:16; fast_pattern; content:"|1e 17 0d|211213000000Z|17 0d|250108235959Z0"; distance:123; within:32; content:"philandro Software GmbH"; distance:75; within:23; reference:url,anydesk.com/en/public-statement; classtype:misc-activity; sid:2050707; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, affected_product Windows_11, attack_target Client_Endpoint, created_at 2024_02_05, deployment Perimeter, deployment SSLDecrypt, former_category INFO, performance_impact Low, confidence High, signature_severity Informational, updated_at 2024_06_10; target:dest_ip;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | Observation of a revoked AnyDesk code signing certificate | Observation of a revoked AnyDesk code-signing certificate |
| detected_entity | AnyDesk | AnyDesk |
| entity_type | Remote Access Tool | Remote Access Tool |
| category | Remote Access | Remote Access |
| subcategory | Remote Access Software | Remote Access Software |
| mitre_tactic | Command And Control | Command And Control |
| mitre_technique | Remote Access Tools | Remote Access Tools |
| mitre_technique_id | T1219 | T1219 |
| cyber_kill_chain_phase | Command and Control | Command and Control |
| model_confidence (hakem puanı değil) | 0.8 | 0.9 |

**gemini-3.5-flash-lite — kör etiket A, classification ID 1079**

Kaydedilmiş validator: PASS; MITRE provenance: INFERRED_MAPPING; önemli bulgu alanları: mitre_tactic, mitre_technique, mitre_technique_id, cyber_kill_chain_phase.

Evidence: ["msg: ET REMOTE_ACCESS AnyDesk Revoked Code Signing Certificate Observed", "content: philandro Software GmbH", "entity_candidate:AnyDesk:EXPLICIT_RULE_NAME", "entity_candidate:Windows 11:SPECIFIC_AFFECTED_PRODUCT", "mitre_candidate:T1219:0.55"]

**qwen3:8b — kör etiket B, classification ID 1078**

Kaydedilmiş validator: PASS; MITRE provenance: INFERRED_MAPPING; önemli bulgu alanları: mitre_tactic, mitre_technique, mitre_technique_id, cyber_kill_chain_phase.

Evidence: ["msg: ET REMOTE_ACCESS AnyDesk Revoked Code Signing Certificate Observed", "content: philandro Software GmbH", "entity_hint: AnyDesk", "mitre_candidates: T1219", "entity_candidate:AnyDesk:EXPLICIT_RULE_NAME", "entity_candidate:Windows 11:SPECIFIC_AFFECTED_PRODUCT", "mitre_candidate:T1219:0.55"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

AnyDesk revoked signing certificate serial/time ve philandro Software imzası gözleniyor, remote-control komutu veya source ATT&CK yok. İkisi de certificate behavior/AnyDesk association'ı doğru tanıyor; fakat bundan inferred T1219 kullanımını ve C2 aşamasını çıkarıyor. Canonical ID olması semantik bağı doğrulamaz. Eşitlik burada ikisinin de aynı hatayı taşımasıdır.

Doğruluk tercihi: **Eşit / kesin üstünlük yok**. Katalog tercihi: **Eşit / kesin üstünlük yok**.

### 15. SID 2009985 / REV 2

Cohort: AUDITED_BENCHMARK — Source: `emerging-ftp.rules`

```text
alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET FTP Possible FTP Daemon Username UNION SELECT SQL Injection Attempt"; flow:established,to_server; content:"USER"; depth:4; content:"UNION"; within:200; nocase; content:"SELECT"; distance:0; nocase; pcre:"/UNION.+SELECT/i"; reference:url,en.wikipedia.org/wiki/SQL_injection; classtype:attempted-user; sid:2009985; rev:2; metadata:affected_product Web_Server_Applications, attack_target Web_Server, created_at 2010_07_30, deployment Datacenter, confidence Medium, signature_severity Major, tag SQL_Injection, updated_at 2019_07_26, mitre_tactic_id TA0001, mitre_tactic_name Initial_Access, mitre_technique_id T1190, mitre_technique_name Exploit_Public_Facing_Application;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | SQL Injection Attempt | SQL Injection |
| detected_entity | null | null |
| entity_type | null | null |
| category | Web Attack | Web Attack |
| subcategory | SQL Injection | SQL Injection |
| mitre_tactic | Initial Access | Initial Access |
| mitre_technique | Exploit Public-Facing Application | Exploit Public-Facing Application |
| mitre_technique_id | T1190 | T1190 |
| cyber_kill_chain_phase | Exploitation | Exploitation |
| model_confidence (hakem puanı değil) | 0.95 | 0.7 |

**gemini-3.5-flash-lite — kör etiket B, classification ID 1202**

Kaydedilmiş validator: PASS; MITRE provenance: EXACT_SOURCE_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET FTP Possible FTP Daemon Username UNION SELECT SQL Injection Attempt", "content: USER, UNION, SELECT", "pcre: /UNION.+SELECT/i", "mitre_candidate:T1190:0.99"]

**qwen3:8b — kör etiket A, classification ID 1203**

Kaydedilmiş validator: PASS; MITRE provenance: EXACT_SOURCE_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["content: USER, UNION, SELECT", "pcre: /UNION.+SELECT/i", "metadata: tag SQL_Injection", "mitre_tactic_id: TA0001", "mitre_technique_id: T1190", "mitre_candidate:T1190:0.99"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

FTP USER içinde UNION SELECT PCRE, source T1190. İkisinde SQL Injection/Web Attack/canonical MITRE/Exploitation uygun. B SQL Injection Attempt diyerek girişim niteliğini daha açık koruyor. A SQL Injection yanlış sayılmadı; bu yalnız anlatım tercihi.

Doğruluk tercihi: **Eşit / kesin üstünlük yok**. Katalog tercihi: **gemini-3.5-flash-lite**.

### 16. SID 2060513 / REV 2

Cohort: AUDITED_BENCHMARK — Source: `emerging-remote_access.rules`

```text
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"ET REMOTE_ACCESS Observed Anydesk Domain (boot .net .anydesk .com) in TLS SNI"; flow:established,to_server; tls.sni; bsize:20; content:"boot.net.anydesk.com"; fast_pattern; classtype:misc-activity; sid:2060513; rev:2; metadata:affected_product Any, attack_target Client_and_Server, created_at 2025_03_03, deployment Perimeter, former_category INFO, performance_impact Low, confidence High, signature_severity Informational, tag AnyDesk, updated_at 2025_03_05, mitre_tactic_id TA0011, mitre_tactic_name Command_And_Control, mitre_technique_id T1219, mitre_technique_name Remote_Access_Software;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | AnyDesk remote access software communication observed in TLS SNI | Observed Anydesk Domain in TLS SNI |
| detected_entity | AnyDesk | AnyDesk |
| entity_type | Remote Access Tool | Remote Access Tool |
| category | Remote Access | Remote Access |
| subcategory | Remote Access Software | Remote Access Software |
| mitre_tactic | Command And Control | Command And Control |
| mitre_technique | Remote Access Tools | Remote Access Tools |
| mitre_technique_id | T1219 | T1219 |
| cyber_kill_chain_phase | Command and Control | null |
| model_confidence (hakem puanı değil) | 1.0 | 0.99 |

**gemini-3.5-flash-lite — kör etiket A, classification ID 1049**

Kaydedilmiş validator: PASS; MITRE provenance: EXACT_SOURCE_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET REMOTE_ACCESS Observed Anydesk Domain (boot .net .anydesk .com) in TLS SNI", "content: boot.net.anydesk.com", "metadata: mitre_technique_id T1219", "entity_hint: AnyDesk", "entity_candidate:AnyDesk:EXPLICIT_RULE_NAME", "mitre_candidate:T1219:0.99"]

**qwen3:8b — kör etiket B, classification ID 1048**

Kaydedilmiş validator: PASS; MITRE provenance: EXACT_SOURCE_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg", "content", "entity_hint", "mitre_candidates", "entity_candidate:AnyDesk:EXPLICIT_RULE_NAME", "mitre_candidate:T1219:0.99"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

AnyDesk boot.net.anydesk.com TLS SNI ve source T1219. İki model de doğru product/tool association ve canonical source mapping veriyor. A KC C2 ekliyor, B null bırakıyor. Servis kullanımı kötüye kullanım ispatı olmadığından bu doluluk farkına doğruluk ödülü/cezası verilmedi.

Doğruluk tercihi: **Eşit / kesin üstünlük yok**. Katalog tercihi: **Eşit / kesin üstünlük yok**.

### 17. SID 2038015 / REV 2

Cohort: FRESH_OPERATIONAL — Source: `data\rules\et-open\emerging-hunting.rules`

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET HUNTING HTTP GET Request XOR Key 33"; flow:established,to_server; content:"|74 76 67 13 1c|"; startswith; fast_pattern; content:"|13 7b 67 67 63 1c|"; distance:0; classtype:misc-activity; sid:2038015; rev:2; metadata:attack_target Client_and_Server, created_at 2022_08_09, deployment Perimeter, performance_impact Low, confidence Medium, signature_severity Informational, tag Description_Generated_By_Proofpoint_Nexus, updated_at 2022_08_10, mitre_tactic_id TA0005, mitre_tactic_name Defense_Evasion, mitre_technique_id T1027, mitre_technique_name Obfuscated_Files_or_Information;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | XOR obfuscation in HTTP traffic | Obfuscated Files or Information |
| detected_entity | null | null |
| entity_type | null | null |
| category | Other | Other |
| subcategory | Informational Activity | Informational Activity |
| mitre_tactic | Stealth | Stealth |
| mitre_technique | Obfuscated Files or Information | Obfuscated Files or Information |
| mitre_technique_id | T1027 | T1027 |
| cyber_kill_chain_phase | null | null |
| model_confidence (hakem puanı değil) | 0.8 | 0.5 |

**gemini-3.5-flash-lite — kör etiket A, classification ID 1356**

Kaydedilmiş validator: PASS; MITRE provenance: EXACT_SOURCE_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET HUNTING HTTP GET Request XOR Key 33", "metadata: mitre_technique_id T1027", "content: \|74 76 67 13 1c\|", "mitre_candidate:T1027:0.90"]

**qwen3:8b — kör etiket B, classification ID 1361**

Kaydedilmiş validator: PASS; MITRE provenance: EXACT_SOURCE_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET HUNTING HTTP GET Request XOR Key 33", "classtype: misc-activity", "metadata: mitre_tactic_id TA0005, mitre_technique_id T1027", "content: \|74 76 67 13 1c\|, \|13 7b 67 67 63 1c\|", "mitre_candidate:T1027:0.90"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

XOR0x33 ile maskelenmiş GET/HTTP paterni ve source T1027. Local MITRE snapshot'ında tactic Stealth olduğundan bunu eski tactic adına göre yanlış saymadım. A XOR/HTTP gözlemini koruyor, B sadece Obfuscated Files or Information teknik adını tekrarlıyor. İkisi canonical doğru; A daha faydalı açıklama.

Doğruluk tercihi: **Eşit / kesin üstünlük yok**. Katalog tercihi: **gemini-3.5-flash-lite**.

### 18. SID 2005279 / REV 9

Cohort: AUDITED_BENCHMARK — Source: `emerging-web_specific_apps.rules`

```text
alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SPECIFIC_APPS Easebay Resources Login Manager SQL Injection Attempt -- memberlist.php init_row UPDATE"; flow:established,to_server; http.uri; content:"/admin/memberlist.php?"; nocase; content:"init_row="; nocase; content:"UPDATE"; nocase; content:"SET"; nocase; distance:0; reference:cve,CVE-2007-0401; reference:url,www.securityfocus.com/archive/1/archive/1/457505/100/0/threaded; classtype:web-application-attack; sid:2005279; rev:9; metadata:affected_product Web_Server_Applications, attack_target Web_Server, created_at 2010_07_30, deployment Datacenter, confidence Medium, signature_severity Major, tag SQL_Injection, updated_at 2020_09_11, mitre_tactic_id TA0001, mitre_tactic_name Initial_Access, mitre_technique_id T1190, mitre_technique_name Exploit_Public_Facing_Application;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | SQL Injection Attempt | Web Attack |
| detected_entity | Easebay Resources Login Manager | Easebay Resources Login Manager |
| entity_type | Product | Product |
| category | Web Attack | Web Attack |
| subcategory | SQL Injection | SQL Injection |
| mitre_tactic | Initial Access | Initial Access |
| mitre_technique | Exploit Public-Facing Application | Exploit Public-Facing Application |
| mitre_technique_id | T1190 | T1190 |
| cyber_kill_chain_phase | Exploitation | Exploitation |
| model_confidence (hakem puanı değil) | 0.95 | 0.9 |

**gemini-3.5-flash-lite — kör etiket A, classification ID 1223**

Kaydedilmiş validator: PASS; MITRE provenance: EXACT_SOURCE_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["ET WEB_SPECIFIC_APPS Easebay Resources Login Manager SQL Injection Attempt -- memberlist.php init_row UPDATE", "classtype: web-application-attack", "content: /admin/memberlist.php?", "content: init_row=", "content: UPDATE", "content: SET", "tag SQL_Injection", "entity_candidate:Easebay Resources Login Manager:EXPLICIT_RULE_NAME", "mitre_candidate:T1190:0.99"]

**qwen3:8b — kör etiket B, classification ID 1225**

Kaydedilmiş validator: PASS; MITRE provenance: EXACT_SOURCE_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET WEB_SPECIFIC_APPS Easebay Resources Login Manager SQL Injection Attempt -- memberlist.php init_row UPDATE", "content: /admin/memberlist.php?, init_row=, UPDATE, SET", "metadata: tag SQL_Injection", "mitre_technique_name: Exploit Public-Facing Application", "mitre_tactic_name: Initial Access", "entity_candidate:Easebay Resources Login Manager:EXPLICIT_RULE_NAME", "mitre_candidate:T1190:0.99"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

Easebay Login Manager init_row UPDATE/SET SQL paterni, CVE-2007-0401/source T1190. Product, SQL Injection alt kategorisi ve canonical MITRE iki tarafta uyumlu. A SQL Injection Attempt, B generic Web Attack behavior veriyor. A katalogda daha açıklayıcı; B'nin diğer alanlarında mekanizma zaten var.

Doğruluk tercihi: **Eşit / kesin üstünlük yok**. Katalog tercihi: **gemini-3.5-flash-lite**.

### 19. SID 2003657 / REV 21

Cohort: FRESH_OPERATIONAL — Source: `data\rules\et-open\emerging-user_agents.rules`

```text
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Suspicious User-Agent (MSIE)"; flow:established,to_server; threshold: type limit, count 2, track by_src, seconds 300; http.user_agent; content:"MSIE"; startswith; http.host; content:!"www.msftncsi.com"; classtype:trojan-activity; sid:2003657; rev:21; metadata:affected_product Any, attack_target Client_Endpoint, created_at 2010_07_30, deployment Perimeter, confidence High, signature_severity Major, tag User_Agent, updated_at 2024_04_13;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | Suspicious User-Agent usage matching MSIE | Suspicious User-Agent Activity |
| detected_entity | Internet Explorer | Internet Explorer |
| entity_type | Product | Product |
| category | Other | Web Attack |
| subcategory | Informational Activity | null |
| mitre_tactic | null | null |
| mitre_technique | null | null |
| mitre_technique_id | null | null |
| cyber_kill_chain_phase | null | null |
| model_confidence (hakem puanı değil) | 0.8 | 0.9 |

**gemini-3.5-flash-lite — kör etiket B, classification ID 1402**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: detected_entity, entity_type.

Evidence: ["msg: ET USER_AGENTS Suspicious User-Agent (MSIE)", "content: MSIng MSIE", "app_layer: http.user_agent", "entity_candidate:Internet Explorer:EXPLICIT_RULE_NAME"]

**qwen3:8b — kör etiket A, classification ID 1408**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: detected_entity, entity_type, category.

Evidence: ["msg: ET USER_AGENTS Suspicious User-Agent (MSIE)", "content: MSIE", "entity_candidates: Internet Explorer (EXPLICIT_RULE_NAME)", "entity_candidate:Internet Explorer:EXPLICIT_RULE_NAME"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

UA sadece MSIE ile başlıyor, affected_product Any. İkisi de spoof edilebilir marker'ı Internet Explorer Product fingerprint gibi yorumluyor. A ayrıca kanıt olmayan Web Attack seçiyor; B informational category ve UA behavior ile daha temkinli. B evidence'taki MSIng MSIE ham content'in birebir karşılığı değil. Tercih B, fakat ortak entity hatası sürüyor.

Doğruluk tercihi: **gemini-3.5-flash-lite**. Katalog tercihi: **gemini-3.5-flash-lite**.

### 20. SID 2010494 / REV 5

Cohort: AUDITED_BENCHMARK — Source: `emerging-scan.rules`

```text
alert tcp $HOME_NET 3306 -> $EXTERNAL_NET any (msg:"ET SCAN Multiple MySQL Login Failures Possible Brute Force Attempt"; flow:established,to_client; dsize:<251; byte_test:1,<,0xfb,0,little; content:"|ff 15 04 23 32 38 30 30 30|"; offset:4; threshold: type threshold, track by_src, count 5, seconds 120; classtype:attempted-recon; sid:2010494; rev:5; metadata:created_at 2010_07_30, confidence Medium, signature_severity Informational, updated_at 2024_03_06;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | Multiple MySQL login failures indicating possible brute force attempt | Multiple MySQL Login Failures Possible Brute Force Attempt |
| detected_entity | null | null |
| entity_type | null | null |
| category | Reconnaissance | Credential Access |
| subcategory | null | Brute Force |
| mitre_tactic | null | Credential Access |
| mitre_technique | null | Brute Force |
| mitre_technique_id | null | T1110 |
| cyber_kill_chain_phase | Reconnaissance | null |
| model_confidence (hakem puanı değil) | 0.8 | 0.55 |

**gemini-3.5-flash-lite — kör etiket B, classification ID 1151**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: category, cyber_kill_chain_phase.

Evidence: ["msg: ET SCAN Multiple MySQL Login Failures Possible Brute Force Attempt", "classtype: attempted-recon", "mitre_candidate:T1110:0.55"]

**qwen3:8b — kör etiket A, classification ID 1150**

Kaydedilmiş validator: PASS; MITRE provenance: INFERRED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["content: \|ff 15 04 23 32 38 30 30 30\|", "classtype: attempted-recon", "category_hint: Reconnaissance", "mitre_candidates: [T1110]", "mitre_candidate:T1110:0.55"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

MySQL hata response'u, 120 saniyede 5 login failure eşleşmesi. A Possible Brute Force/Credential Access ve canonical T1110 ile davranışı doğru koruyor. B behavior brute force derken category ve KC Reconnaissance diyor: eski ET SCAN ailesi gerçek auth-failure davranışına baskın geliyor. B MITRE null olduğu için değil, kategori/aşama çelişkisi nedeniyle geride.

Doğruluk tercihi: **qwen3:8b**. Katalog tercihi: **qwen3:8b**.

### 21. SID 2019089 / REV 6

Cohort: AUDITED_BENCHMARK — Source: `emerging-exploit.rules`

```text
alert tcp any 873 -> any any (msg:"ET EXPLOIT F5 BIG-IP rsync cmi authorized_keys successful exfiltration"; flow:established,to_client; flowbits:isset,ET.F5.key; content:"ssh-rsa"; fast_pattern; reference:url,www.security-assessment.com/files/documents/advisory/F5_Unauthenticated_rsync_access_to_Remote_Root_Code_Execution.pdf; classtype:attempted-admin; sid:2019089; rev:6; metadata:created_at 2014_08_29, signature_severity Critical, updated_at 2024_03_14;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | Exploitation of F5 BIG-IP | Exploit Attempt |
| detected_entity | null | null |
| entity_type | null | null |
| category | Exploitation | Exploitation |
| subcategory | Exploit Attempt | Exploit Attempt |
| mitre_tactic | Initial Access | Initial Access |
| mitre_technique | Exploit Public-Facing Application | Exploit Public-Facing Application |
| mitre_technique_id | T1190 | T1190 |
| cyber_kill_chain_phase | Exploitation | null |
| model_confidence (hakem puanı değil) | 0.8 | 0.55 |

**gemini-3.5-flash-lite — kör etiket A, classification ID 1155**

Kaydedilmiş validator: PASS; MITRE provenance: INFERRED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET EXPLOIT F5 BIG-IP rsync cmi authorized_keys successful exfiltration", "classtype: attempted-admin", "content: ssh-rsa", "mitre_candidate:T1190:0.55"]

**qwen3:8b — kör etiket B, classification ID 1154**

Kaydedilmiş validator: PASS; MITRE provenance: INFERRED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET EXPLOIT F5 BIG-IP rsync cmi authorized_keys successful exfiltration", "classtype: attempted-admin", "content: ssh-rsa", "flowbits: isset,ET.F5.key", "category_hint: Exploitation", "mitre_candidates: [T1190]", "mitre_candidate:T1190:0.55"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

Rsync src873 response, ET.F5.key flowbit ve ssh-rsa; msg authorized_keys successful exfiltration. A F5 BIG-IP bağlamını behavior'da tutuyor, B sadece Exploit Attempt diyor. İkisi de key-transfer/response aşamasını ve structured ürün association'ı kaybediyor. T1190 public-facing initial access yalnız bu cevaptan tam doğrulanamıyor. Null entity kesin yanlış değil, katalog eksiği.

Doğruluk tercihi: **Eşit / kesin üstünlük yok**. Katalog tercihi: **gemini-3.5-flash-lite**.

### 22. SID 2021371 / REV 7

Cohort: AUDITED_BENCHMARK — Source: `emerging-info.rules`

```text
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Possible External IP Lookup www.whatsmyip.us"; flow:established,to_server; http.host; bsize:16; content:"www.whatsmyip.us"; fast_pattern; classtype:external-ip-check; sid:2021371; rev:7; metadata:attack_target Client_Endpoint, created_at 2015_06_30, deployment Perimeter, performance_impact Low, confidence High, signature_severity Informational, updated_at 2024_11_26, mitre_tactic_id TA0007, mitre_tactic_name Discovery, mitre_technique_id T1614, mitre_technique_name System_Location_Discovery;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | External IP lookup | Informational network activity |
| detected_entity | null | null |
| entity_type | null | null |
| category | Other | Other |
| subcategory | Informational Activity | Informational Activity |
| mitre_tactic | null | null |
| mitre_technique | null | null |
| mitre_technique_id | null | null |
| cyber_kill_chain_phase | null | null |
| model_confidence (hakem puanı değil) | 0.8 | 0.9 |

**gemini-3.5-flash-lite — kör etiket B, classification ID 1071**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET INFO Possible External IP Lookup www.whatsmyip.us", "classtype: external-ip-check", "content: www.whatsmyip.us", "mitre_candidate:T1614:0.90"]

**qwen3:8b — kör etiket A, classification ID 1070**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET INFO Possible External IP Lookup www.whatsmyip.us", "classtype: external-ip-check", "content: www.whatsmyip.us", "mitre_tactic_id: TA0007", "mitre_tactic_name: Discovery", "mitre_technique_id: T1614", "mitre_technique_name: System Location Discovery", "mitre_candidate:T1614:0.90"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

www.whatsmyip.us HTTP isteği/source T1614. A Informational network activity ile güvenli ama işlevi kaybediyor; B External IP lookup diyor. İki modelin null final MITRE/KC seçimi savunulabilir: servis kullanımı tek başına adversarial discovery değil. B açıklama üstünlüğü, accuracy farkı değil.

Doğruluk tercihi: **Eşit / kesin üstünlük yok**. Katalog tercihi: **gemini-3.5-flash-lite**.

### 23. SID 2047740 / REV 1

Cohort: FRESH_OPERATIONAL — Source: `data\rules\et-open\emerging-info.rules`

```text
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Webhook/HTTP Request Inspection Service Domain (intercept .rest in TLS SNI)"; flow:established,to_server; tls.sni; content:".to.intercept.rest"; endswith; fast_pattern; reference:url,intercept.rest; classtype:misc-activity; sid:2047740; rev:1; metadata:created_at 2023_08_25, deployment Perimeter, performance_impact Low, confidence High, signature_severity Informational, updated_at 2023_08_25, reviewed_at 2023_08_26, mitre_tactic_id TA0010, mitre_tactic_name Exfiltration, mitre_technique_id T1567, mitre_technique_name Exfiltration_Over_Web_Service;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | Webhook or HTTP inspection service domain usage | Informational network activity |
| detected_entity | null | null |
| entity_type | null | null |
| category | Other | Other |
| subcategory | Informational Activity | Informational Activity |
| mitre_tactic | Exfiltration | null |
| mitre_technique | Exfiltration Over Web Service | null |
| mitre_technique_id | T1567 | null |
| cyber_kill_chain_phase | null | null |
| model_confidence (hakem puanı değil) | 0.85 | 0.9 |

**gemini-3.5-flash-lite — kör etiket B, classification ID 1271**

Kaydedilmiş validator: PASS; MITRE provenance: EXACT_SOURCE_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET INFO Webhook/HTTP Request Inspection Service Domain (intercept .rest in TLS SNI)", "classtype: misc-activity", "content: .to.intercept.rest", "metadata: mitre_tactic_name Exfiltration", "metadata: mitre_technique_name Exfiltration_Over_Web_Service", "mitre_candidate:T1567:0.90"]

**qwen3:8b — kör etiket A, classification ID 1275**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET INFO Webhook/HTTP Request Inspection Service Domain (intercept .rest in TLS SNI)", "classtype: misc-activity", "metadata: mitre_tactic_id TA0010, mitre_tactic_name Exfiltration, mitre_technique_id T1567, mitre_technique_name Exfiltration_Over_Web_Service", "content: .to.intercept.rest", "app_layer: tls.sni", "mitre_candidate:T1567:0.90"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

TLS SNI .to.intercept.rest webhook inspection servisi, source T1567. A generic informational ve null MITRE ile temkinli. B servis işlevini açık anlatıyor ve canonical EXACT_SOURCE_MAPPING koruyor. T1567 source association olarak savunulabilir, gözlenmiş veri sızıntısı değildir. Daha fazla MITRE alanı dolu diye semantik zafer verilmedi.

Doğruluk tercihi: **Eşit / kesin üstünlük yok**. Katalog tercihi: **gemini-3.5-flash-lite**.

### 24. SID 2060760 / REV 1

Cohort: FRESH_OPERATIONAL — Source: `data\rules\et-open\emerging-phishing.rules`

```text
alert dns $HOME_NET any -> any any (msg:"ET PHISHING TA453 Domain in DNS Lookup"; dns.query; dotprefix; content:".join-room.site"; nocase; endswith; reference:url,x.com/NarimanGharib/status/1898343272772174032; classtype:credential-theft; sid:2060760; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, created_at 2025_03_10, deployment Perimeter, performance_impact Low, confidence High, signature_severity Major, tag TA453, tag Description_Generated_By_Proofpoint_Nexus, updated_at 2025_03_10, mitre_tactic_id TA0001, mitre_tactic_name Initial_Access, mitre_technique_id T1566, mitre_technique_name Phishing;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | Phishing domain lookup | Phishing Infrastructure |
| detected_entity | null | null |
| entity_type | null | null |
| category | Credential Access | Suspicious DNS |
| subcategory | Credential Activity | Unusual DNS Query |
| mitre_tactic | Initial Access | Initial Access |
| mitre_technique | Phishing | Phishing |
| mitre_technique_id | T1566 | T1566 |
| cyber_kill_chain_phase | Delivery | null |
| model_confidence (hakem puanı değil) | 0.85 | 0.9 |

**gemini-3.5-flash-lite — kör etiket A, classification ID 1281**

Kaydedilmiş validator: PASS; MITRE provenance: EXACT_SOURCE_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET PHISHING TA453 Domain in DNS Lookup", "classtype: credential-theft", "content: .join-room.site", "metadata: mitre_tactic_id TA0001", "metadata: mitre_technique_id T1566", "mitre_candidate:T1566:0.90"]

**qwen3:8b — kör etiket B, classification ID 1289**

Kaydedilmiş validator: PASS; MITRE provenance: EXACT_SOURCE_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET PHISHING TA453 Domain in DNS Lookup", "classtype: credential-theft", "content: .join-room.site", "mitre_tactic_id: TA0001", "mitre_technique_id: T1566", "mitre_technique_name: Phishing", "mitre_candidates: T1566", "mitre_candidate:T1566:0.90"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

TA453 ilişkili .join-room.site DNS lookup/source T1566/credential-theft. A credential category ve Delivery ile source niyetini izliyor ama gözlenen şey credential submit değil. B phishing infrastructure/DNS bağlamını daha iyi koruyor; Unusual DNS Query yine fazla genel. İkisinin canonical source T1566'sı ilişkidir, gerçek mail delivery kanıtı değil. Actor'ü malware entity yapmamaları uygun.

Doğruluk tercihi: **Eşit / kesin üstünlük yok**. Katalog tercihi: **qwen3:8b**.

### 25. SID 2527010 / REV 1715

Cohort: FRESH_OPERATIONAL — Source: `data\rules\et-open\threatview_CS_c2.rules`

```text
alert ip [89.185.84.22,139.60.161.236,89.185.84.28,185.143.223.75,193.233.203.214,185.143.223.76,5.44.42.42,5.44.42.44,5.44.42.48,13.58.89.86,81.19.140.23,45.147.230.252,185.143.223.69,79.133.56.243,5.181.86.248,142.44.211.35,84.32.128.99,84.32.128.5,185.143.223.71,190.123.44.221,43.154.27.211,179.60.146.53,84.32.128.89,13.40.120.240,77.73.133.80,5.44.42.17,194.165.16.83,139.60.161.164,5.44.42.14,5.44.42.45,5.44.42.49,160.20.147.57,179.43.162.24,64.44.135.106,23.29.115.190,64.44.102.127,149.255.35.160,68.233.238.123,104.156.59.221,23.227.198.227,23.227.198.239,3.138.96.16,179.60.146.16,23.81.246.200,23.19.227.177,64.44.98.231,23.81.246.209,45.153.242.82,23.83.133.97,77.73.134.10] any -> $HOME_NET any (msg:"ET Threatview.io High Confidence Cobalt Strike C2 IP group 11"; reference:url,threatview.io/Downloads/High-Confidence-CobaltStrike-C2%20-Feeds.txt; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2527010; rev:1715; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag Threatview_CS, signature_severity Major, created_at 2021_12_09, updated_at 2026_08_31;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | Command and Control communication associated with Cobalt Strike | Command and Control |
| detected_entity | Cobalt Strike | Cobalt Strike |
| entity_type | Attack Tool | Attack Tool |
| category | Command and Control | Command and Control |
| subcategory | C2 Communication | C2 Communication |
| mitre_tactic | null | Command and Control |
| mitre_technique | null | C2 Communication |
| mitre_technique_id | null | null |
| cyber_kill_chain_phase | Command and Control | null |
| model_confidence (hakem puanı değil) | 0.9 | 0.9 |

**gemini-3.5-flash-lite — kör etiket B, classification ID 1420**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET Threatview.io High Confidence Cobalt Strike C2 IP group 11", "metadata: tag Threatview_CS", "entity_candidate:Cobalt Strike:EXPLICIT_RULE_NAME"]

**qwen3:8b — kör etiket A, classification ID 1430**

Kaydedilmiş validator: REVIEW; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: mitre_tactic, mitre_technique.

Evidence: ["msg: ET Threatview.io High Confidence Cobalt Strike C2 IP group 11", "entity_hint: Cobalt Strike", "entity_candidates: Cobalt Strike (Attack Tool)", "entity_candidate:Cobalt Strike:EXPLICIT_RULE_NAME"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

Diğer Threatview Cobalt Strike C2 IP grubu. A taxonomy C2 Communication etiketini technique ID olmadan ATT&CK alanına koyuyor. B associated with Cobalt Strike davranışını daha doğru sınırlandırıyor ve MITRE tuple null. Entity/KC yine source IOC ilişkisidir, payload fingerprint değildir.

Doğruluk tercihi: **gemini-3.5-flash-lite**. Katalog tercihi: **gemini-3.5-flash-lite**.

### 26. SID 2056218 / REV 1

Cohort: AUDITED_BENCHMARK — Source: `emerging-malware.rules`

```text
alert dns $HOME_NET any -> any any (msg:"ET MALWARE Observed DNS Query to SloppyLemming/UNK_SloppyDisc Domain (sensors .opensecurity-legacy .com)"; dns.query; dotprefix; content:".sensors.opensecurity-legacy.com"; nocase; endswith; reference:url,www.cloudflare.com/threat-intelligence/research/report/unraveling-sloppylemmings-operations-across-south-asia/; classtype:trojan-activity; sid:2056218; rev:1; metadata:attack_target Client_Endpoint, created_at 2024_09_27, deployment Perimeter, malware_family SloppyLemming, malware_family UNK_SloppyDisc, confidence High, signature_severity Major, tag Description_Generated_By_Proofpoint_Nexus, updated_at 2024_09_27;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | Observed DNS query to malware-associated domain | DNS query to SloppyLemming/UNK_SloppyDisc domain |
| detected_entity | SloppyLemming | SloppyLemming |
| entity_type | Malware | Malware |
| category | Malware | Malware |
| subcategory | Malware Network Activity | Malware Network Activity |
| mitre_tactic | null | null |
| mitre_technique | null | null |
| mitre_technique_id | null | null |
| cyber_kill_chain_phase | null | null |
| model_confidence (hakem puanı değil) | 0.9 | 0.9 |

**gemini-3.5-flash-lite — kör etiket A, classification ID 1210**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: entity_type.

Evidence: ["msg: ET MALWARE Observed DNS Query to SloppyLemming/UNK_SloppyDisc Domain (sensors .opensecurity-legacy .com)", "classtype: trojan-activity", "metadata: malware_family SloppyLemming", "content: .sensors.opensecurity-legacy.com", "entity_candidate:SloppyLemming:EXPLICIT_RULE_NAME", "entity_candidate:UNK SloppyDisc:EXPLICIT_MALWARE_NAME"]

**qwen3:8b — kör etiket B, classification ID 1211**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: entity_type.

Evidence: ["msg: ET MALWARE Observed DNS Query to SloppyLemming/UNK_SloppyDisc Domain (sensors .opensecurity-legacy .com)", "metadata.malware_family: SloppyLemming", "metadata.malware_family: UNK_SloppyDisc", "content: .sensors.opensecurity-legacy.com", "entity_candidate:SloppyLemming:EXPLICIT_RULE_NAME", "entity_candidate:UNK SloppyDisc:EXPLICIT_MALWARE_NAME"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

DNS sensors.opensecurity-legacy.com, metadata malware_family SloppyLemming. Referans Cloudflare araştırması SloppyLemming'i threat actor olarak tanımlıyor. İkisi de actor'ü Malware type'a dönüştürüyor. DNS/indicator association doğru olsa da ortak entity_type hatası var; metadata bağımsız ontoloji doğrulaması değil. UNK_SloppyDisc'i ayrıca doğrulamadan alternatif malware diye önermedim.

Doğruluk tercihi: **Eşit / kesin üstünlük yok**. Katalog tercihi: **Eşit / kesin üstünlük yok**.

Teknik kaynak: [Cloudflare: SloppyLemming threat actor](https://www.cloudflare.com/cloudforce-one/research/unraveling-sloppylemmings-operations-across-south-asia/)

### 27. SID 2017873 / REV 3

Cohort: FRESH_OPERATIONAL — Source: `data\rules\et-open\emerging-coinminer.rules`

```text
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET COINMINER W32/BitCoinMiner.MultiThreat Stratum Protocol Mining.Notify Work Server Response"; flow:established,to_client; content:"|22|params|22 3A| [|22|"; depth:120; content:"|22|method|22 3A| |22|mining.notify|22|"; distance:0; reference:url,research.zscaler.com/2013/12/bitcoin-mining-operation-seen-across.html; reference:url,www.btcguild.com/new_protocol.php; reference:url,mining.bitcoin.cz/stratum-mining; classtype:coin-mining; sid:2017873; rev:3; metadata:attack_target Client_Endpoint, created_at 2013_12_17, deployment Perimeter, confidence High, signature_severity Major, tag Coinminer, updated_at 2019_07_26, mitre_tactic_id TA0040, mitre_tactic_name Impact, mitre_technique_id T1496, mitre_technique_name Resource_Hijacking;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | Cryptocurrency mining server response using Stratum protocol | Resource Hijacking |
| detected_entity | null | null |
| entity_type | null | null |
| category | Impact | Malware |
| subcategory | null | Malware Network Activity |
| mitre_tactic | Impact | Impact |
| mitre_technique | Resource Hijacking | Resource Hijacking |
| mitre_technique_id | T1496 | T1496 |
| cyber_kill_chain_phase | Actions on Objectives | null |
| model_confidence (hakem puanı değil) | 0.95 | 0.9 |

**gemini-3.5-flash-lite — kör etiket B, classification ID 1426**

Kaydedilmiş validator: PASS; MITRE provenance: EXACT_SOURCE_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET COINMINER W32/BitCoinMiner.MultiThreat Stratum Protocol Mining.Notify Work Server Response", "classtype: coin-mining", "metadata: mitre_technique_id T1496", "content: \|22\|method\|22 3A\| \|22\|mining.notify\|22\|", "mitre_candidate:T1496:0.90"]

**qwen3:8b — kör etiket A, classification ID 1436**

Kaydedilmiş validator: PASS; MITRE provenance: EXACT_SOURCE_MAPPING; önemli bulgu alanları: category, subcategory.

Evidence: ["msg: ET COINMINER W32/BitCoinMiner.MultiThreat Stratum Protocol Mining.Notify Work Server Response", "classtype: coin-mining", "metadata: mitre_tactic_id TA0040, mitre_tactic_name Impact, mitre_technique_id T1496, mitre_technique_name Resource_Hijacking", "content: \|22\|params\|22 3A\| [\|22\|, \|22\|method\|22 3A\| \|22\|mining.notify\|22\|", "mitre_candidate:T1496:0.90"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

Stratum mining.notify response/source T1496. A mining protokolünü Malware/Malware Network Activity diye program kanıtı olmadan etiketliyor. B cryptocurrency mining server response diyerek gözlemi doğru koruyor. B Impact/T1496/KC source'un olası izinsiz kullanım bağlamı; mining her durumda unauthorized değildir. İki source mapping canonical, entity null yerinde.

Doğruluk tercihi: **gemini-3.5-flash-lite**. Katalog tercihi: **gemini-3.5-flash-lite**.

### 28. SID 2100606 / REV 7

Cohort: FRESH_OPERATIONAL — Source: `data\rules\et-open\emerging-misc.rules`

```text
alert tcp $EXTERNAL_NET any -> $HOME_NET 513 (msg:"GPL MISC rlogin root"; flow:established,to_server; content:"root|00|root|00|"; reference:arachnids,389; classtype:attempted-admin; sid:2100606; rev:7; metadata:created_at 2010_09_23, signature_severity Informational, tag Description_Generated_By_Proofpoint_Nexus, updated_at 2024_03_08;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | Attempted administrative access via rlogin | Informational Activity |
| detected_entity | null | null |
| entity_type | null | null |
| category | Other | Other |
| subcategory | Informational Activity | Informational Activity |
| mitre_tactic | null | null |
| mitre_technique | null | null |
| mitre_technique_id | null | null |
| cyber_kill_chain_phase | null | null |
| model_confidence (hakem puanı değil) | 0.5 | 0.5 |

**gemini-3.5-flash-lite — kör etiket A, classification ID 1368**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: GPL MISC rlogin root", "classtype: attempted-admin", "content: root\|00\|root\|00\|"]

**qwen3:8b — kör etiket B, classification ID 1372**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: \"GPL MISC rlogin root\"", "classtype: attempted-admin", "content: \"root\|00\|root\|00\|\""]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

TCP513 rlogin root-null-root-null. A attempted administrative access via rlogin ile gerçek gözlemi anlatıyor, B yalnız Informational Activity diyor. İkisinin null entity/MITRE/KC alanları temkinli; başarılı login veya spesifik ürün çıkarımı yapılmıyor. Fark katalog ayrıntısı.

Doğruluk tercihi: **Eşit / kesin üstünlük yok**. Katalog tercihi: **gemini-3.5-flash-lite**.

### 29. SID 2066004 / REV 1

Cohort: AUDITED_BENCHMARK — Source: `emerging-web_specific_apps.rules`

```text
alert http any any -> $HOME_NET any (msg:"ET WEB_SPECIFIC_APPS AvTech PwdGrp.cgi user Parameter Cross Site Scripting Attempt (CVE-2025-57202)"; flow:established,to_server; http.method; content:"POST"; http.uri; bsize:30; content:"/cgi-bin/supervisor/PwdGrp.cgi"; fast_pattern; http.request_body; content:"action|3d|add"; content:"user|3d|"; pcre:"/^.*(?:on(?:(?:error)|(?:s(?:elec|ubmi)|rese)t|d(?:blclick|ragdrop)|(?:mouse|key)[a-z]|c(?:hange|lick)|(?:un)?load|focus|blur)|s(?:cript|tyle))(?:=|%3[dD])?/Ri"; reference:url,xchg-rax-rax.github.io/2025/10/13/avtech_vulnerabilites.html; reference:cve,2025-57202; classtype:web-application-attack; sid:2066004; rev:1; metadata:affected_product AvTech, attack_target Networking_Equipment, tls_state plaintext, created_at 2025_12_03, cve CVE_2025_57202, deployment Perimeter, deployment Internal, performance_impact Low, confidence High, signature_severity Major, tag Exploit, tag Description_Generated_By_Proofpoint_Nexus, updated_at 2025_12_03, mitre_tactic_id TA0001, mitre_tactic_name Initial_Access, mitre_technique_id T1190, mitre_technique_name Exploit_Public_Facing_Application; target:dest_ip;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | Cross Site Scripting Attempt | Web Attack |
| detected_entity | AvTech | AvTech |
| entity_type | Product | Product |
| category | Web Attack | Web Attack |
| subcategory | Cross-Site Scripting | Cross-Site Scripting |
| mitre_tactic | null | Initial Access |
| mitre_technique | null | Exploit Public-Facing Application |
| mitre_technique_id | null | T1190 |
| cyber_kill_chain_phase | Exploitation | Exploitation |
| model_confidence (hakem puanı değil) | 0.9 | 0.99 |

**gemini-3.5-flash-lite — kör etiket B, classification ID 1140**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET WEB_SPECIFIC_APPS AvTech PwdGrp.cgi user Parameter Cross Site Scripting Attempt (CVE-2025-57202)", "classtype: web-application-attack", "pcre: /^.*(?:on(?:(?:error)\|(?:s(?:elec\|ubmi)\|rese)t\|d(?:blclick\|ragdrop)\|(?:mouse\|key)[a-z]\|c(?:hange\|lick)\|(?:un)?load\|focus\|blur)\|s(?:cript\|tyle))(?:=\|%3[dD])?/Ri", "entity_candidate:AvTech:SPECIFIC_AFFECTED_PRODUCT", "mitre_candidate:T1190:0.99"]

**qwen3:8b — kör etiket A, classification ID 1141**

Kaydedilmiş validator: PASS; MITRE provenance: EXACT_SOURCE_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET WEB_SPECIFIC_APPS AvTech PwdGrp.cgi user Parameter Cross Site Scripting Attempt (CVE-2025-57202)", "metadata.affected_product: AvTech", "metadata.cve: CVE_2025_57202", "content: user\|3d\|", "pcre: /.*(?:on(?:error\|s(?:elec\|ubmi)\|rese)t\|d(?:blclick\|ragdrop)\|(?:mouse\|key)[a-z]\|c(?:hange\|lick)\|(?:un)?load\|focus\|blur)/Ri", "app_layer.http.uri: /cgi-bin/supervisor/PwdGrp.cgi", "classtype: web-application-attack", "entity_candidate:AvTech:SPECIFIC_AFFECTED_PRODUCT", "mitre_candidate:T1190:0.99"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

AvTech PwdGrp.cgi user parametresi XSS PCRE'si, CVE/source T1190. A product/XSS/canonical source MITRE tutarlı ama generic Web Attack behavior. B daha spesifik XSS behavior, final MITRE null. İkisinin avantajı farklı: null mapping otomatik yanlış kabul edilmedi, source provenance ayrıca korunmalı. Kesin üstünlük yok.

Doğruluk tercihi: **Eşit / kesin üstünlük yok**. Katalog tercihi: **Eşit / kesin üstünlük yok**.

### 30. SID 2100366 / REV 8

Cohort: FRESH_OPERATIONAL — Source: `data\rules\et-open\emerging-icmp.rules`

```text
alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP PING *NIX"; itype:8; content:"|10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F|"; depth:32; classtype:misc-activity; sid:2100366; rev:8; metadata:created_at 2010_09_23, confidence Medium, signature_severity Informational, tag Description_Generated_By_Proofpoint_Nexus, updated_at 2019_07_26;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | ICMP ping activity | Informational Activity |
| detected_entity | null | null |
| entity_type | null | null |
| category | Other | Other |
| subcategory | Informational Activity | Informational Activity |
| mitre_tactic | null | null |
| mitre_technique | null | null |
| mitre_technique_id | null | null |
| cyber_kill_chain_phase | null | null |
| model_confidence (hakem puanı değil) | 0.8 | 0.5 |

**gemini-3.5-flash-lite — kör etiket A, classification ID 1446**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: \"GPL ICMP PING *NIX\"", "protocol: icmp", "classtype: misc-activity"]

**qwen3:8b — kör etiket B, classification ID 1460**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: \"GPL ICMP PING *NIX\"", "classtype: misc-activity", "content: [\|10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F\|]"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

ICMP echo type8 ve artan-byte payload, belirli tool fingerprint yok. A ICMP ping diyor; B Informational Activity ile ping işlevini kaybediyor. Diğer conservative category ve null alanlar uyumlu. A daha açıklayıcı, ayrı semantik zafer değil.

Doğruluk tercihi: **Eşit / kesin üstünlük yok**. Katalog tercihi: **gemini-3.5-flash-lite**.

### 31. SID 2500010 / REV 7731

Cohort: FRESH_OPERATIONAL — Source: `data\rules\et-open\compromised.rules`

```text
alert ip [171.231.176.42,171.231.177.118,171.231.178.70,171.231.179.20,171.231.183.213,171.231.183.72,171.231.184.215,171.231.185.92,171.231.187.199,171.231.187.245,171.231.188.78,171.231.189.174,171.231.190.24,171.231.190.30,171.231.191.67,171.231.194.150,171.231.196.244,171.231.196.247,171.243.149.121,171.243.150.213,171.243.150.32,177.74.153.10,177.84.130.211,178.104.90.251,178.128.163.14,178.128.80.167,178.175.167.40,181.129.250.18,18.145.109.98,18.145.143.60] any -> $HOME_NET any (msg:"ET COMPROMISED Known Compromised or Hostile Host Traffic group 6"; reference:url,danger.rulez.sk/projects/bruteforceblocker/blist.php; threshold: type limit, track by_src, seconds 60, count 1; classtype:misc-attack; sid:2500010; rev:7731; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag COMPROMISED, signature_severity Major, created_at 2011_04_28, updated_at 2026_08_31;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | Traffic from known malicious infrastructure | Traffic from known malicious infrastructure |
| detected_entity | null | null |
| entity_type | null | null |
| category | Network Abuse | Network Abuse |
| subcategory | Suspicious IP Activity | Suspicious IP Activity |
| mitre_tactic | null | null |
| mitre_technique | null | null |
| mitre_technique_id | null | null |
| cyber_kill_chain_phase | null | null |
| model_confidence (hakem puanı değil) | 0.8 | 0.9 |

**gemini-3.5-flash-lite — kör etiket B, classification ID 1245**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET COMPROMISED Known Compromised or Hostile Host Traffic group 6", "classtype: misc-attack"]

**qwen3:8b — kör etiket A, classification ID 1244**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["message: ET COMPROMISED Known Compromised or Hostile Host Traffic group 6", "metadata: tag COMPROMISED", "similar_rules: sid 2500000"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

Compromised-host IP listesi. İkisi de suspicious-IP/network-abuse association'ı tutup named entity/MITRE/KC uydurmuyor. Final alanlarda anlamlı üstünlük yok; IP feed eşleşmesi belirli malware fingerprint olarak gösterilmemiş.

Doğruluk tercihi: **Eşit / kesin üstünlük yok**. Katalog tercihi: **Eşit / kesin üstünlük yok**.

### 32. SID 2037772 / REV 2

Cohort: FRESH_OPERATIONAL — Source: `data\rules\et-open\emerging-current_events.rules`

```text
alert dns $HOME_NET any -> any any (msg:"ET CURRENT_EVENTS Sliver Related Domain in DNS Lookup (saleforces-it .com)"; dns.query; bsize:17; content:"saleforces-it.com"; nocase; reference:url,twitter.com/ESETresearch/status/1547943014860894210; classtype:trojan-activity; sid:2037772; rev:2; metadata:attack_target Client_Endpoint, created_at 2022_07_15, deployment Perimeter, confidence High, signature_severity Major, tag Description_Generated_By_Proofpoint_Nexus, updated_at 2024_03_26;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | DNS lookup for Sliver-related domain | DNS query to suspicious domain |
| detected_entity | null | null |
| entity_type | null | null |
| category | Command and Control | Suspicious DNS |
| subcategory | DNS C2 Communication | Unusual DNS Query |
| mitre_tactic | null | null |
| mitre_technique | null | null |
| mitre_technique_id | null | null |
| cyber_kill_chain_phase | Command and Control | null |
| model_confidence (hakem puanı değil) | 0.8 | 0.8 |

**gemini-3.5-flash-lite — kör etiket B, classification ID 1340**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: subcategory.

Evidence: ["msg: ET CURRENT_EVENTS Sliver Related Domain in DNS Lookup (saleforces-it .com)", "classtype: trojan-activity", "content: saleforces-it.com"]

**qwen3:8b — kör etiket A, classification ID 1344**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["content: saleforces-it.com", "classtype: trojan-activity", "category_hint: Suspicious DNS", "controlled_subcategories: Suspicious DNS -> Unusual DNS Query"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

Sliver-related saleforces-it.com DNS lookup. A suspicious DNS diyerek protokole sadık fakat Sliver association'ı behavior'da kaybediyor. B association'ı daha iyi yazsa da DNS C2 Communication diyor: C2 host adını çözmek DNS üzerinden komut kanalı kurulduğu anlamına gelmez. Bu yanlış alt kategori, ayrıntı avantajından önemli. Entity null temkinli sayıldı.

Doğruluk tercihi: **qwen3:8b**. Katalog tercihi: **qwen3:8b**.

### 33. SID 2019842 / REV 7

Cohort: AUDITED_BENCHMARK — Source: `emerging-web_client.rules`

```text
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_CLIENT Possible Internet Explorer VBscript CVE-2014-6332 multiple redim preserve"; flow:established,to_client; http.content_type; content:!"text/xml"; content:!"application/xml"; file.data; content:"preserve"; nocase; content:"redim|20|"; nocase; fast_pattern; pcre:"/^\s*?Preserve\s*?(?P<var1>[a-z]\w{0,254}+)\s*?\x28\s*?[^\x29]+?\x29.*?redim\s*?Preserve\s*?(?P=var1)/Rsi"; reference:cve,2014-6332; classtype:attempted-user; sid:2019842; rev:7; metadata:affected_product Web_Browsers, affected_product Web_Browser_Plugins, attack_target Client_Endpoint, created_at 2014_12_03, cve CVE_2014_6332, deployment Perimeter, confidence Medium, signature_severity Major, tag Web_Client_Attacks, tag CISA_KEV, updated_at 2024_03_21;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | Exploitation of CVE-2014-6332 in Internet Explorer via VBScript redim preserve | Web Attack |
| detected_entity | Internet Explorer | Internet Explorer |
| entity_type | Product | Product |
| category | Web Attack | Web Attack |
| subcategory | null | null |
| mitre_tactic | null | null |
| mitre_technique | null | null |
| mitre_technique_id | null | null |
| cyber_kill_chain_phase | Exploitation | Exploitation |
| model_confidence (hakem puanı değil) | 0.8 | 0.8 |

**gemini-3.5-flash-lite — kör etiket B, classification ID 1045**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET WEB_CLIENT Possible Internet Explorer VBscript CVE-2014-6332 multiple redim preserve", "cve: CVE-2014-6332", "content: preserve", "content: redim\|20\|", "entity_candidate:Internet Explorer:EXPLICIT_RULE_NAME"]

**qwen3:8b — kör etiket A, classification ID 1044**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: 'ET WEB_CLIENT Possible Internet Explorer VBscript CVE-2014-6332 multiple redim preserve'", "content: 'preserve', 'redim\|20\|'", "pcre: '/^\\s*?Preserve\\s*?(?P<var1>[a-z]\\w{0,254}+)\\s*?\\x28\\s*?[^\\x29]+?\\x29.*?redim\\s*?Preserve\\s*?(?P=var1)/Rsi'", "metadata: 'cve CVE_2014_6332'", "entity_candidate:Internet Explorer:EXPLICIT_RULE_NAME"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

IE VBScript redim preserve paterni, CVE-2014-6332. İkisinin product/Web Attack/Exploitation alanları uyumlu; MITRE null makul. A generic Web Attack behavior, B CVE/VBScript mekanizmasını koruyor. Başarılı exploit ispatı yok; B katalog ayrıntısı üstün.

Doğruluk tercihi: **Eşit / kesin üstünlük yok**. Katalog tercihi: **gemini-3.5-flash-lite**.

### 34. SID 2040009 / REV 3

Cohort: FRESH_OPERATIONAL — Source: `data\rules\et-open\emerging-dyn_dns.rules`

```text
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET DYN_DNS DYNAMIC_DNS HTTP Request to a *.nard .ca Domain"; flow:established,to_server; http.host; content:".nard.ca"; endswith; reference:url,freedns.afraid.org/domain/registry/; classtype:bad-unknown; sid:2040009; rev:3; metadata:attack_target Client_and_Server, created_at 2022_11_28, deployment Perimeter, former_category INFO, performance_impact Low, confidence High, signature_severity Informational, updated_at 2024_06_11, mitre_tactic_id TA0011, mitre_tactic_name Command_And_Control, mitre_technique_id T1568, mitre_technique_name Dynamic_Resolution;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | HTTP request to a dynamic DNS domain | HTTP request to a dynamic DNS domain |
| detected_entity | null | null |
| entity_type | null | null |
| category | Command and Control | Suspicious DNS |
| subcategory | HTTP C2 Communication | Unusual DNS Query |
| mitre_tactic | Command And Control | Command And Control |
| mitre_technique | Dynamic Resolution | Dynamic Resolution |
| mitre_technique_id | T1568 | T1568 |
| cyber_kill_chain_phase | Command and Control | null |
| model_confidence (hakem puanı değil) | 0.85 | 0.9 |

**gemini-3.5-flash-lite — kör etiket A, classification ID 1249**

Kaydedilmiş validator: PASS; MITRE provenance: EXACT_SOURCE_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET DYN_DNS DYNAMIC_DNS HTTP Request to a *.nard .ca Domain", "content: .nard.ca", "app_layer: http.host", "metadata: mitre_technique_id T1568", "mitre_candidate:T1568:0.90"]

**qwen3:8b — kör etiket B, classification ID 1248**

Kaydedilmiş validator: PASS; MITRE provenance: EXACT_SOURCE_MAPPING; önemli bulgu alanları: subcategory.

Evidence: ["content: .nard.ca", "mitre_candidates: T1568", "controlled_subcategories: Suspicious DNS > Unusual DNS Query", "similar_rules: category and subcategory", "mitre_candidate:T1568:0.90"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

HTTP host .nard.ca dynamic-DNS, source T1568. A HTTP gözlemini doğru tutuyor; C2/KC source ilişkisi olarak koşullu. B Unusual DNS Query ile HTTP buffer'ını DNS trafiği diye etiketliyor. SID2064637 ile aynı rubric uygulandı; canonical T1568 her ikisinde source uyumlu.

Doğruluk tercihi: **gemini-3.5-flash-lite**. Katalog tercihi: **gemini-3.5-flash-lite**.

### 35. SID 2060508 / REV 2

Cohort: AUDITED_BENCHMARK — Source: `emerging-remote_access.rules`

```text
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"ET REMOTE_ACCESS Observed Anydesk Relay Domain (net .anydesk .com) in TLS SNI"; flow:established,to_server; tls.sni; dotprefix; content:".net.anydesk.com"; endswith; fast_pattern; reference:url,support.anydesk.com/knowledge/firewall; classtype:misc-activity; sid:2060508; rev:2; metadata:affected_product Any, attack_target Client_and_Server, created_at 2025_03_03, deployment Perimeter, former_category INFO, performance_impact Low, confidence High, signature_severity Informational, tag AnyDesk, updated_at 2025_03_05, mitre_tactic_id TA0011, mitre_tactic_name Command_And_Control, mitre_technique_id T1219, mitre_technique_name Remote_Access_Software;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | AnyDesk relay domain observed in TLS SNI | Observed Anydesk Relay Domain in TLS SNI |
| detected_entity | AnyDesk | AnyDesk |
| entity_type | Remote Access Tool | Remote Access Tool |
| category | Remote Access | Remote Access |
| subcategory | Remote Access Software | Remote Access Software |
| mitre_tactic | Command And Control | Command And Control |
| mitre_technique | Remote Access Tools | Remote Access Tools |
| mitre_technique_id | T1219 | T1219 |
| cyber_kill_chain_phase | Command and Control | null |
| model_confidence (hakem puanı değil) | 0.95 | 0.99 |

**gemini-3.5-flash-lite — kör etiket B, classification ID 1136**

Kaydedilmiş validator: PASS; MITRE provenance: EXACT_SOURCE_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET REMOTE_ACCESS Observed Anydesk Relay Domain (net .anydesk .com) in TLS SNI", "content: .net.anydesk.com", "metadata: mitre_tactic_id TA0011", "metadata: mitre_technique_id T1219", "entity_candidate:AnyDesk:EXPLICIT_RULE_NAME", "mitre_candidate:T1219:0.99"]

**qwen3:8b — kör etiket A, classification ID 1137**

Kaydedilmiş validator: PASS; MITRE provenance: EXACT_SOURCE_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET REMOTE_ACCESS Observed Anydesk Relay Domain (net .anydesk .com) in TLS SNI", "content: .net.anydesk.com", "entity_hint: AnyDesk", "entity_candidates: AnyDesk (Remote Access Tool)", "mitre_candidates: T1219 (Remote Access Tools)", "entity_candidate:AnyDesk:EXPLICIT_RULE_NAME", "mitre_candidate:T1219:0.99"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

AnyDesk relay TLS SNI/source T1219. İkisi de AnyDesk/RAS ve canonical source mapping bakımından uygun. A KC null, B KC C2: doluluk otomatik doğruluk üstünlüğü değil; servis kullanımı kötü niyet kanıtlamaz. SID2060513 ile tutarlı eşitlik kararı.

Doğruluk tercihi: **Eşit / kesin üstünlük yok**. Katalog tercihi: **Eşit / kesin üstünlük yok**.

### 36. SID 2025094 / REV 7

Cohort: FRESH_OPERATIONAL — Source: `data\rules\et-open\emerging-adware_pup.rules`

```text
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET ADWARE_PUP Win32/Adware.Adposhel.A Checkin 5"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/q/"; startswith; fast_pattern; http.request_body; content:"q="; startswith; pcre:"/^[a-zA-Z0-9_-]+$/R"; http.connection; content:"close"; nocase; endswith; http.content_type; content:"application/x-www-form-urlencoded"; startswith; endswith; http.header_names; to_lowercase; content:!"|0d 0a|accept"; content:!"|0d 0a|referer|0d 0a|"; reference:md5,f0e02ba660cfcb122b89bc780a6555ac; classtype:pup-activity; sid:2025094; rev:7; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, created_at 2017_12_01, deployment Internet, malware_family Adposhel, performance_impact Moderate, confidence High, signature_severity Minor, tag Adware, updated_at 2024_05_01;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | Adposhel malware checkin | Adware check-in activity |
| detected_entity | Adposhel | Adposhel |
| entity_type | Malware | Malware |
| category | Malware | Malware |
| subcategory | Malware Network Activity | Malware Network Activity |
| mitre_tactic | null | null |
| mitre_technique | null | null |
| mitre_technique_id | null | null |
| cyber_kill_chain_phase | Command and Control | null |
| model_confidence (hakem puanı değil) | 0.9 | 0.9 |

**gemini-3.5-flash-lite — kör etiket B, classification ID 1324**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET ADWARE_PUP Win32/Adware.Adposhel.A Checkin 5", "metadata: malware_family Adposhel", "classtype: pup-activity", "entity_candidate:Adposhel:EXPLICIT_MALWARE_NAME"]

**qwen3:8b — kör etiket A, classification ID 1329**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["metadata.malware_family", "content.POST", "content.q=", "content.close", "content.application/x-www-form-urlencoded", "entity_candidate:Adposhel:EXPLICIT_MALWARE_NAME"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

Adposhel adware/PUP POST /q/, q=, header constraints ve md5. Family association destekli. A Adware check-in diyerek PUP niteliğini koruyor ve KC null bırakıyor. B generic malware checkin/C2 KC veriyor; olası kötü amaçlı check-in bağlamı ama her PUP çağrısı saldırı zinciri değil. A katalog için daha sadık; semantik fark kesin değil.

Doğruluk tercihi: **Eşit / kesin üstünlük yok**. Katalog tercihi: **qwen3:8b**.

### 37. SID 2102809 / REV 5

Cohort: FRESH_OPERATIONAL — Source: `data\rules\et-open\emerging-sql.rules`

```text
alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.unregister_mview_repgroup buffer overflow attempt"; flow:established,to_server; content:"dbms_repcat.unregister_mview_repgroup"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*(gname|gowner)[\r\n\s]*=>[\r\n\s]*\2|(gname|gowner)\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*((\x27[^\x27]*\x27|\x22[^\x22]+\x22)\s*,\s*){2}(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102809; rev:5; metadata:created_at 2010_09_23, confidence High, signature_severity Major, tag Description_Generated_By_Proofpoint_Nexus, updated_at 2024_03_08;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | SQL buffer overflow attempt targeting dbms_repcat.unregister_mview_repgroup | Buffer Overflow Attempt |
| detected_entity | null | null |
| entity_type | null | null |
| category | Exploitation | Exploitation |
| subcategory | Exploit Attempt | Exploit Attempt |
| mitre_tactic | null | null |
| mitre_technique | null | null |
| mitre_technique_id | null | null |
| cyber_kill_chain_phase | Exploitation | Exploitation |
| model_confidence (hakem puanı değil) | 0.9 | 0.9 |

**gemini-3.5-flash-lite — kör etiket B, classification ID 1299**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: GPL SQL dbms_repcat.unregister_mview_repgroup buffer overflow attempt", "content: dbms_repcat.unregister_mview_repgroup", "classtype: attempted-user"]

**qwen3:8b — kör etiket A, classification ID 1310**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["content: dbms_repcat.unregister_mview_repgroup", "classtype: attempted-user", "pcre: /.../si", "metadata: confidence High"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

Oracle DBMS_REPCAT.unregister_mview_repgroup ve 1075 karakter argüman PCRE'si. İkisinde overflow/Exploitation uyumlu. A generic behavior, B Oracle/package mekanizmasını koruyor. Structured entity iki tarafta null: product association porttan değil fonksiyon/msg'den saklanabilirdi, fakat null yanlış ürün iddiası değil. ATT&CK zorlanmıyor.

Doğruluk tercihi: **Eşit / kesin üstünlük yok**. Katalog tercihi: **gemini-3.5-flash-lite**.

### 38. SID 2001581 / REV 15

Cohort: FRESH_OPERATIONAL — Source: `data\rules\et-open\emerging-scan.rules`

```text
alert tcp $HOME_NET any -> any 135 (msg:"ET SCAN Behavioral Unusual Port 135 traffic Potential Scan or Infection"; flow:to_server; flags: S,12; threshold: type both, track by_src, count 70 , seconds 60; classtype:misc-activity; sid:2001581; rev:15; metadata:created_at 2010_07_30, confidence Medium, signature_severity Informational, updated_at 2019_07_26;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | Unusual port 135 traffic indicating potential port scan or infection | Unusual Port 135 traffic |
| detected_entity | null | null |
| entity_type | null | null |
| category | Reconnaissance | Network Abuse |
| subcategory | Service Scan | Suspicious TCP Activity |
| mitre_tactic | null | null |
| mitre_technique | null | null |
| mitre_technique_id | null | null |
| cyber_kill_chain_phase | Reconnaissance | null |
| model_confidence (hakem puanı değil) | 0.7 | 0.5 |

**gemini-3.5-flash-lite — kör etiket A, classification ID 1472**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET SCAN Behavioral Unusual Port 135 traffic Potential Scan or Infection"]

**qwen3:8b — kör etiket B, classification ID 1489**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET SCAN Behavioral Unusual Port 135 traffic Potential Scan or Infection", "category_hint: Reconnaissance", "controlled_subcategories: Network Abuse -> Suspicious TCP Activity"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

Port135'e 60 saniyede 70 SYN, by_src; farklı hedef sayısı şart değil. A potential scan/infection ifadesiyle niyeti koruyor; Service Scan/KC Recon hipotezdir. B Unusual Port135/Suspicious TCP ile daha güvenli ama threshold/scan bağlamını zayıflatıyor. İkisi savunulabilir; porttan ürün atamamak doğru.

Doğruluk tercihi: **Eşit / kesin üstünlük yok**. Katalog tercihi: **gemini-3.5-flash-lite**.

Teknik kaynak: [Suricata threshold semantics](https://docs.suricata.io/en/latest/rules/thresholding.html)

### 39. SID 2101640 / REV 12

Cohort: FRESH_OPERATIONAL — Source: `data\rules\et-open\emerging-chat.rules`

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET 6666:7000 (msg:"GPL CHAT IRC DCC chat request"; flow:established,to_server; flowbits:set,is_proto_irc; content:"PRIVMSG "; depth:8; nocase; content:" |3A|.DCC CHAT chat"; nocase; classtype:policy-violation; sid:2101640; rev:12; metadata:created_at 2010_09_23, signature_severity Informational, updated_at 2024_03_14;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | IRC DCC chat request | GPL CHAT IRC DCC chat request |
| detected_entity | null | null |
| entity_type | null | null |
| category | Policy Violation | Policy Violation |
| subcategory | Prohibited Application or Protocol | Prohibited Application or Protocol |
| mitre_tactic | null | Defense Evasion |
| mitre_technique | null | Prohibited Application or Protocol |
| mitre_technique_id | null | null |
| cyber_kill_chain_phase | null | null |
| model_confidence (hakem puanı değil) | 0.85 | 0.8 |

**gemini-3.5-flash-lite — kör etiket B, classification ID 1422**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: GPL CHAT IRC DCC chat request", "classtype: policy-violation", "content: PRIVMSG ", "content:  \|3A\|.DCC CHAT chat"]

**qwen3:8b — kör etiket A, classification ID 1432**

Kaydedilmiş validator: REVIEW; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: mitre_tactic, mitre_technique.

Evidence: ["msg: GPL CHAT IRC DCC chat request", "classtype: policy-violation", "flow: established, to_server", "content: PRIVMSG , \|3A\|.DCC CHAT chat"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

IRC PRIVMSG DCC chat policy rule. İkisi policy intent'i koruyor; yerel ihlal kurum politikasına bağlıdır. A Defense Evasion/Prohibited Application or Protocol değerlerini ID'siz ATT&CK tuple yapıyor. B desteklenmeyen MITRE'yi tamamen null tutarak yapısal/semantik hatadan kaçınıyor.

Doğruluk tercihi: **gemini-3.5-flash-lite**. Katalog tercihi: **gemini-3.5-flash-lite**.

### 40. SID 2102785 / REV 5

Cohort: FRESH_OPERATIONAL — Source: `data\rules\et-open\emerging-sql.rules`

```text
alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.execute_ddl buffer overflow attempt"; flow:established,to_server; content:"dbms_repcat.execute_ddl"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*(\x27[^\x27]{1075,}\x27|\x22[^\x22]{1075,}\x22)[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2|gname\s*=>\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,})|\(\s*(\x27[^\x27]{1075,}|\x22[^\x22]{1075,}))/si"; reference:url,www.appsecinc.com/resources/alerts/oracle/2004-0001/25.html; classtype:attempted-user; sid:2102785; rev:5; metadata:created_at 2010_09_23, confidence High, signature_severity Major, tag Description_Generated_By_Proofpoint_Nexus, updated_at 2024_03_08;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | buffer overflow attempt targeting Oracle DBMS_REPCAT | Buffer Overflow Attempt |
| detected_entity | null | null |
| entity_type | null | null |
| category | Exploitation | Exploitation |
| subcategory | Exploit Attempt | Exploit Attempt |
| mitre_tactic | null | null |
| mitre_technique | null | null |
| mitre_technique_id | null | null |
| cyber_kill_chain_phase | Exploitation | Exploitation |
| model_confidence (hakem puanı değil) | 0.8 | 0.9 |

**gemini-3.5-flash-lite — kör etiket B, classification ID 1395**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: GPL SQL dbms_repcat.execute_ddl buffer overflow attempt", "content: dbms_repcat.execute_ddl", "pcre: /((\\w+)[\\r\\n\\s]*\\x3a=[\\r\\n\\s]*(\\x27[^\\x27]{1075,}\\x27\|\\x22[^\\x22]{1075,}\\x22)[\\r\\n\\s]*\\x3b.*gname[\\r\\n\\s]*=>[\\r\\n\\s]*\\2\|gname\\s*=>\\s*(\\x27[^\\x27]{1075,}\|\\x22[^\\x22]{1075,})\|\\(\\s*(\\x27[^\\x27]{1075,}\|\\x22[^\\x22]{1075,}))/si"]

**qwen3:8b — kör etiket A, classification ID 1399**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["content: dbms_repcat.execute_ddl", "classtype: attempted-user", "pcre: /((\\w+)[\\r\\n\\s]*\\x3a=[\\r\\n\\s]*(\\x27[^\\x27]{1075,}\\x27\|\\x22[^\\x22]{1075,}\\x22)[\\r\\n\\s]*\\x3b.*gname[\\r\\n\\s]*=>[\\r\\n\\s]*\\2\|gname\\s*=>\\s*(\\x27[^\\x27]{1075,}\|\\x22[^\\x22]{1075,})\|\\(\\s*(\\x27[^\\x27]{1075,}\|\\x22[^\\x22]{1075,})/si"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

Oracle DBMS_REPCAT.execute_ddl uzun argüman overflow PCRE'si. A generic Buffer Overflow, B Oracle/package hedefini belirtiyor; diğer exploit/KC ve null MITRE alanları aynı çizgide. Product association iki tarafta eksik ama null otomatik yanlış değil. B katalog ayrıntısı daha yararlı.

Doğruluk tercihi: **Eşit / kesin üstünlük yok**. Katalog tercihi: **gemini-3.5-flash-lite**.

### 41. SID 2014649 / REV 7

Cohort: FRESH_OPERATIONAL — Source: `data\rules\et-open\emerging-activex.rules`

```text
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET ACTIVEX Tracker Software pdfSaver ActiveX StoreInRegistry Method Access Potential Buffer Overflow 2"; flow:established,to_client; file.data; content:"ActiveXObject"; nocase; content:"pdfxctrlLib.PdfPrinterPreferences"; nocase; distance:0; content:"StoreInRegistry"; nocase; distance:0; reference:url,exploit-db.com/exploits/18427/; classtype:attempted-user; sid:2014649; rev:7; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, created_at 2012_04_28, deployment Perimeter, confidence High, signature_severity Major, tag ActiveX, updated_at 2024_03_13;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | Buffer Overflow attempt via ActiveX StoreInRegistry method | Exploit Attempt |
| detected_entity | null | null |
| entity_type | null | null |
| category | Exploitation | Exploitation |
| subcategory | Exploit Attempt | Exploit Attempt |
| mitre_tactic | null | null |
| mitre_technique | null | null |
| mitre_technique_id | null | null |
| cyber_kill_chain_phase | Exploitation | Exploitation |
| model_confidence (hakem puanı değil) | 0.85 | 0.9 |

**gemini-3.5-flash-lite — kör etiket A, classification ID 1227**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET ACTIVEX Tracker Software pdfSaver ActiveX StoreInRegistry Method Access Potential Buffer Overflow 2", "content: ActiveXObject", "content: pdfxctrlLib.PdfPrinterPreferences", "content: StoreInRegistry"]

**qwen3:8b — kör etiket B, classification ID 1230**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["content: ActiveXObject", "content: pdfxctrlLib.PdfPrinterPreferences", "content: StoreInRegistry", "classtype: attempted-user", "metadata: confidence High"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

ActiveXObject/pdfxctrlLib.PdfPrinterPreferences/StoreInRegistry, msg Potential Buffer Overflow. Bu rule argüman uzunluğunu kontrol etmiyor. A metodu koruyor, B sadece Exploit Attempt; ikisinde de potential niteliği daha açık olmalı. Tracker pdfSaver product association saklanabilirdi, entity null otomatik yanlış değil. A açıklama daha iyi, exploit başarısı doğrulanmıyor.

Doğruluk tercihi: **Eşit / kesin üstünlük yok**. Katalog tercihi: **gemini-3.5-flash-lite**.

### 42. SID 2100289 / REV 12

Cohort: FRESH_OPERATIONAL — Source: `data\rules\et-open\emerging-pop3.rules`

```text
alert tcp $EXTERNAL_NET any -> $HOME_NET 110 (msg:"GPL POP3 x86 SCO overflow"; flow:established,to_server; content:"V|0E|1|C0 B0 3B 8D|~|12 89 F9 89 F9|"; reference:bugtraq,156; reference:cve,1999-0006; classtype:attempted-admin; sid:2100289; rev:12; metadata:created_at 2010_09_23, cve CVE_1999_0006, signature_severity Major, updated_at 2024_03_08;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | Buffer overflow attack against POP3 service | Exploit Attempt |
| detected_entity | null | null |
| entity_type | null | null |
| category | Exploitation | Exploitation |
| subcategory | Exploit Attempt | Exploit Attempt |
| mitre_tactic | null | Exploitation |
| mitre_technique | null | Exploit Attempt |
| mitre_technique_id | null | null |
| cyber_kill_chain_phase | Exploitation | null |
| model_confidence (hakem puanı değil) | 0.8 | 0.8 |

**gemini-3.5-flash-lite — kör etiket A, classification ID 1283**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: GPL POP3 x86 SCO overflow", "classtype: attempted-admin", "content: V\|0E\|1\|C0 B0 3B 8D\|~\|12 89 F9 89 F9\|"]

**qwen3:8b — kör etiket B, classification ID 1291**

Kaydedilmiş validator: REVIEW; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: mitre_tactic, mitre_technique.

Evidence: ["msg: \"GPL POP3 x86 SCO overflow\"", "classtype: attempted-admin", "content: \"V\|0E\|1\|C0 B0 3B 8D\|~\|12 89 F9 89 F9\|\"", "metadata: cve CVE_1999_0006", "references: cve,1999-0006"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

POP3/x86 SCO shellcode paterni, CVE-1999-0006. A overflow mekanizması/Exploitation ve null MITRE ile uyumlu. B generic exploit yanında ID'siz taxonomy etiketlerini MITRE tuple'a taşıyor. Esas hata invalid MITRE, KC null tek başına hata değil.

Doğruluk tercihi: **gemini-3.5-flash-lite**. Katalog tercihi: **gemini-3.5-flash-lite**.

### 43. SID 2404304 / REV 8031

Cohort: FRESH_OPERATIONAL — Source: `data\rules\et-open\botcc.rules`

```text
alert ip $HOME_NET any -> [50.16.16.211] any (msg:"ET CNC Feodo Tracker Reported CnC Server group 5"; reference:url,feodotracker.abuse.ch; threshold: type limit, track by_src, seconds 3600, count 1; flowbits:set,ET.Evil; flowbits:set,ET.BotccIP; classtype:trojan-activity; sid:2404304; rev:8031; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag Banking_Trojan, signature_severity Major, created_at 2014_11_04, updated_at 2026_08_31;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | Command and control server communication associated with Feodo Tracker | Command and Control |
| detected_entity | null | null |
| entity_type | null | null |
| category | Command and Control | Command and Control |
| subcategory | C2 Communication | C2 Communication |
| mitre_tactic | null | null |
| mitre_technique | null | null |
| mitre_technique_id | null | null |
| cyber_kill_chain_phase | Command and Control | null |
| model_confidence (hakem puanı değil) | 0.85 | 0.5 |

**gemini-3.5-flash-lite — kör etiket A, classification ID 1327**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET CNC Feodo Tracker Reported CnC Server group 5", "classtype: trojan-activity", "metadata: tag Banking_Trojan"]

**qwen3:8b — kör etiket B, classification ID 1333**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["category_hint: Command and Control", "classtype: trojan-activity", "metadata: tag Banking_Trojan", "references: url,feodotracker.abuse.ch"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

Feodo Tracker reported C&C IP'sine outbound trafik. A reported C2 server association'ı daha açık anlatıyor; B generic C2 diyor. İkisinin entity null seçimi doğru: feed adı malware ailesi değil. A KC C2 source ilişkisidir; B KC null diye cezalandırılmadı. Katalog ayrıntısı A lehine.

Doğruluk tercihi: **Eşit / kesin üstünlük yok**. Katalog tercihi: **gemini-3.5-flash-lite**.

### 44. SID 2029780 / REV 3

Cohort: AUDITED_BENCHMARK — Source: `emerging-hunting.rules`

```text
alert smtp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET HUNTING Possible Covid19 Themed Email Spam Outbound M5"; flow:established,to_server; content:"covid-19"; nocase; fast_pattern; threshold:type threshold, count 5, seconds 120, track by_src; classtype:bad-unknown; sid:2029780; rev:3; metadata:created_at 2020_03_31, confidence Medium, signature_severity Minor, tag Description_Generated_By_Proofpoint_Nexus, updated_at 2024_03_07;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | Suspicious SMTP traffic related to potential Covid-19 themed email spam | Suspicious SMTP Activity |
| detected_entity | null | null |
| entity_type | null | null |
| category | Network Abuse | Network Abuse |
| subcategory | Suspicious SMTP Activity | Suspicious SMTP Activity |
| mitre_tactic | null | null |
| mitre_technique | null | null |
| mitre_technique_id | null | null |
| cyber_kill_chain_phase | Delivery | null |
| model_confidence (hakem puanı değil) | 0.7 | 0.5 |

**gemini-3.5-flash-lite — kör etiket B, classification ID 1177**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET HUNTING Possible Covid19 Themed Email Spam Outbound M5", "protocol: smtp", "content: covid-19"]

**qwen3:8b — kör etiket A, classification ID 1176**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET HUNTING Possible Covid19 Themed Email Spam Outbound M5", "protocol: smtp", "classtype: bad-unknown", "content: [\"covid-19\"]"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

SMTP covid-19 eşleşmesi, 120 saniyede 5 eşleşme; possible themed spam. A generic Suspicious SMTP ve null KC ile temkinli. B potential Covid-19 spam diyerek anlamı koruyor; Delivery sadece olası kampanya bağlamı, kelime/eşik tek başına malicious delivery kanıtı değil. Null entity/MITRE yerinde.

Doğruluk tercihi: **Eşit / kesin üstünlük yok**. Katalog tercihi: **gemini-3.5-flash-lite**.

### 45. SID 2103244 / REV 5

Cohort: FRESH_OPERATIONAL — Source: `data\rules\et-open\emerging-netbios.rules`

```text
alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"GPL NETBIOS SMB irot andx bind attempt"; flow:established,to_server; flowbits:set,smb.tree.bind.irot; flowbits:noalert; content:"|00|"; depth:1; content:"|FF|SMB"; within:4; distance:3; pcre:"/^(\x75|\x2d|\x2f|\x73|\xa2|\x2e|\x24|\x74)/sR"; byte_test:1,!&,128,6,relative; content:"%"; depth:1; offset:39; byte_jump:2,0,little,relative; content:"&|00|"; within:2; distance:29; content:"|5C|PIPE|5C 00|"; distance:4; nocase; byte_jump:2,-17,relative,from_beginning,little; isdataat:4,relative; content:"|05|"; byte_test:1,!&,16,3,relative; content:"|0B|"; within:1; distance:1; content:"`|9E E7 B9|R=|CE 11 AA A1 00 00|i|01 29|?"; within:16; distance:29; classtype:protocol-command-decode; sid:2103244; rev:5; metadata:created_at 2010_09_23, confidence Medium, signature_severity Informational, updated_at 2024_03_14;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | NETBIOS SMB bind attempt | Suspicious network activity |
| detected_entity | null | null |
| entity_type | null | null |
| category | Network Abuse | Network Abuse |
| subcategory | Suspicious TCP Activity | Suspicious TCP Activity |
| mitre_tactic | null | null |
| mitre_technique | null | null |
| mitre_technique_id | null | null |
| cyber_kill_chain_phase | null | null |
| model_confidence (hakem puanı değil) | 0.8 | 0.5 |

**gemini-3.5-flash-lite — kör etiket B, classification ID 1371**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: category, subcategory.

Evidence: ["msg: GPL NETBIOS SMB irot andx bind attempt", "classtype: protocol-command-decode", "flow: established, to_server"]

**qwen3:8b — kör etiket A, classification ID 1374**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: category, subcategory.

Evidence: ["flow: established, to_server", "classtype: protocol-command-decode", "content: \|00\|, \|FF\|SMB, %, &\|00\|, \|5C\|PIPE\|5C 00\|, \|05\|, \|0B\|, `\|9E E7 B9\|R=\|CE 11 AA A1 00 00\|i\|01 29\|?", "pcre: /^(\\x75\|\\x2d\|\\x2f\|\\x73\|\\xa2\|\\x2e\|\\x24\|\\x74)/sR"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

SMB IROT bind, flowbits:set ve flowbits:noalert: bağımsız alarm vermeyen helper/dependency. A generic suspicious network, B somut NETBIOS SMB bind diyor. İkisi de Network Abuse/Suspicious TCP ile saldırı kanıtı olmayan decode kuralını risk olayı gibi etiketliyor ve noalert rolünü kaçırıyor. B göreli daha yararlı, ama ikisinde ortak problem var.

Doğruluk tercihi: **Eşit / kesin üstünlük yok**. Katalog tercihi: **gemini-3.5-flash-lite**.

Teknik kaynak: [Suricata flowbits / noalert](https://docs.suricata.io/en/latest/rules/flow-keywords.html)

### 46. SID 2014402 / REV 3

Cohort: FRESH_OPERATIONAL — Source: `data\rules\et-open\emerging-worm.rules`

```text
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET WORM W32/Rimecud wg.txt Checkin"; flow:established,to_server; http.uri; content:"/wg.txt"; reference:md5,a89f7289d5cce821a194542e90026082; reference:md5,fd56ce176889d4fbe588760a1da6462b; reference:url,www.microsoft.com/security/portal/Threat/Encyclopedia/Entry.aspx?Name=Worm%3AWin32%2FRimecud; classtype:trojan-activity; sid:2014402; rev:3; metadata:created_at 2012_03_20, signature_severity Major, updated_at 2020_04_21;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | Malware checkin activity | Malware Network Activity |
| detected_entity | null | null |
| entity_type | null | null |
| category | Malware | Malware |
| subcategory | Malware Network Activity | Malware Network Activity |
| mitre_tactic | null | Malware |
| mitre_technique | null | Malware Network Activity |
| mitre_technique_id | null | null |
| cyber_kill_chain_phase | Command and Control | null |
| model_confidence (hakem puanı değil) | 0.8 | 0.8 |

**gemini-3.5-flash-lite — kör etiket A, classification ID 1411**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET WORM W32/Rimecud wg.txt Checkin", "content: /wg.txt", "classtype: trojan-activity"]

**qwen3:8b — kör etiket B, classification ID 1418**

Kaydedilmiş validator: REVIEW; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: mitre_tactic, mitre_technique.

Evidence: ["msg: ET WORM W32/Rimecud wg.txt Checkin", "classtype: trojan-activity", "content: /wg.txt", "protocol: http", "flow: established, to_server"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

/wg.txt HTTP URI ve Rimecud check-in msg/md5 referansları. A malware check-in niyetini koruyor. B generic davranış yanında Malware/Malware Network Activity etiketlerini ID'siz MITRE tuple'a yazıyor. Rimecud source association ayrıca saklanabilir; kısa URI tek başına güçlü fingerprint olmadığından iki null entity otomatik yanlış sayılmadı.

Doğruluk tercihi: **gemini-3.5-flash-lite**. Katalog tercihi: **gemini-3.5-flash-lite**.

### 47. SID 2403426 / REV 111389

Cohort: FRESH_OPERATIONAL — Source: `data\rules\et-open\ciarmy.rules`

```text
alert ip [91.230.168.216,91.230.168.217,91.230.168.218,91.230.168.219,91.230.168.221,91.230.168.222,91.230.168.232,91.230.168.233,91.230.168.234,91.230.168.235,91.230.168.236,91.230.168.237,91.230.168.238,91.230.168.239,91.230.168.24,91.230.168.248,91.230.168.249,91.230.168.25,91.230.168.250,91.230.168.251,91.230.168.252,91.230.168.253,91.230.168.254,91.230.168.255,91.230.168.26,91.230.168.27,91.230.168.28,91.230.168.3,91.230.168.30,91.230.168.31,91.230.168.32,91.230.168.33,91.230.168.34,91.230.168.38,91.230.168.39,91.230.168.4,91.230.168.5,91.230.168.65,91.230.168.66,91.230.168.69,91.230.168.72,91.230.168.74,91.230.168.75,91.230.168.76,91.230.168.78,91.230.168.8,91.230.168.82,91.230.168.83,91.230.168.84,91.230.168.85] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 127"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403426; rev:111389; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_08_31;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | Traffic involving a poor reputation IP address | Traffic from known malicious infrastructure |
| detected_entity | null | null |
| entity_type | null | null |
| category | Network Abuse | Network Abuse |
| subcategory | Suspicious IP Activity | Suspicious IP Activity |
| mitre_tactic | null | null |
| mitre_technique | null | null |
| mitre_technique_id | null | null |
| cyber_kill_chain_phase | null | null |
| model_confidence (hakem puanı değil) | 0.8 | 0.875 |

**gemini-3.5-flash-lite — kör etiket B, classification ID 1241**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET CINS Active Threat Intelligence Poor Reputation IP group 127", "metadata: tag CINS"]

**qwen3:8b — kör etiket A, classification ID 1240**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["similar_rules"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

CINS poor-reputation IP feed. A known malicious diyor ve evidence yalnız similar_rules; B poor-reputation gözlemini msg/tag ile daha sadık anlatıyor. Category ve null entity/MITRE/KC uygun. B açıklama/denetlenebilirlik avantajı var, ayrı büyük semantik hata değil.

Doğruluk tercihi: **Eşit / kesin üstünlük yok**. Katalog tercihi: **gemini-3.5-flash-lite**.

### 48. SID 2101732 / REV 10

Cohort: AUDITED_BENCHMARK — Source: `emerging-rpc.rules`

```text
alert udp $EXTERNAL_NET any -> $HOME_NET 111 (msg:"GPL RPC portmap rwalld request UDP"; content:"|00 01 86 A0|"; depth:4; offset:12; content:"|00 00 00 03|"; within:4; distance:4; byte_jump:4,4,relative,align; byte_jump:4,4,relative,align; content:"|00 01 86 A8|"; within:4; content:"|00 00 00 00|"; depth:4; offset:4; classtype:rpc-portmap-decode; sid:2101732; rev:10; metadata:created_at 2010_09_23, signature_severity Informational, updated_at 2019_07_26;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | RPC portmap rwalld request | RPC portmap decode |
| detected_entity | null | null |
| entity_type | null | null |
| category | Discovery | Other |
| subcategory | null | Informational Activity |
| mitre_tactic | null | null |
| mitre_technique | null | null |
| mitre_technique_id | null | null |
| cyber_kill_chain_phase | null | null |
| model_confidence (hakem puanı değil) | 0.8 | 0.8 |

**gemini-3.5-flash-lite — kör etiket B, classification ID 1175**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: GPL RPC portmap rwalld request UDP", "classtype: rpc-portmap-decode"]

**qwen3:8b — kör etiket A, classification ID 1174**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: \"GPL RPC portmap rwalld request UDP\"", "classtype: rpc-portmap-decode", "protocol: udp"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

UDP111 program100000/procedure3 GETPORT ile program100008 rwalld sorgulanıyor; direkt rwalld saldırısı değil. A RPC portmap decode/Other genel olarak doğru ama işlevi kaybediyor. B portmap rwalld request/Discovery ile servis portu öğrenme işlevini koruyor. MITRE/KC null doğru; discovery benign olabilir.

Doğruluk tercihi: **Eşit / kesin üstünlük yok**. Katalog tercihi: **gemini-3.5-flash-lite**.

Teknik kaynak: [RFC 1833: Port Mapper GETPORT / DUMP](https://www.rfc-editor.org/rfc/rfc1833.html)

### 49. SID 2029645 / REV 2

Cohort: FRESH_OPERATIONAL — Source: `data\rules\et-open\emerging-scan.rules`

```text
alert http $EXTERNAL_NET any -> any any (msg:"ET SCAN Polaris Botnet User-Agent (Inbound)"; flow:established,to_server; http.user_agent; bsize:7; content:"polaris"; fast_pattern; classtype:attempted-admin; sid:2029645; rev:2; metadata:affected_product Linux, attack_target IoT, created_at 2020_03_18, deployment Perimeter, confidence High, signature_severity Minor, tag Description_Generated_By_Proofpoint_Nexus, updated_at 2024_03_08;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | Botnet User-Agent scanning activity | Web scanning activity |
| detected_entity | null | null |
| entity_type | null | null |
| category | Reconnaissance | Reconnaissance |
| subcategory | Web Scan | Web Scan |
| mitre_tactic | null | null |
| mitre_technique | null | null |
| mitre_technique_id | null | null |
| cyber_kill_chain_phase | Reconnaissance | Reconnaissance |
| model_confidence (hakem puanı değil) | 0.8 | 0.5 |

**gemini-3.5-flash-lite — kör etiket A, classification ID 1292**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET SCAN Polaris Botnet User-Agent (Inbound)", "content: polaris", "app_layer: http.user_agent"]

**qwen3:8b — kör etiket B, classification ID 1302**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET SCAN Polaris Botnet User-Agent (Inbound)", "classtype: attempted-admin", "content: polaris", "category_hint: Reconnaissance", "controlled_subcategories: Reconnaissance -> Web Scan"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

Inbound HTTP exact polaris User-Agent, msg botnet UA; web-scan source niyeti. A botnet UA association'ı behavior'da koruyor, B daha genel web-scan. Category/KC niyet olarak savunulabilir; UA tek başına infection kanıtı değil. Null entity/MITRE güvenli. A katalog ayrıntısı üstün.

Doğruluk tercihi: **Eşit / kesin üstünlük yok**. Katalog tercihi: **gemini-3.5-flash-lite**.

### 50. SID 2520127 / REV 6363

Cohort: FRESH_OPERATIONAL — Source: `data\rules\et-open\tor.rules`

```text
alert tcp [5.79.66.19,5.83.143.18,61.220.100.193,62.133.45.2,62.182.80.112,62.182.84.146,62.72.47.105,62.84.176.89,64.188.93.178,64.190.76.10] any -> $HOME_NET any (msg:"ET TOR Known Tor Exit Node Traffic group 128"; reference:url,check.torproject.org/torbulkexitlist; threshold: type limit, track by_src, seconds 60, count 1; classtype:misc-attack; flowbits:set,ET.TorIP; sid:2520127; rev:6363; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag TOR, signature_severity Informational, created_at 2008_12_01, updated_at 2026_08_31;)
```

| Alan | Gemini | Qwen |
|---|---|---|
| detected_behavior | Tor anonymity network traffic | Tor anonymity network usage |
| detected_entity | Tor | Tor |
| entity_type | Software | Software |
| category | Policy Violation | Policy Violation |
| subcategory | Prohibited Application or Protocol | Prohibited Application or Protocol |
| mitre_tactic | null | null |
| mitre_technique | null | null |
| mitre_technique_id | null | null |
| cyber_kill_chain_phase | null | null |
| model_confidence (hakem puanı değil) | 0.9 | 0.95 |

**gemini-3.5-flash-lite — kör etiket A, classification ID 1400**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET TOR Known Tor Exit Node Traffic group 128", "metadata: tag TOR", "entity_candidate:Tor:EXPLICIT_RULE_NAME"]

**qwen3:8b — kör etiket B, classification ID 1406**

Kaydedilmiş validator: PASS; MITRE provenance: NO_SUPPORTED_MAPPING; önemli bulgu alanları: belirli önemli hata ileri sürülmedi.

Evidence: ["msg: ET TOR Known Tor Exit Node Traffic group 128", "entity_hint: null", "category_hint: null", "entity_candidates: Tor (Software)", "entity_candidate:Tor:EXPLICIT_RULE_NAME"]

**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**

Tor exit-node IP listesi. İkisi Tor Software/Policy association'ı koruyor; entity endpoint'te çalışan client fingerprint anlamına gelmemeli. Policy Violation kurumun Tor politikasına bağlıdır, IP eşleşmesi tek başına ihlal/kötü niyet kanıtı değil. Null ATT&CK/KC makul ve belirgin model üstünlüğü yok.

Doğruluk tercihi: **Eşit / kesin üstünlük yok**. Katalog tercihi: **Eşit / kesin üstünlük yok**.

## Doğrulama ve sınırlar

- sample_exactly_50: True
- unique_pairs_50: True
- seed42_reproducible: True
- all_50_judgments_complete: True
- original_source_hashes_unchanged: True
- database_100_outputs_match_snapshot: True
- side_assessments_100: True
- nine_fields_per_side: True
- all_unreviewed: True
- review_lock_matches: True

Golden dataset, sample-250, baseline results ve local MITRE SHA256 değerleri başlangıçla aynı. Yeni API çağrısı: 0. DB mutation: 0. AI review statüsü: UNREVIEWED. Kaynak/prompt/candidate ortaklıkları nedeniyle bu test salt model yeteneği değil mevcut iki provider pipeline konfigürasyonunun karşılaştırmasıdır. 50 kural tek seed ve tek run ile seçildi; 52 bin kurala kesin genelleme veya istatistiksel anlamlılık iddiası yapılmadı. 16 audited kaydın önceki expected etiketleri bu tercih kararlarında hakem olarak kullanılmadı.
