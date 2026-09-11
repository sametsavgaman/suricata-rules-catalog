import { createContext, useContext, useEffect, useMemo, useState } from "react";

export type Locale = "en" | "tr";

const translations: Record<Locale, Record<string, string>> = {
  en: {},
  tr: {
    "Detection Catalog": "Detection Kataloğu",
    Families: "Aileler",
    Rules: "Kurallar",
    "Model Lab": "Model Laboratuvarı",
    Docs: "Dokümantasyon",
    "Total Rules": "Toplam Kural",
    "Detection Families": "Tespit Aileleri",
    "Rules with MITRE": "MITRE Eşlemeli Kurallar",
    Candidates: "Adaylar",
    "Product planning queue": "Ürün planlama kuyruğu",
    "Unique imported rules": "İçe aktarılan benzersiz kurallar",
    "Explainable rule groupings": "Açıklanabilir kural grupları",
    "Unique latest classifications": "Benzersiz güncel sınıflandırmalar",
    "Loading catalog counts…": "Katalog sayıları yükleniyor…",
    "Rules by Category": "Kategoriye Göre Kurallar",
    "MITRE Tactics": "MITRE Taktikleri",
    "classification branches": "sınıflandırma dalları",
    "evidence pathways": "kanıt yolları",
    "Start with the catalog table": "Katalog tablosundan başlayın",
    "Open Rule Explorer →": "Kural Gezgini'ni Aç →",
    Classified: "Sınıflandırıldı",
    Review: "İnceleme",
    Failed: "Başarısız",
    "Review Required": "İnceleme Gerekli",
    "MITRE Mapped": "MITRE Eşlemeli",
    "Product Candidates": "Ürün Adayları",
    Unclassified: "Sınıflandırılmamış",
    EN: "EN",
    TR: "TR",
    "Catalog Intelligence": "Katalog Zekâsı",
    "Let’s find the right rule together.": "Doğru kuralı birlikte bulalım.",
    "Ask about a category, behavior, or MITRE technique to retrieve relevant catalog records and their sources.":
      "İlgili katalog kayıtlarını ve kaynaklarını bulmak için kategori, davranış veya MITRE tekniği hakkında sorun.",
    "Gemini-powered search": "Gemini destekli arama",
    "Ask the catalog": "Kataloga sor",
    "Example: List rules in the C2 category that use DNS…":
      "Örnek: DNS kullanan C2 kategorisindeki kuralları listele…",
    "Only your question is sent to Gemini. Each question is independent.":
      "Gemini'ye yalnızca sorunuz gönderilir. Her soru bağımsızdır.",
    "Processing…": "İşleniyor…",
    "Search catalog": "Katalogda ara",
    "Interpreting your question and searching the catalog…":
      "Sorunuz yorumlanıyor ve katalog aranıyor…",
    "Loading records…": "Kayıtlar yükleniyor…",
    "How does this assistant work?": "Bu asistan nasıl çalışır?",
    "← Previous": "← Önceki",
    "Next →": "Sonraki →",
    Clear: "Temizle",
    "Applied filters": "Uygulanan filtreler",
    "All catalog records": "Tüm katalog kayıtları",
    "Catalog search results": "Katalog arama sonuçları",
    "Rule / source": "Kural / kaynak",
    Classification: "Sınıflandırma",
    "MITRE / Entity": "MITRE / Varlık",
    "Product status": "Ürün durumu",
    "Filters are combined with AND semantics. Counts are not suitability or accuracy scores.":
      "Filtreler AND mantığıyla birleştirilir. Sayılar uygunluk veya doğruluk skoru değildir.",
    "No records match these conditions. Try a broader category or fewer filters.":
      "Bu koşullarla eşleşen kayıt yok. Daha geniş bir kategori veya daha az filtre deneyin.",
    "Detection family": "Tespit ailesi",
    Category: "Kategori",
    Subcategory: "Alt kategori",
    Entity: "Varlık",
    Tactic: "Taktik",
    Protocol: "Protokol",
    "Model provider": "Model sağlayıcı",
    Keyword: "Anahtar kelime",
    "Candidate Workspace": "Aday Çalışma Alanı",
    "PRODUCT PLANNING": "ÜRÜN PLANLAMA",
    "Browse catalog": "Kataloğa göz at",
    "Loading product queue…": "Ürün kuyruğu yükleniyor…",
    "No rules in this product queue yet.":
      "Bu ürün kuyruğunda henüz kural yok.",
    "No message": "Mesaj yok",
    "No entity": "Varlık yok",
    "MODEL OPERATIONS": "MODEL OPERASYONLARI",
    "Model Control Center": "Model Kontrol Merkezi",
    "Select challengers and compare them against the immutable Qwen reference.":
      "Karşılaştırma modellerini seçin ve değiştirilemez Qwen referansıyla karşılaştırın.",
    "Refresh services": "Servisleri yenile",
    Model: "Model",
    "Base URL": "Temel URL",
    Active: "Aktif",
    "Checking…": "Kontrol ediliyor…",
    Unavailable: "Kullanılamıyor",
    Configured: "Yapılandırıldı",
    "Not configured": "Yapılandırılmadı",
    "Default comparison challenger · API":
      "Varsayılan karşılaştırma modeli · API",
    "Immutable baseline. The model name cannot be changed.":
      "Değiştirilemez temel. Model adı değiştirilemez.",
    "Saving…": "Kaydediliyor…",
    "Save & Use for Classification": "Kaydet ve Sınıflandırmada Kullan",
    "Test Connection": "Bağlantıyı Test Et",
    "Test Local Model": "Yerel Modeli Test Et",
    "Choose your challengers": "Karşılaştırma modellerinizi seçin",
    "Run Comparison": "Karşılaştırmayı Çalıştır",
    "Running comparison…": "Karşılaştırma çalışıyor…",
    "Find Rule": "Kural Bul",
    "Search SID or message": "SID veya mesaj ara",
    "Which result is better?": "Hangi sonuç daha iyi?",
    Unsure: "Emin değilim",
    "Both acceptable": "İkisi de kabul edilebilir",
    Neither: "Hiçbiri",
    "Optional comparison note": "İsteğe bağlı karşılaştırma notu",
    "Save Comparison Review": "Karşılaştırma İncelemesini Kaydet",
    "Provider result unavailable.": "Sağlayıcı sonucu kullanılamıyor.",
    "rules found": "kural bulundu",
    "unknown source": "bilinmeyen kaynak",
    "Loading Model Lab…": "Model Laboratuvarı yükleniyor…",
    "Rule Explorer": "Kural Gezgini",
    Classifier: "Sınıflandırıcı",
    "Qwen3 8B is always included. Select one or more configured models before running the comparison.":
      "Qwen3 8B her zaman dahil edilir. Karşılaştırmayı çalıştırmadan önce yapılandırılmış modelleri seçin.",
    "READY TO COMPARE": "KARŞILAŞTIRMAYA HAZIR",
    "Every model receives the same canonical rule context.":
      "Her model aynı kanonik kural bağlamını alır",
    UNAVAILABLE: "KULLANILAMIYOR",
    "PLATFORM GUIDE": "PLATFORM REHBERİ",
    "CATALOG RESPONSE": "KATALOG YANITI",
    records: "kayıt",
    "Source unavailable": "Kaynak kullanılamıyor",
    "Model unavailable": "Model kullanılamıyor",
    "Not classified yet": "Henüz sınıflandırılmadı",
    "No message available": "Mesaj mevcut değil",
    Unassigned: "Atanmamış",
    "MITRE unassigned": "MITRE atanmamış",
    "Entity unassigned": "Varlık atanmamış",
    "Gemini converts your question into a constrained filter plan. The backend validates that plan and searches the catalog. Records, approvals, and model results are never changed. Review the signature and its behavior in your own network before making product decisions. Changing pages does not trigger another Gemini call.":
      "Gemini sorunuzu kısıtlı bir filtre planına dönüştürür. Backend bu planı doğrular ve kataloğu arar. Kayıtlar, onaylar ve model sonuçları değiştirilmez. Ürün kararı vermeden önce imzayı ve davranışını kendi ağınızda inceleyin. Sayfa değiştirmek yeni bir Gemini çağrısı başlatmaz.",
    "All categories": "Tüm kategoriler",
    "All statuses": "Tüm durumlar",
    "Manual review: any": "Manuel inceleme: tümü",
    "Entity: any": "Varlık: tümü",
    "MITRE: any": "MITRE: tümü",
    "Model: any": "Model: tümü",
    "Provider: any": "Sağlayıcı: tümü",
    "Classifier: any": "Sınıflandırıcı: tümü",
    "Inference: any": "Çıkarım: tümü",
    "Product status: any": "Ürün durumu: tümü",
    "Newest SID": "En yeni SID",
    "Oldest SID": "En eski SID",
    "Recently classified": "Son sınıflandırılan",
    "Search rules": "Kurallarda ara",
    "Search SID, rule, entity, MITRE…": "SID, kural, varlık, MITRE ara…",
    "No filters applied": "Filtre uygulanmadı",
    "active filters": "aktif filtre",
    CSV: "CSV",
    "PDF / Print": "PDF / Yazdır",
    Message: "Mesaj",
    Behavior: "Davranış",
    "Decision checks": "Karar kontrolleri",
    Status: "Durum",
    "No rules match the current filters.":
      "Mevcut filtrelerle eşleşen kural yok.",
    "Not assigned": "Atanmadı",
    "Detection families": "Tespit aileleri",
    "Classification pending": "Sınıflandırma bekliyor",
    "Review save failed": "İnceleme kaydedilemedi",
    "Classification failed": "Sınıflandırma başarısız",
    "Original Suricata Rule": "Orijinal Suricata Kuralları",
    "AI Classification": "AI'ın Sınıflandırması",
    "MITRE Provenance": "MITRE Kökeni",
    "System Decision": "Sistem Kararı",
    "Model explanation:": "Model açıklaması:",
    "Decision Evidence": "Karar Kanıtı",
    "Validation issues": "Doğrulama sorunları",
    "Consistency warnings": "Tutarlılık uyarıları",
    "Classify rule": "Kuralı sınıflandır",
    Reclassify: "Yeniden sınıflandır",
    "Export CSV": "Dışa aktar",
    "Export PDF": "PDF yazdır",
    Copy: "Kopyala",
    "Copy JSON": "JSON kopyala",
    "Run classification with": "Sınıflandırmayı şununla çalıştır",
    "Configured default": "Yapılandırılmış varsayılan",
    "This rule has not been classified.": "Bu kural sınıflandırılmadı.",
    "Classification accepted by validator":
      "Sınıflandırma doğrulama kontrolünden geçti",
    "Classification decision recorded": "Sınıflandırma kararı kaydedildi",
    "No mapping provenance recorded.": "Eşleme kökeni kaydedilmedi.",
    "No supported mapping": "Desteklenen eşleme yok",
    "Not available": "Mevcut değil",
    "Human review": "İnsan incelemesi",
    "Semantic check": "Anlamsal kontrol",
    Validator: "Validator",
    "Field decisions": "Alan kararları",
    "All entity types": "Tüm varlık türleri",
    "Inspection batch: any": "İnceleme batch'i: tümü",
    "MITRE provenance: any": "MITRE kökeni: tümü",
    "All protocols": "Tüm protokoller",
    "All MITRE tactics": "Tüm MITRE taktikleri",
    "Family category": "Aile kategorisi",
    "Family protocol": "Aile protokolü",
    "Family product status": "Aile ürün durumu",
    "Has entity": "Varlık var",
    "Null entity": "Varlık yok",
    "Has MITRE": "MITRE var",
    "Null MITRE": "MITRE yok",
    "Exact source": "Tam kaynak eşlemesi",
    "Derived sub-technique": "Türetilmiş alt teknik",
    Inferred: "Çıkarılmış",
    "Source overridden": "Kaynak geçersiz kılındı",
    "No mapping": "Eşleme yok",
    "Not evaluated": "Değerlendirilmedi",
    Candidate: "Aday",
    Approved: "Onaylandı",
    Rejected: "Reddedildi",
    Integrated: "Entegre edildi",
    "List the AnyDesk rules": "AnyDesk kurallarını listele",
    "How many AnyDesk rules are there?": "Kaç tane AnyDesk kuralı var?",
    "Show detection families related to T1219":
      "T1219 ile ilişkili detection ailelerini göster",
    "Show families related to DNS tunneling":
      "DNS tünellemesiyle ilişkili aileleri göster",
    "▣ PDF / Print": "▣ PDF yazdır",
    "↓ CSV": "↓ CSV",
    "← Prev": "← Önceki",
    "Classifying…": "Sınıflandırılıyor…",
    Return: "Geri dön",
    Cancel: "İptal",
    "Save Changes": "Değişiklikleri kaydet",
    Edit: "Düzenle",
    "Needs Review": "İnceleme gerekli",
    "✓ Mark Reviewed / Approve": "✓ İncelendi olarak işaretle / Onayla",
    "Add to Candidate": "Adaylara ekle",
    "Approve for Product": "Ürün için onayla",
    "Reject for Product": "Ürün için reddet",
    "Already Integrated": "Zaten entegre",
    "Product Planning": "Ürün Planlama",
    "Manual Review": "Manuel İnceleme",
    "Audit Log": "İşlem Günlüğü",
    "Review activity and corrections without user identity.": "Kullanıcı kimliği göstermeden inceleme ve düzeltme etkinliklerini görüntüleyin.",
    "Review and correction history": "İnceleme ve düzeltme geçmişi",
    "This log records when an action happened and what changed. It does not identify the operator.": "Bu günlük işlemin ne zaman yapıldığını ve neyin değiştiğini kaydeder; işlemi yapan kişiyi tanımlamaz.",
    "TRACEABLE CHANGES": "İZLENEBİLİR DEĞİŞİKLİKLER",
    "All actions": "Tüm işlemler",
    "Manual review": "Manuel inceleme",
    "Field correction": "Alan düzeltmesi",
    "Product decision": "Ürün kararı",
    "From date": "Başlangıç tarihi",
    "To date": "Bitiş tarihi",
    Time: "Zaman",
    Action: "İşlem",
    Field: "Alan",
    Change: "Değişiklik",
    Note: "Not",
    "No audit events yet.": "Henüz günlük kaydı yok.",
    Previous: "Önceki",
    Next: "Sonraki",
    "Loading audit log…": "İşlem günlüğü yükleniyor…",
    "Audit log could not be loaded": "İşlem günlüğü yüklenemedi",
    "Manually reviewed and approved": "Manuel olarak incelendi ve onaylandı",
    "Human review requested": "İnsan incelemesi istendi",
    "This rule is currently used in the product": "Bu kural şu anda üründe kullanılmaktadır",
    "It is marked as already integrated in the product catalogue.": "Ürün kataloğunda zaten entegre olarak işaretlenmiştir.",
    "Technical Details": "Teknik Ayrıntılar",
    "Parser output and agent trace are available for diagnostics.": "Tanılama için ayrıştırıcı çıktısı ve agent izi kullanılabilir.",
    "Parser Output": "Ayrıştırıcı Çıktısı",
    "Agent Trace": "Agent İzi",
    "This is the deterministic parser output extracted from the original Suricata rule. The classifier receives this data plus enrichment context.": "Bu, özgün Suricata kuralından çıkarılan deterministik ayrıştırıcı çıktısıdır. Sınıflandırıcı bu veriyi zenginleştirme bağlamıyla birlikte alır.",
    "This is an operational trace of enrichment tools, evidence gates, abstention decisions, MITRE provenance and validator results. It is not the raw model response.": "Bu, zenginleştirme araçlarının, kanıt eşiklerinin, çekimserlik kararlarının, MITRE kökeninin ve doğrulayıcı sonuçlarının operasyonel izidir. Ham model yanıtı değildir.",
    "After inspecting the rule, approve it when the classification is correct. Use Correct classification when a field is wrong.": "Kuralı inceledikten sonra sınıflandırma doğruysa onaylayın. Bir alan yanlışsa Sınıflandırmayı düzelt seçeneğini kullanın.",
    "✓ Mark inspected and approve": "✓ İncelendi ve onaylandı olarak işaretle",
    "Correct classification": "Sınıflandırmayı düzelt",
    "Save correction": "Düzeltmeyi kaydet",
    "Correction save failed": "Düzeltme kaydedilemedi",
    "Change at least one field before saving": "Kaydetmeden önce en az bir alanı değiştirin",
    "The original model output remains preserved; only the displayed decision is overridden.": "Özgün model çıktısı korunur; yalnızca ekranda gösterilen karar geçersiz kılınır.",
    "Open audit log": "İşlem günlüğünü aç",
    "detected behavior": "tespit edilen davranış",
    "detected entity": "tespit edilen varlık",
    "entity type": "varlık türü",
    category: "kategori",
    subcategory: "alt kategori",
    "mitre tactic": "MITRE taktiği",
    "mitre technique": "MITRE tekniği",
    "mitre technique id": "MITRE ID",
    "cyber kill chain phase": "öldürme zinciri aşaması",
    "Parsed Input": "Ayrıştırılmış Girdi",
    "Agent Activity": "Agent Etkinliği",
    "Rule Review History": "Kural İnceleme Geçmişi",
    "Product history": "Ürün geçmişi",
    "Current status:": "Mevcut durum:",
    "NOT CLASSIFIED": "SINIFLANDIRILMADI",
    UNREVIEWED: "İNCELENMEDİ",
    NOT_EVALUATED: "DEĞERLENDİRİLMEDİ",
    "Manual review is complete when you approve or reject this classification.":
      "Bu sınıflandırmayı onayladığınızda veya reddettiğinizde manuel inceleme tamamlanır.",
    "keeps it open for later verification.":
      "daha sonra doğrulama için açık tutar.",
    Reject: "Reddet",
    "Optional note (required for Reject)":
      "İsteğe bağlı not (Reddet için gerekli)",
    "Edit the displayed classification fields.":
      "Gösterilen sınıflandırma alanlarını düzenleyin.",
    "A reason is required and the original model output remains preserved.":
      "Gerekçe zorunludur ve özgün model çıktısı korunur.",
    "Reason for edit (required)": "Düzenleme gerekçesi (zorunlu)",
    "This rule has no successful AI classification yet, so there is nothing to review.":
      "Bu kuralın henüz başarılı bir AI sınıflandırması yok; incelenecek bir sonuç bulunmuyor.",
    "Product status:": "Ürün durumu:",
    "This is separate from AI classification review: it records whether the rule belongs in the NDR product.":
      "Bu alan AI sınıflandırma incelemesinden ayrıdır; kuralın NDR ürününe dahil olup olmadığını kaydeder.",
    "Product planning note": "Ürün planlama notu",
    "Technique coverage, with evidence.": "Kanıtlarıyla teknik kapsamı.",
    "Mapped rules": "Eşlenmiş kurallar",
    "Unmapped rules": "Eşlenmemiş kurallar",
    Techniques: "Teknikler",
    "Sub-techniques": "Alt teknikler",
    Tactics: "Taktikler",
    "Mapped families": "Eşlenmiş aileler",
    "TACTIC LENS": "TAKTİK GÖRÜNÜMÜ",
    "ATT&CK tactics": "ATT&CK taktikleri",
    "All tactics": "Tüm taktikler",
    rules: "kural",
    families: "aile",
    "Represented techniques": "Temsil edilen teknikler",
    "canonical IDs represented in the current filter.":
      "Mevcut filtrede temsil edilen kanonik ID.",
    "Search techniques": "Tekniklerde ara",
    "All levels": "Tüm seviyeler",
    "Technique level": "Teknik seviyesi",
    Loading: "Yükleniyor",
    mapped: "eşlenmiş",
    unmapped: "eşlenmemiş",
    "mapped ·": "eşlenmiş ·",
    "unmapped family rules": "eşlenmemiş aile kuralı",
    "catalog rules": "katalog kuralı",
    Categories: "Kategoriler",
    Protocols: "Protokoller",
    "ATT&CK relationships": "ATT&CK ilişkileri",
    "Catalog profile": "Katalog profili",
    "Related Detection Families": "İlişkili Tespit Aileleri",
    "Browse filtered families →": "Filtrelenmiş ailelere göz at →",
    "Rules mapped to": "Şuna eşlenen kurallar:",
    "UNDERLYING SIGNATURES": "TEMEL İMZALAR",
    "Family unassigned": "Aile atanmamış",
    "VIEW RULE ↗": "KURALI GÖRÜNTÜLE ↗",
    "No canonical sub-techniques.": "Kanonik alt teknik yok.",
    "No Detection Family is currently associated with mapped rules.":
      "Eşlenmiş kurallarla ilişkili tespit ailesi yok.",
    Coverage: "Kapsam",
    Compare: "Karşılaştır",
    "Rule Packs": "Kural Paketleri",
    "Rule pack": "Kural paketi",
    "Existing Rules": "Mevcut Kurallar",
    "Existing rules, clearly accounted for.":
      "Mevcut kurallar, net biçimde kayıt altında.",
    "Map your product ruleset.": "Ürün kural setinizi eşleyin.",
    "Upload the Suricata rules currently deployed in your cybersecurity product. Existing catalogue classifications are reused; only new or unclassified rules are sent to Gemini.":
      "Siber güvenlik ürününüzde hâlihazırda çalışan Suricata kurallarını yükleyin. Mevcut katalog sınıflandırmaları yeniden kullanılır; yalnızca yeni veya sınıflandırılmamış kurallar Gemini'ye gönderilir.",
    "Product ruleset workspace": "Ürün kural seti çalışma alanı",
    "IMPORT PRODUCT BASELINE": "ÜRÜN TABANINI İÇE AKTAR",
    "Upload your current ruleset": "Mevcut kural setinizi yükleyin",
    "Drop .rules files here": ".rules dosyalarını buraya bırakın",
    "or choose files · up to 25 MB each": "veya dosya seçin · dosya başına en fazla 25 MB",
    "Parsing ruleset…": "Kural seti parse ediliyor…",
    Selected: "Seçilen",
    "Choose different files": "Dosyaları değiştir",
    "Ruleset could not be inspected.": "Kural seti incelenemedi.",
    "Ruleset could not be imported.": "Kural seti içe aktarılamadı.",
    "Ready to establish baseline": "Ürün tabanı oluşturulmaya hazır",
    "rules parsed": "kural parse edildi",
    "Exact catalogue match": "Tam katalog eşleşmesi",
    "New catalogue record": "Yeni katalog kaydı",
    "Same SID, new revision": "Aynı SID, yeni revizyon",
    "Parse error": "Parse hatası",
    "New rules and revisions will be added to the catalogue. Every successfully parsed rule will be marked Already Integrated with its source filename.":
      "Yeni kurallar ve revizyonlar kataloğa eklenecek. Başarıyla parse edilen her kural, kaynak dosya adıyla Zaten Entegre olarak işaretlenecek.",
    "Import & mark as existing": "İçe aktar ve mevcut olarak işaretle",
    "Establishing baseline…": "Ürün tabanı oluşturuluyor…",
    "Product baseline updated": "Ürün tabanı güncellendi",
    "Existing Qwen classifications will be reused": "Mevcut Qwen sınıflandırmaları yeniden kullanılacak",
    "New or unclassified rules will use Gemini": "Yeni veya sınıflandırılmamış kurallar Gemini kullanacak",
    "I understand that parsed fields from these new rules will be sent to the configured Gemini API for classification. Existing Qwen results will not be changed.":
      "Bu yeni kuralların parse edilen alanlarının sınıflandırma için yapılandırılmış Gemini API'ye gönderileceğini anlıyorum. Mevcut Qwen sonuçları değiştirilmeyecek.",
    "Import & classify new rules": "İçe aktar ve yeni kuralları sınıflandır",
    "Import & reuse classifications": "İçe aktar ve sınıflandırmaları kullan",
    "rules marked existing": "kural mevcut olarak işaretlendi",
    "Qwen results reused": "Qwen sonucu yeniden kullanıldı",
    "queued for Gemini": "Gemini kuyruğuna alındı",
    "new catalogue records": "yeni katalog kaydı",
    "already in baseline": "zaten ürün tabanında",
    "GEMINI IMPORT CLASSIFICATION": "GEMINI İÇE AKTARIM SINIFLANDIRMASI",
    "Classification completed": "Sınıflandırma tamamlandı",
    "Classifying new rules…": "Yeni kurallar sınıflandırılıyor…",
    "Waiting to classify…": "Sınıflandırma bekleniyor…",
    "Classification needs attention": "Sınıflandırma işlem gerektiriyor",
    "Auto-classified": "Otomatik sınıflandırıldı",
    "Retry Gemini classification": "Gemini sınıflandırmasını yeniden dene",
    "Configure Gemini in Model Lab": "Gemini'yi Model Laboratuvarı'nda yapılandır",
    "Gemini classification could not be retried.": "Gemini sınıflandırması yeniden başlatılamadı.",
    "Baseline was imported, but classification progress could not be loaded.": "Ürün tabanı içe aktarıldı ancak sınıflandırma ilerlemesi yüklenemedi.",
    GEMINI_API_KEY_NOT_CONFIGURED: "Gemini API anahtarı yapılandırılmamış.",
    GEMINI_MODEL_NOT_CONFIGURED: "Gemini modeli yapılandırılmamış.",
    "SEARCH PRODUCT COVERAGE": "ÜRÜN KAPSAMINDA ARA",
    "Find an existing detection": "Mevcut bir tespiti bulun",
    "Search the product baseline": "Ürün tabanında ara",
    "Enter SID, rule message, entity or MITRE technique…": "SID, kural mesajı, varlık veya MITRE tekniği girin…",
    "Clear search": "Aramayı temizle",
    "Showing product rules matching": "Şununla eşleşen ürün kuralları gösteriliyor:",
    "Search only within rules confirmed as present in the product.": "Yalnızca üründe bulunduğu doğrulanmış kurallar içinde arama yapın.",
    "Upload the product ruleset above, or mark a rule as Already Integrated from its decision panel.":
      "Yukarıdan ürün kural setini yükleyin veya bir kuralı karar panelinden Zaten Entegre olarak işaretleyin.",
    "PRODUCT BASELINE · NDR CATALOGUE": "ÜRÜN TABANI · NDR KATALOĞU",
    "Rules marked ": "İşaretli kurallar ",
    "in the product decision ledger are collected here as the current NDR baseline. Use this view to verify coverage before adding new content.":
      "ürün karar defterinde mevcut NDR tabanı olarak burada toplanır. Yeni içerik eklemeden önce kapsamı doğrulamak için bu görünümü kullanın.",
    "Integrated in product": "Ürüne entegre",
    "Matching current filter": "Geçerli filtreyle eşleşen",
    "With classification": "Sınıflandırılmış",
    "MITRE mapped on page": "Sayfada MITRE eşlemeli",
    "INTEGRATED CONTENT REGISTER": "ENTEGRE İÇERİK KAYDI",
    "Current NDR rule set": "Mevcut NDR kural seti",
    "integrated records": "entegre kayıt",
    page: "sayfa",
    "Search existing rules": "Mevcut kurallarda ara",
    "Search SID, message, MITRE…": "SID, mesaj, MITRE ara…",
    "Loading existing rules…": "Mevcut kurallar yükleniyor…",
    "No integrated rules match the current search.":
      "Aramayla eşleşen entegre kural yok.",
    "No rules are marked as existing yet.":
      "Henüz mevcut olarak işaretlenmiş kural yok.",
    "Mark a rule as Already Integrated from its product decision panel; it will appear here automatically.":
      "Bir kuralı ürün karar panelinden Zaten Entegre olarak işaretleyin; otomatik olarak burada görünür.",
    "Try a broader search or clear the filter.":
      "Daha geniş bir arama deneyin veya filtreyi temizleyin.",
    "Open Rules to review product decisions →":
      "Ürün kararlarını incelemek için Kuralları açın →",
    "No entity assigned": "Varlık atanmamış",
    "ALREADY INTEGRATED": "ZATEN ENTEGRE",
    "Open rule details": "Kural detayını aç",
    "Remove from product": "Üründen çıkar",
    "PRODUCT BASELINE CHANGE": "ÜRÜN TABANI DEĞİŞİKLİĞİ",
    "Remove this rule from the product?": "Bu kural üründen çıkarılsın mı?",
    "This removes the rule from the current NDR baseline. Its catalogue record, classification and history will be kept.":
      "Bu işlem kuralı mevcut NDR tabanından çıkarır. Katalog kaydı, sınıflandırması ve geçmişi korunur.",
    "Removing…": "Çıkarılıyor…",
    "Rule removed from the product baseline. Its catalogue record and classification were kept.":
      "Kural ürün tabanından çıkarıldı. Katalog kaydı ve sınıflandırması korundu.",
    "Rule could not be removed from the product baseline.": "Kural ürün tabanından çıkarılamadı.",
    "MITRE COVERAGE · GAP ANALYSIS": "MITRE KAPSAMI · BOŞLUK ANALİZİ",
    "See what the catalogue maps — and what it does not.":
      "Kataloğun neleri eşlediğini ve neleri eşlemediğini görün.",
    "Coverage is measured against the local ATT&CK repository. It describes catalogue mappings, not validated detection coverage in a deployed NDR sensor.":
      "Kapsam yerel ATT&CK deposuna göre ölçülür. Bu değer, çalışan bir NDR sensöründe doğrulanmış tespit kapsamını değil katalog eşlemelerini gösterir.",
    "Catalogue coverage": "Katalog kapsamı",
    "Technique gaps": "Teknik boşlukları",
    "ATT&CK repository": "ATT&CK deposu",
    "Tactic coverage": "Taktik kapsamı",
    "Unrepresented techniques": "Temsil edilmeyen teknikler",
    "Search T1059 or technique name": "T1059 veya teknik adı ara",
    "Clear filters": "Filtreleri temizle",
    "No tactic": "Taktik yok",
    "Showing the first 150 gaps. Refine the filters to narrow the list.":
      "İlk 150 boşluk gösteriliyor. Listeyi daraltmak için filtreleri kullanın.",
    "RULE COMPARISON": "KURAL KARŞILAŞTIRMASI",
    "RULE COMPARISON · EVIDENCE DESK": "KURAL KARŞILAŞTIRMASI · KANIT MASASI",
    "Compare rules by evidence, not guesswork.":
      "Kuralları tahminle değil, kanıtla karşılaştırın.",
    "Build a set from any rule row or family profile, then inspect detection behavior, MITRE provenance, validation and product readiness side by side.":
      "Herhangi bir kural satırından veya aile profilinden bir set oluşturun; tespit davranışını, MITRE kökenini, doğrulamayı ve ürün hazırlığını yan yana inceleyin.",
    "COMPARISON SET": "KARŞILAŞTIRMA SETİ",
    "Assemble your evidence desk": "Kanıt masanızı oluşturun",
    "Use the Compare action on a rule to prefill one slot, then add one to three peers.":
      "Bir kuraldaki Karşılaştır aksiyonuyla ilk alanı doldurun, ardından bir ila üç eş kural ekleyin.",
    "Add another rule": "Başka kural ekle",
    "Loading evidence…": "Kanıt yükleniyor…",
    "Compare selected rules": "Seçili kuralları karşılaştır",
    "Browse Rule Explorer →": "Kural Gezgini'ne göz at →",
    "Recent sets": "Son setler",
    "HOW TO USE THIS VIEW": "BU GÖRÜNÜMÜ KULLANMA",
    "Evidence set loaded": "Kanıt seti yüklendi",
    "Start anywhere in the catalogue": "Katalogda herhangi bir yerden başlayın",
    "You no longer need to remember two SIDs before arriving here. Open Compare directly from a rule, a family, or a catalogue row.":
      "Buraya gelmeden iki SID hatırlamanız gerekmez. Karşılaştırmayı doğrudan bir kuraldan, bir aileden veya katalog satırından açın.",
    "Each card is the same rule contract, so differences stay visible and reviewable.":
      "Her kart aynı kural sözleşmesini kullanır; böylece farklar görünür ve incelenebilir kalır.",
    "Open a rule and choose ": "Bir kuralı açın ve ",
    "Add a peer from the same family or tactic.":
      "Aynı aile veya taktikten bir eş kural ekleyin.",
    "Review evidence, then add the right rule to a pack.":
      "Kanıtı inceleyin, ardından doğru kuralı pakete ekleyin.",
    "Explore detection families ↗": "Tespit ailelerini keşfedin ↗",
    "+ Add rule": "+ Kural ekle",
    "Compare rules": "Kuralları karşılaştır",
    "Loading…": "Yükleniyor…",
    "Open ↗": "Aç ↗",
    Family: "Aile",
    "MITRE evidence": "MITRE kanıtı",
    Unmapped: "Eşlenmemiş",
    "Untitled rule": "Adsız kural",
    "Not classified": "Sınıflandırılmadı",
    "Enter at least two SIDs.": "En az iki SID girin.",
    "Rules could not be loaded": "Kurallar yüklenemedi",
    "+ Add to Rule Pack": "+ Kural Paketine Ekle",
    "Choose a rule pack": "Bir kural paketi seçin",
    "Add to selected pack": "Seçili pakete ekle",
    "No rule packs yet. Create the first one below.":
      "Henüz kural paketi yok. İlk paketi aşağıdan oluşturun.",
    "New pack name": "Yeni paket adı",
    "Create + add": "Oluştur ve ekle",
    "Rule added.": "Kural eklendi.",
    "Pack created and rule added.": "Paket oluşturuldu ve kural eklendi.",
    "RULE PACK BUILDER": "KURAL PAKETİ OLUŞTURUCU",
    "Build and manage multiple rule packs.":
      "Birden fazla kural paketi oluşturun ve yönetin.",
    "Keep separate packs for different products, environments or deployment decisions, then export the currently selected pack.":
      "Farklı ürünler, ortamlar veya dağıtım kararları için ayrı paketler tutun; ardından seçili paketi dışa aktarın.",
    "Your rule packs": "Kural paketleriniz",
    "Create pack": "Paket oluştur",
    "Selected pack name": "Seçili paket adı",
    "Add SID": "SID ekle",
    Add: "Ekle",
    "Download .rules": ".rules indir",
    "Download manifest": "Manifest indir",
    "Select or create a pack": "Bir paket seçin veya oluşturun",
    "Selected rules": "Seçili kurallar",
    Remove: "Kaldır",
    "No rules in this pack.": "Bu pakette kural yok.",
    "Use “Add to Rule Pack” on any rule row, or enter a SID here.":
      "Herhangi bir kural satırında “Kural Paketine Ekle” seçeneğini kullanın veya buraya bir SID girin.",
    "RULE DECISION CARD": "KURAL KARAR KARTI",
    "In product": "Üründe mevcut",
    "Mark existing": "Mevcut olarak işaretle",
    "NEXT ACTION": "SONRAKİ ADIM",
    REVIEWED: "İNCELENDİ",
    EVALUATE: "DEĞERLENDİR",
    "Compare this rule": "Bu kuralı karşılaştır",
    "Open pack builder": "Paket oluşturucuyu aç",
    Detection: "Tespit",
    "Readiness uses recorded evidence and review state. Performance and false-positive behavior have not been measured.":
      "Hazır olma durumu kayıtlı kanıt ve inceleme durumuna dayanır. Performans ve yanlış pozitif davranışı ölçülmemiştir.",
    "Classify before product review": "Ürün incelemesinden önce sınıflandırın",
    "Evidence review required": "Kanıt incelemesi gerekli",
    "Candidate for human review": "İnsan incelemesi adayı",
    "Approved catalogue selection": "Onaylı katalog seçimi",
    "Ready for product evaluation": "Ürün değerlendirmesine hazır",
    "Run classification and inspect parsed evidence.":
      "Sınıflandırmayı çalıştırın ve ayrıştırılmış kanıtı inceleyin.",
    "Resolve validator warnings before selection.":
      "Seçimden önce doğrulayıcı uyarılarını giderin.",
    "Complete Manual Review before deployment consideration.":
      "Dağıtımı değerlendirmeden önce manuel incelemeyi tamamlayın.",
    "Compare alternatives and add this rule to a reviewed pack.":
      "Alternatifleri karşılaştırın ve bu kuralı incelenmiş bir pakete ekleyin.",
    "Turn a missed attack into an actionable rule plan.":
      "Kaçırılan bir saldırıyı uygulanabilir bir kural planına dönüştürün.",
    "Describe what the customer or red team did. The workspace maps the scenario to catalog evidence, surfaces coverage gaps and recommends rules for a reviewable pack.":
      "Müşterinin veya red teamin ne yaptığını açıklayın. Çalışma alanı senaryoyu katalog kanıtlarıyla eşler, kapsam boşluklarını gösterir ve incelenebilir bir paket için kural önerir.",
    "Gemini-assisted mapping · local catalogue results":
      "Gemini destekli eşleme · yerel katalog sonuçları",
    "Gemini plan · local evidence": "Gemini planı · yerel kanıt",
    "Detection Readiness": "Tespit Hazırlığı",
    "DETECTION READINESS": "TESPİT HAZIRLIĞI",
    "Customer scenario": "Müşteri senaryosu",
    "Assess detection readiness": "Tespit hazırlığını değerlendir",
    "Attack path": "Saldırı yolu",
    "Verified behavioral checkpoints": "Doğrulanmış davranış kontrol noktaları",
    "Behavioral checkpoints": "Davranış kontrol noktaları",
    "Recommended rules": "Önerilen kurallar",
    "Rules to investigate and add to a pack":
      "İncelenecek ve pakete eklenecek kurallar",
    "verified candidates": "doğrulanmış aday",
    "signals extracted": "çıkarılan sinyal",
    "coverage status": "kapsam durumu",
    COVERED: "KAPSANDI",
    PARTIAL: "KISMİ",
    GAP: "BOŞLUK",
    "COVERED detection readiness": "Kapsama hazır",
    "PARTIAL detection readiness": "Kısmi kapsama",
    "GAP detection readiness": "Kapsama boşluğu",
    Assumptions: "Varsayımlar",
    "COVERAGE MATRIX": "KAPSAM MATRİSİ",
    "What the local catalogue can support":
      "Yerel kataloğun destekleyebildiği alanlar",
    "Coverage is computed from verified local mappings and evidence, not from Gemini claims.":
      "Kapsam, Gemini iddialarından değil doğrulanmış yerel eşlemeler ve kanıtlardan hesaplanır.",
    "Every recommendation includes the local evidence used for its match.":
      "Her öneri, eşleşmede kullanılan yerel kanıtı içerir.",
    "Catalog evidence found": "Katalog kanıtı bulundu",
    "Needs analyst clarification": "Analist açıklaması gerekiyor",
    REVIEW: "İNCELEME",
    "No verified local candidates were found. Review the GAP rows and refine the scenario.":
      "Doğrulanmış yerel aday bulunamadı. BOŞLUK satırlarını inceleyin ve senaryoyu ayrıntılandırın.",
    "No direct candidates were returned. Refine the scenario with a protocol, tool or MITRE technique.":
      "Doğrudan aday bulunamadı. Senaryoyu bir protokol, araç veya MITRE tekniğiyle ayrıntılandırın.",
    "These are catalog candidates, not proof of deployed detection.":
      "Bunlar katalog adaylarıdır; çalışan tespit için kanıt değildir.",
    "Coverage gap assessment": "Kapsam boşluğu değerlendirmesi",
    "Why this appears as a gap": "Neden boşluk olarak görünüyor",
    "What is known": "Bilinenler",
    "Recommended review": "Önerilen inceleme",
    "Decision boundary": "Karar sınırı",
    "Open Rule Pack Builder →": "Kural Paketi Oluşturucuyu Aç →",
  },
};

// Kept separate from the historical dictionary so newly audited UI copy can
// be reviewed and extended without rewriting the large legacy block above.
const supplementalTranslations: Record<string, string> = {
  "DETECTION CONTENT WORKSPACE": "TESPİT İÇERİĞİ ÇALIŞMA ALANI",
  "Loading categories…": "Kategoriler yükleniyor…",
  "Loading tactics…": "Taktikler yükleniyor…",
  "LIVE DATASET": "CANLI VERİ SETİ",
  "Model quick filters": "Model hızlı filtreleri",
  "Rule pack": "Kural paketi",
  "Detection Families": "Tespit Aileleri",
  "INTELLIGENT DETECTION NAVIGATION": "AKILLI TESPİT GEZGİNİ",
  "canonical family": "kanonik aile",
  "assigned rules": "atanmış kural",
  "conservative coverage": "temkinli kapsam",
  "underlying rules": "temel kural",
  "product picks": "ürün seçimi",
  "families found": "aile bulundu",
  "family found": "aile bulundu",
  "Bir rule yalnızca kanıtlı primary family içinde sayılır.":
    "Bir kural yalnızca kanıtlı birincil family içinde sayılır.",
  "Each rule is counted only within its evidence-backed primary family.":
    "Her kural yalnızca kanıt destekli birincil ailesi içinde sayılır.",
  "Preparing detection family…": "Tespit ailesi hazırlanıyor…",
  "Ask Gemini about this family": "Gemini'ye bu aileyi sor",
  "Inspect the detection surfaces, MITRE coverage and product decisions represented by this family.":
    "Bu ailedeki tespit yüzeylerini, MITRE kapsamını ve ürün kararlarını inceleyin.",
  Evidence: "Kanıt",
  "Entity types": "Varlık türleri",
  mapped: "eşlenmiş",
  "unmapped family rules": "eşlenmemiş aile kuralı",
  "Canonical aileler hazırlanıyor…": "Kanonik aileler hazırlanıyor…",
  "Eşleşen detection family bulunamadı.":
    "Eşleşen detection family bulunamadı.",
  "Filtreleri genişletin. Kanıtı olmayan kurallar kasıtlı olarak UNASSIGNED kalır.":
    "Filtreleri genişletin. Kanıtı olmayan kurallar kasıtlı olarak ATANMAMIŞ kalır.",
  "Technique yüklenemedi": "Teknik yüklenemedi",
  "Rules yüklenemedi": "Kurallar yüklenemedi",
  "MITRE kataloğuna dön": "MITRE kataloğuna dön",
  "Technique intelligence hazırlanıyor…": "Teknik zekâ hazırlanıyor…",
  "ATT&amp;CK hierarchy hazırlanıyor…": "ATT&amp;CK hiyerarşisi hazırlanıyor…",
  "CATALOG INTELLIGENCE · MITRE ATT&amp;CK":
    "KATALOG ZEKÂSI · MITRE ATT&amp;CK",
  "Explore how the Suricata catalogue maps across ATT&amp;CK. This view describes catalogue mappings; it is not a claim of validated NDR product coverage.":
    "Suricata kataloğunun ATT&amp;CK genelindeki eşlemelerini inceleyin. Bu görünüm katalog eşlemelerini açıklar; doğrulanmış NDR ürün kapsamı iddiası değildir.",
  "Open Coverage &amp; Gap Analysis →": "Kapsam ve Boşluk Analizi'ni aç →",
  "Represented techniques": "Temsil edilen teknikler",
  "canonical IDs represented in the current filter.":
    "mevcut filtrede temsil edilen kanonik ID",
  "Broaden the search or tactic filter.":
    "Aramayı veya taktik filtresini genişletin.",
  "Preparing ATT&amp;CK hierarchy…": "ATT&amp;CK hiyerarşisi hazırlanıyor…",
  "Back to MITRE catalogue": "MITRE kataloğuna dön",
  "MITRE ATT&amp;CK Intelligence": "MITRE ATT&amp;CK Zekâsı",
  "CATALOG COVERAGE": "KATALOG KAPSAMI",
  "Canonical ATT&CK description is not available in the local repository.":
    "Yerel depoda kanonik ATT&CK açıklaması bulunmuyor.",
  "Catalog rules": "Katalog kuralları",
  "Inspect the parent and sub-techniques, confirm whether the behavior creates network-visible evidence, then search existing rules for the technique name and relevant protocol artifacts before authoring or sourcing new content.":
    "Üst ve alt teknikleri inceleyin, davranışın ağ üzerinde görünür kanıt oluşturup oluşturmadığını doğrulayın; yeni içerik yazmadan veya tedarik etmeden önce mevcut kurallarda teknik adını ve ilgili protokol izlerini arayın.",
  "Do not claim coverage until a rule has explicit or validated inferred evidence. A neighboring technique or family association alone is not sufficient.":
    "Bir kural açık veya doğrulanmış çıkarımsal kanıt taşımadan kapsam iddiasında bulunmayın. Yalnızca komşu teknik veya aile ilişkisi yeterli değildir.",
  "The local ATT&CK repository identifies this technique, but no canonical description is stored.":
    "Yerel ATT&CK deposu bu tekniği tanımlıyor ancak kanonik bir açıklama saklanmıyor.",
  "Eşleşen ATT&amp;CK tekniği yok.": "Eşleşen ATT&amp;CK tekniği yok.",
  "Aramayı veya tactic filtresini genişletin.":
    "Aramayı veya taktik filtresini genişletin.",
  "Bu ailede hangi detection yüzeylerinin bulunduğunu, MITRE kapsamını ve ürün seçim durumunu inceleyin.":
    "Bu aile içindeki tespit yüzeylerini, MITRE kapsamını ve ürün kararlarını inceleyin.",
  "Rule Explorer’da aç →": "Kural Gezgini'nde aç →",
  "Gemini’ye bu aileyi sor": "Gemini'ye bu family'yi sor",
  "Evidence-backed links": "Kanıt destekli bağlantı",
  "Provenance explains why each rule belongs here. Model similarity alone never creates a family.":
    "Köken bilgisi her kuralın neden burada olduğunu açıklar. Yalnızca model benzerliği family oluşturmaz.",
  "Detections in": "Tespitler:",
  "Open MITRE Intelligence →": "MITRE İstihbaratı'nı aç →",
  "This family has no canonical MITRE mapping.":
    "Bu aile için kanonik MITRE eşlemesi yok.",
  "Bu family için canonical MITRE eşlemesi bulunmuyor.":
    "Bu aile için kanonik MITRE eşlemesi bulunmuyor.",
  "Assignment provenance": "Atama kökeni",
  "Coverage profile": "Kapsam profili",
  "UNDERLYING SIGNATURES": "TEMEL İMZALAR",
  "FAMILY → ATT&amp;CK": "FAMILY → ATT&amp;CK",
  "MITRE techniques": "MITRE teknikleri",
  "Product status: any": "Ürün durumu: tümü",
  "Family product status": "Aile ürün durumu",
  "Family protocol": "Aile protokolü",
  "Family category": "Aile kategorisi",
  "Catalog intelligence": "Katalog zekâsı",
  "Technique coverage, with evidence.": "Kanıtlarıyla teknik kapsamı.",
  "CANONICAL SOURCE": "KANONİK KAYNAK",
  "Search MITRE techniques": "MITRE tekniklerinde ara",
  "Search techniques": "Tekniklerde ara",
  "Tactic lens": "Taktik görünümü",
  "Tactic → Technique → Sub-technique": "Taktik → Teknik → Alt teknik",
  "Rules could not be loaded": "Kurallar yüklenemedi",
  "Family could not be loaded": "Aile yüklenemedi",
  "No message": "Mesaj yok",
  "source unknown": "kaynak bilinmiyor",
  "No rule message": "Kural mesajı yok",
  "Classification pending": "Sınıflandırma bekliyor",
  "Not assigned": "Atanmadı",
  "Browse rules →": "Kurallara göz at →",
  "Explore MITRE →": "MITRE'yi keşfet →",
  "Open Model Lab →": "Model Laboratuvarı'nı aç →",
  "Natural-Language Catalog Search": "Doğal Dille Katalog Araması",
  "Platform Documentation": "Platform Dokümantasyonu",
  "Bağlantıdaki classification bu güncel revizyonda bulunamadı. Aşağıda SID'nin güncel revizyonu gösteriliyor; asistan listesindeki REV ile karşılaştırın.":
    "Bağlantıdaki sınıflandırma bu güncel revizyonda bulunamadı. Aşağıda SID'nin güncel revizyonu gösteriliyor; asistan listesindeki REV ile karşılaştırın.",
  "AI SECURITY ANALYSIS PLATFORM": "YAPAY ZEKÂ GÜVENLİK ANALİZ PLATFORMU",
  "Curated deployment collections": "Seçilmiş dağıtım koleksiyonları",
  "CATALOG\nDETECTION": "KATALOG\nTESPİT",
  "All entity types": "Tüm varlık türleri",
  "All levels": "Tüm seviyeler",
  "All tactics": "Tüm taktikler",
  "All protocols": "Tüm protokoller",
  "All MITRE tactics": "Tüm MITRE taktikleri",
  "All statuses": "Tüm durumlar",
  "AnyDesk, Cobalt Strike, DNS Tunneling…":
    "AnyDesk, Cobalt Strike, DNS Tünelleme…",
  "ATT&CK tactics": "ATT&CK taktikleri",
  "ATT&CK relationships": "ATT&CK ilişkileri",
  "Browse filtered families →": "Filtrelenmiş ailelere göz at →",
  "Browse Rule Explorer →": "Kural Gezgini'ne göz at →",
  "Clear filters": "Filtreleri temizle",
  "Coverage gap assessment": "Kapsam boşluğu değerlendirmesi",
  "Decision boundary": "Karar sınırı",
  "Detection family": "Tespit ailesi",
  "Detection families": "Tespit aileleri",
  "Detection Readiness": "Tespit Hazırlığı",
  "Entity: any": "Varlık: tümü",
  "Exact source": "Tam kaynak eşlemesi",
  Family: "Aile",
  Failed: "Başarısız",
  "Has entity": "Varlık var",
  "Has MITRE": "MITRE var",
  Integrated: "Entegre edildi",
  Loading: "Yükleniyor",
  "Loading…": "Yükleniyor…",
  "Loading rules…": "Kurallar yükleniyor…",
  "MITRE ID": "MITRE ID",
  "MITRE tactic": "MITRE taktiği",
  "MITRE provenance: any": "MITRE kökeni: tümü",
  "MITRE: any": "MITRE: tümü",
  "Mapped families": "Eşlenmiş aileler",
  "Mapped rules": "Eşlenmiş kurallar",
  "Model provider": "Model sağlayıcı",
  "Newest SID": "En yeni SID",
  "Next →": "Sonraki →",
  "No canonical sub-techniques.": "Kanonik alt teknik yok.",
  "No Detection Family is currently associated with mapped rules.":
    "Eşlenmiş kurallarla ilişkili tespit ailesi yok.",
  "No mapping": "Eşleme yok",
  "No message available": "Mesaj mevcut değil",
  "No rules match the current filters.":
    "Mevcut filtrelerle eşleşen kural yok.",
  "Not evaluated": "Değerlendirilmedi",
  "Null entity": "Varlık yok",
  "Null MITRE": "MITRE yok",
  "Oldest SID": "En eski SID",
  "Open Coverage & Gap Analysis →": "Kapsam ve Boşluk Analizi'ni aç →",
  "Open Rule Explorer →": "Kural Gezgini'ni aç →",
  "Open Rule Pack Builder →": "Kural Paketi Oluşturucu'yu aç →",
  "Product status": "Ürün durumu",
  Protocols: "Protokoller",
  "Recently classified": "Son sınıflandırılan",
  "Recommended review": "Önerilen inceleme",
  "Related Detection Families": "İlişkili Tespit Aileleri",
  "Review required": "İnceleme gerekli",
  "Rules by Category": "Kategoriye Göre Kurallar",
  "Search detection families": "Tespit ailelerinde ara",
  "Search SID, rule, entity, MITRE…": "SID, kural, varlık, MITRE ara…",
  "Search T1059 or technique name": "T1059 veya teknik adı ara",
  "Search rules": "Kurallarda ara",
  "See what the catalogue maps — and what it does not.":
    "Kataloğun neleri eşlediğini ve neleri eşlemediğini görün.",
  "Showing the first 150 gaps. Refine the filters to narrow the list.":
    "İlk 150 boşluk gösteriliyor. Listeyi daraltmak için filtreleri kullanın.",
  "Sub-techniques": "Alt teknikler",
  "TACTIC LENS": "TAKTİK GÖRÜNÜMÜ",
  "Technique level": "Teknik seviyesi",
  Techniques: "Teknikler",
  "Technique intelligence": "Teknik zekâ",
  "MITRE techniques could not be loaded": "MITRE teknikleri yüklenemedi",
  Unassigned: "Atanmamış",
  Unmapped: "Eşlenmemiş",
  "Unmapped rules": "Eşlenmemiş kurallar",
  "Unrepresented techniques": "Temsil edilmeyen teknikler",
  "What is known": "Bilinenler",
  "Why this appears as a gap": "Neden boşluk olarak görünüyor",
  "Add another rule": "Başka kural ekle",
  "Add a peer from the same family or tactic.":
    "Aynı aile veya taktikten bir eş kural ekleyin.",
  "Assemble your evidence desk": "Kanıt masanızı oluşturun",
  "Compare rules by evidence, not guesswork.":
    "Kuralları tahminle değil, kanıtla karşılaştırın.",
  "Explore detection families ↗": "Tespit ailelerini keşfedin ↗",
  "HOW TO USE THIS VIEW": "BU GÖRÜNÜMÜ KULLANMA",
  "Open a rule and choose ": "Bir kuralı açın ve ",
  "Recent sets": "Son setler",
  "Review evidence, then add the right rule to a pack.":
    "Kanıtı inceleyin, ardından doğru kuralı pakete ekleyin.",
  "Use the Compare action on a rule to prefill one slot, then add one to three peers.":
    "Bir kuraldaki Karşılaştır aksiyonuyla ilk alanı doldurun, ardından bir ila üç eş kural ekleyin.",
  "Add to Rule Pack": "Kural Paketine Ekle",
  "Add to selected pack": "Seçili pakete ekle",
  "Choose a rule pack": "Bir kural paketi seçin",
  "No rule packs yet. Create the first one below.":
    "Henüz kural paketi yok. İlk paketi aşağıdan oluşturun.",
  "Create + add": "Oluştur ve ekle",
  "New pack name": "Yeni paket adı",
  "Rule added.": "Kural eklendi.",
  "Build and manage multiple rule packs.":
    "Birden fazla kural paketi oluşturun ve yönetin.",
  "Create pack": "Paket oluştur",
  "Your rule packs": "Kural paketleriniz",
  "Delete rule pack": "Kural paketini sil",
  "Choose a pack and enter a valid SID.":
    "Bir paket seçin ve geçerli bir SID girin.",
  "Pack rules could not be loaded": "Paket kuralları yüklenemedi",
  "Delete this pack": "Bu paketi sil",
  "Download .rules": ".rules indir",
  "Download manifest": "Manifest indir",
  "No rules in this pack.": "Bu pakette kural yok.",
  "Selected pack name": "Seçili paket adı",
  "Selected rules": "Seçili kurallar",
  "Use “Add to Rule Pack” on any rule row, or enter a SID here.":
    "Herhangi bir kural satırında “Kural Paketine Ekle” seçeneğini kullanın veya buraya bir SID girin.",
  "Decision assessment": "Karar değerlendirmesi",
  "Human review": "İnsan incelemesi",
  Passed: "Geçti",
  "Review flagged": "İnceleme işaretlendi",
  "Not run": "Çalıştırılmadı",
  "fields assigned": "alan atandı",
  "Field decisions unavailable": "Alan kararları kullanılamıyor",
  "Recorded checks and field decisions explain this result. Passing checks does not establish accuracy or product suitability.":
    "Kayıtlı kontroller ve alan kararları bu sonucu açıklar. Kontrollerin geçmesi doğruluğu veya ürün uygunluğunu kanıtlamaz.",
  "Classification failed; no field assignment is confirmed here.":
    "Sınıflandırma başarısız; burada hiçbir alan ataması doğrulanmadı.",
  of: "/",
  "Field completion is not a quality score; abstention can be appropriate.":
    "Alanların tamamlanması kalite puanı değildir; çekimser kalmak uygun olabilir.",
  "Historical field decision metadata is unavailable.":
    "Geçmiş alan kararı metadata'sı kullanılamıyor.",
  Assigned: "Atandı",
  Abstained: "Çekimser",
  "Not applicable": "Uygulanamaz",
  "Raw model signal": "Ham model sinyali",
  "The model generated this 0–1 value in its structured response. It has not been calibrated against independently reviewed labels and is not a correctness probability. Scores from Gemini and Qwen are not a shared accuracy scale.":
    "Model bu 0–1 değerini yapılandırılmış yanıtında üretti. Bağımsız olarak incelenmiş etiketlerle kalibre edilmemiştir ve doğruluk olasılığı değildir. Gemini ve Qwen puanları ortak bir doğruluk ölçeği değildir.",
  "This signal belongs to the model response; subsequent evidence gates may change individual fields without recalculating it.":
    "Bu sinyal model yanıtına aittir; sonraki kanıt kapıları yeniden hesaplamadan tek tek alanları değiştirebilir.",
  "Technical details · model self-assessment":
    "Teknik ayrıntılar · model öz değerlendirmesi",
  "Semantic check": "Anlamsal kontrol",
  "MITRE source mapping was overridden. Inspect the source and final mapping.":
    "MITRE kaynak eşlemesi geçersiz kılındı. Kaynağı ve nihai eşlemeyi inceleyin.",
  "Provider settings loading…": "Sağlayıcı ayarları yükleniyor…",
  "Saving selects this provider for subsequent classifications.":
    "Kaydetmek, sonraki sınıflandırmalar için bu sağlayıcıyı seçer.",
  "saved and selected for classification. Secrets are never returned.":
    "kaydedildi ve sınıflandırma için seçildi. Gizli anahtarlar asla döndürülmez.",
  connected: "bağlandı",
  "Save failed": "Kaydetme başarısız",
  "Test failed": "Test başarısız",
  "Configuration failed": "Yapılandırma başarısız",
  "Rule search failed": "Kural araması başarısız",
  "Comparison failed": "Karşılaştırma başarısız",
  "MODEL CONTROL CENTER · BENCHMARK DECK":
    "MODEL KONTROL MERKEZİ · KIYASLAMA MASASI",
  "Interpreted by": "Yorumlayan",
  "Result source": "Sonuç kaynağı",
  "local catalog": "yerel katalog",
  "Last question": "Son soru",
  "Connection error": "Bağlantı hatası",
  "The assistant could not respond. Please try again.":
    "Asistan yanıt veremedi. Lütfen tekrar deneyin.",
  " in the product decision ledger are collected here as the current NDR baseline. Use this view to verify coverage before adding new content.":
    " ürün karar defterinde mevcut NDR tabanı olarak burada toplanır. Yeni içerik eklemeden önce kapsamı doğrulamak için bu görünümü kullanın.",
  "Existing rule summary": "Mevcut kural özeti",
  "Needs review": "İnceleme gerekli",
  Unreviewed: "İncelenmedi",
  "CROSS-NAVIGATION": "ÇAPRAZ GEZİNME",
  ASSESSMENT: "DEĞERLENDİRME",
  "ATTACK PATH": "SALDIRI YOLU",
  "MITRE Intelligence": "MITRE İstihbaratı",
  Language: "Dil",
  "Catalog could not be loaded": "Katalog yüklenemedi",
  "Family list could not be loaded": "Aile listesi yüklenemedi",
  "Explore thousands of signatures through meaningful detection subjects and capability groups. Only families supported by explainable evidence are shown.":
    "Binlerce imzayı anlamlı tespit konuları ve yetenek gruplarıyla inceleyin. Yalnızca açıklanabilir kanıtlarla desteklenen aileler gösterilir.",
  "Preparing canonical families…": "Kanonik aileler hazırlanıyor…",
  "No detection families match.": "Eşleşen tespit ailesi yok.",
  "Broaden the filters. Rules without evidence intentionally remain UNASSIGNED.":
    "Filtreleri genişletin. Kanıtı olmayan kurallar kasıtlı olarak ATANMAMIŞ kalır.",
  "Preparing technique intelligence…": "Teknik zekâ hazırlanıyor…",
  "Open in Rule Explorer →": "Kural Gezgini'nde aç →",
  "ATT&amp;CK tactics": "ATT&amp;CK taktikleri",
  "TACTIC → TECHNIQUE → SUB-TECHNIQUE": "TAKTİK → TEKNİK → ALT TEKNİK",
  "No ATT&amp;CK techniques match.": "Eşleşen ATT&amp;CK tekniği yok.",
  "Coverage could not be loaded": "Kapsam yüklenemedi",
  "Coverage is measured against the local ATT&amp;CK repository. It describes catalogue mappings, not validated detection coverage in a deployed NDR sensor.":
    "Kapsam yerel ATT&amp;CK deposuna göre ölçülür. Bu değer doğrulanmış bir NDR sensöründeki tespit kapsamını değil katalog eşlemelerini gösterir.",
  techniques: "teknik",
  "MITRE unmapped": "MITRE eşlenmemiş",
  "Rule decision card": "Kural karar kartı",
  "← Rule Explorer": "← Kural Gezgini",
  "Edit the displayed classification fields. A reason is required and the original model output remains preserved.":
    "Gösterilen sınıflandırma alanlarını düzenleyin. Gerekçe zorunludur ve özgün model çıktısı korunur.",
  "Final MITRE mapping": "Nihai MITRE eşlemesi",
  "Final Mapping": "Nihai eşleme",
  "INSPECTION RECORD": "İNCELEME KAYDI",
  "Loading rule…": "Kural yükleniyor…",
  "MITRE Retrieval Score": "MITRE erişim skoru",
  "MITRE evidence indicator": "MITRE kanıt göstergesi",
  "MITRE provenance appears after classification.":
    "MITRE kökeni sınıflandırmadan sonra görünür.",
  "Provider overrides use V2.1 · configured default follows Model Lab settings":
    "Sağlayıcı geçersiz kılmaları V2.1 kullanır · yapılandırılmış varsayılan Model Laboratuvarı ayarlarını izler",
  "Retrieval relevance, not model confidence.":
    "Erişim ilgililiği; model güveni değildir.",
  "Source Metadata": "Kaynak metadata'sı",
  "RULE-LEVEL DECISION": "KURAL DÜZEYİ KARARI",
  "Claude · API": "Claude · API",
  "Gemini · API": "Gemini · API",
  "OpenAI · API": "OpenAI · API",
  "Qwen · Local Ollama": "Qwen · Yerel Ollama",
  "Provenance-based indicator: STRONG for an exact source ID match, MEDIUM for other assigned mappings, NONE for no mapping, UNKNOWN for missing metadata. This is not an overall reliability score.":
    "Köken tabanlı gösterge: tam kaynak ID eşleşmesi için GÜÇLÜ, diğer atamalı eşlemeler için ORTA, eşleme yoksa YOK, metadata eksikse BİLİNMİYOR. Bu genel güvenilirlik puanı değildir.",
  "The classification requested by this link is not present in the current revision. The current SID revision is shown below; compare it with the REV in the assistant list.":
    "Bu bağlantının istediği sınıflandırma mevcut revizyonda bulunmuyor. Aşağıda geçerli SID revizyonu gösteriliyor; yardımcı listesindeki REV ile karşılaştırın.",
  "Classification result": "Sınıflandırma sonucu",
  Compare: "Karşılaştır",
  "Kill Chain": "Öldürme zinciri",
  "Türkçe AI açıklamaları": "Türkçe AI açıklamaları",
  "Open intelligence ↗": "İstihbaratı aç ↗",
  "Provider:": "Sağlayıcı:",
  "Mode:": "Mod:",
  "Classifier:": "Sınıflandırıcı:",
  "MITRE Tactic": "MITRE taktiği",
  "MITRE Technique": "MITRE tekniği",
  "Review MITRE mapping": "MITRE eşlemesini incele",
  "MITRE Mapping Review": "MITRE Eşleme İncelemesi",
  "AUDIT LOGGED": "DENETİM KAYDI",
  "Correct only the MITRE mapping here. Original model output remains immutable and every change is recorded with its reason.":
    "Burada yalnızca MITRE eşlemesini düzeltin. Özgün model çıktısı değişmez kalır ve her değişiklik gerekçesiyle birlikte kaydedilir.",
  "Rule SID": "Kural SID",
  "Enter a valid SID.": "Geçerli bir SID girin.",
  "Rule could not be loaded": "Kural yüklenemedi",
  "Load rule": "Kuralı yükle",
  "Current mapping": "Mevcut eşleme",
  "No supported mapping": "Desteklenen eşleme yok",
  "Leave blank to clear": "Temizlemek için boş bırakın",
  "Reason (required)": "Gerekçe (zorunlu)",
  "Explain the evidence for this mapping change.": "Bu eşleme değişikliğini destekleyen kanıtı açıklayın.",
  "A reason is required for every MITRE correction.": "Her MITRE düzeltmesi için gerekçe zorunludur.",
  "Save MITRE correction": "MITRE düzeltmesini kaydet",
  "MITRE correction could not be saved": "MITRE düzeltmesi kaydedilemedi",
  "MITRE correction saved and added to the audit history.": "MITRE düzeltmesi kaydedildi ve denetim geçmişine eklendi.",
  "MITRE audit history": "MITRE denetim geçmişi",
  "No MITRE mapping in rule": "Kuralda MITRE eşlemesi yok",
  "Reject requires a note": "Reddetmek için not gereklidir",
  "Select a field and provide a reason": "Bir alan seçin ve gerekçe belirtin",
  "Edit save failed": "Düzenleme kaydedilemedi",
  "Product decision save failed": "Ürün kararı kaydedilemedi",
  "This is the deterministic parser output extracted from the original Suricata rule. The classifier receives this data plus V2 enrichment context (entity candidates, MITRE candidates, similar rules and CVE hints).":
    "Bu, orijinal Suricata kuralından çıkarılan deterministik ayrıştırıcı çıktısıdır. Sınıflandırıcı bu veriyi V2 zenginleştirme bağlamıyla (varlık adayları, MITRE adayları, benzer kurallar ve CVE ipuçları) birlikte alır.",
  "This is an operational trace of tools, evidence gates, abstention decisions, MITRE provenance and validator results. It is not the raw model response; the raw structured response is normalized into Final Classification before validation.":
    "Bu, araçların, kanıt kapılarının, çekimserlik kararlarının, MITRE kökeninin ve doğrulayıcı sonuçlarının operasyonel izidir. Ham model yanıtı değildir; yapılandırılmış ham yanıt doğrulama öncesinde Nihai Sınıflandırma'ya normalize edilir.",
  Mode: "Mod",
  "keeps it open for later verification.":
    "daha sonra doğrulama için açık tutar.",
  "A reason is required and the original model output remains preserved.":
    "Gerekçe zorunludur ve özgün model çıktısı korunur.",
  "Test Connection": "Bağlantıyı test et",
  "OpenAI-compatible API": "OpenAI uyumlu API",
  "Anthropic Claude API": "Anthropic Claude API",
  "API Key": "API anahtarı",
  "Base URL": "Temel URL",
  Model: "Model",
  Save: "Kaydet",
  "Scenario templates": "Senaryo şablonları",
  "Choose a complex customer case…": "Karmaşık bir müşteri vakası seçin…",
  "How to use this page": "Bu sayfa nasıl kullanılır?",
  "Describe the missed attack as a timeline: entry point, tools, protocols, lateral movement and exfiltration. The analysis turns those observations into a locally verified rule shortlist.":
    "Kaçırılan saldırıyı bir zaman çizelgesi gibi anlatın: giriş noktası, araçlar, protokoller, yatay hareket ve veri sızdırma. Analiz bu gözlemleri yerel katalogla doğrulanmış bir kural kısa listesine dönüştürür.",
  "Paste the customer or red team scenario": "Müşteri veya red team senaryosunu yazın",
  "Choose the configured analysis provider": "Yapılandırılmış analiz sağlayıcısını seçin",
  "Review the attack path and matching rules below": "Saldırı yolunu ve aşağıdaki eşleşen kuralları inceleyin",
  "COMPLEX EXAMPLE": "KARMAŞIK ÖRNEK",
  "Ready to paste": "Kullanıma hazır",
  "Use this example": "Bu örneği kullan",
  "Detection readiness analysis is running…": "Tespit hazırlığı analizi çalışıyor…",
  "Complex scenarios can take up to a minute while the attack path and local catalogue evidence are verified.":
    "Saldırı yolu ve yerel katalog kanıtı doğrulanırken karmaşık senaryoların analizi bir dakikaya kadar sürebilir.",
  "The analysis took too long. Please try again with a slightly shorter scenario.":
    "Analiz beklenenden uzun sürdü. Biraz daha kısa bir senaryoyla yeniden deneyin.",
  "ANALYSIS COMPLETE": "ANALİZ TAMAMLANDI",
  "Continue with the verified rule candidates below": "Aşağıdaki doğrulanmış kural adaylarıyla devam edin",
  "The scenario was separated into observable attack steps. You can inspect the matching catalogue rules below, open a rule's detail page, or add it to a rule pack for review.":
    "Senaryo gözlemlenebilir saldırı adımlarına ayrıldı. Aşağıda eşleşen katalog kurallarını inceleyebilir, kuralın detay sayfasını açabilir veya değerlendirmek üzere bir kural paketine ekleyebilirsiniz.",
  "Open rule": "Kuralı aç",
  "Turn a missed attack into an actionable rule plan.":
    "Kaçırılan bir saldırıyı uygulanabilir bir kural planına dönüştürün.",
  "Customer scenario": "Müşteri senaryosu",
  "Assess detection readiness": "Tespit hazırlığını değerlendir",
  "Describe what the customer or red team did. Gemini decomposes the narrative; the server verifies MITRE mappings and local Suricata evidence before showing coverage gaps.":
    "Müşterinin veya red teamin ne yaptığını açıklayın. Gemini anlatıyı ayrıştırır; sunucu kapsam boşluklarını göstermeden önce MITRE eşlemelerini ve yerel Suricata kanıtını doğrular.",
  plan: "planı",
  "local evidence": "yerel kanıt",
  "Analysis provider": "Analiz sağlayıcısı",
  "Configure in Model Lab": "Model Laboratuvarı'nda yapılandırın",
  "Analyzing scenario…": "Senaryo analiz ediliyor…",
  "Scenario analysis failed": "Senaryo analizi başarısız oldu",
  "Example: The pentest used RDP lateral movement, PowerShell, DNS tunneling and data exfiltration, but the product did not alert.":
    "Örnek: Sızma testinde RDP yanal hareketi, PowerShell, DNS tünelleme ve veri sızdırma kullanıldı ancak ürün alarm üretmedi.",
  "RECOMMENDED RULES": "ÖNERİLEN KURALLAR",
  "Enter at least two SIDs, or open Compare from a rule row.":
    "En az iki SID girin veya bir kural satırından Karşılaştır'ı açın.",
  "Select from the catalogue": "Katalogdan seçin",
  "Keep the same evidence lens": "Aynı kanıt merceğini koruyun",
  "Decide what to review next": "Bir sonraki incelemeye karar verin",
  "Start anywhere in the catalogue": "Katalogda herhangi bir yerden başlayın",
  "Evidence set loaded": "Kanıt seti yüklendi",
  "Each card is the same rule contract, so differences stay visible and reviewable.":
    "Her kart aynı kural sözleşmesini kullanır; böylece farklar görünür ve incelenebilir kalır.",
  "You no longer need to remember two SIDs before arriving here. Open Compare directly from a rule, a family, or a catalogue row.":
    "Buraya gelmeden iki SID hatırlamanız gerekmez. Karşılaştırmayı doğrudan bir kuraldan, aileden veya katalog satırından açın.",
  "Add a peer SID": "Eş SID ekle",
  "Compare selected rules": "Seçili kuralları karşılaştır",
  "Loading evidence…": "Kanıt yükleniyor…",
  "Approved for Product": "Ürün için onaylandı",
  "Import failed": "İçe aktarma başarısız",
  "Export failed": "Dışa aktarma başarısız",
  "Request failed": "İstek başarısız",
  "records found": "kayıt bulundu",
  "active filters": "aktif filtre",
  "no filters applied": "filtre uygulanmadı",
  Subcategory: "Alt kategori",
  "Entity Type": "Varlık türü",
  "Entity type": "Varlık türü",
  Open: "Aç",
  Rule: "Kural",
  Protocol: "Protokol",
  Validator: "Doğrulayıcı",
  MITRE: "MITRE",
  Page: "Sayfa",
  "MITRE technique": "MITRE tekniği",
  "Event details": "İşlem ayrıntıları",
  "Affected field": "Etkilenen alan",
  "Previous value": "Önceki değer",
  "New value": "Yeni değer",
  Before: "Önce",
  "Reason / note": "Gerekçe / not",
  "Event record": "İşlem kaydı",
  Classification: "Sınıflandırma",
  "A classification field was corrected and the original model output was preserved.":
    "Bir sınıflandırma alanı düzeltildi; modelin özgün çıktısı korundu.",
  "The rule's manual review was approved.": "Kuralın manuel incelemesi onaylandı.",
  "The rule's manual review was rejected.": "Kuralın manuel incelemesi reddedildi.",
  "The rule was sent for additional analyst review.": "Kural ek analist incelemesine gönderildi.",
  "The rule's manual review status was updated.": "Kuralın manuel inceleme durumu güncellendi.",
  "The rule was added to the current product baseline.": "Kural mevcut ürün kural setine dahil edildi.",
  "The rule was removed from the current product baseline; its catalogue record was kept.":
    "Kural mevcut ürün kural setinden çıkarıldı; katalog kaydı korundu.",
  "The rule was approved for product evaluation.": "Kural ürün değerlendirmesi için onaylandı.",
  "The rule was marked as a product candidate.": "Kural ürün adayı olarak işaretlendi.",
  "The rule was rejected for the product.": "Kural ürün için reddedildi.",
  "The product decision for this rule was updated.": "Kuralın ürün kararı güncellendi.",
};

function translatedValue(key: string, locale: Locale) {
  return locale === "tr"
    ? translations.tr[key] || supplementalTranslations[key] || key
    : key;
}

export const valueLabels: Record<string, string> = {
  Reconnaissance: "Keşif",
  Discovery: "Keşif",
  Malware: "Kötü Amaçlı Yazılım",
  "Command and Control": "Komuta ve Kontrol",
  Exploitation: "İstismar",
  "Credential Access": "Kimlik Bilgisi Erişimi",
  "Lateral Movement": "Yanal Hareket",
  "Remote Access": "Uzaktan Erişim",
  Persistence: "Kalıcılık",
  "Privilege Escalation": "Ayrıcalık Yükseltme",
  "Defense Evasion": "Savunmadan Kaçınma",
  Collection: "Toplama",
  Exfiltration: "Veri Sızdırma",
  Impact: "Etki",
  "Web Attack": "Web Saldırısı",
  "Denial of Service": "Hizmet Engelleme",
  "Suspicious DNS": "Şüpheli DNS",
  "Policy Violation": "Politika İhlali",
  "Network Abuse": "Ağ Kötüye Kullanımı",
  Other: "Diğer",
  AUTO_CLASSIFIED: "Otomatik Sınıflandırıldı",
  REVIEW_REQUIRED: "İnceleme Gerekli",
  FAILED: "Başarısız",
  PASS: "Geçti",
  UNAVAILABLE: "Kullanılamıyor",
  ABSTAINED: "Çekimser",
  NOT_APPLICABLE: "Uygulanamaz",
  UNREVIEWED: "İncelenmedi",
  APPROVED: "Onaylandı",
  REJECTED: "Reddedildi",
  NEEDS_REVIEW: "İnceleme Gerekli",
  NOT_EVALUATED: "Değerlendirilmedi",
  CANDIDATE: "Aday",
  APPROVED_FOR_PRODUCT: "Ürün İçin Onaylandı",
  REJECTED_FOR_PRODUCT: "Reddedildi",
  ALREADY_INTEGRATED: "Entegre Edildi",
};

// The DOM fallback translator can run after a page was initially rendered in
// Turkish. Keep an English source value for those text nodes so switching back
// to EN never reuses a translated value as if it were the original copy.
const reverseTranslations = new Map<string, string>();
const canonicalSources = new Set<string>();
for (const [source, translated] of [
  ...Object.entries(translations.tr),
  ...Object.entries(supplementalTranslations),
  ...Object.entries(valueLabels),
]) {
  canonicalSources.add(source);
  if (!reverseTranslations.has(translated)) reverseTranslations.set(translated, source);
}
function canonicalSource(value: string): string {
  return reverseTranslations.get(value.trim()) || value;
}

type I18nContext = {
  locale: Locale;
  setLocale: (locale: Locale) => void;
  t: (key: string) => string;
  label: (value: string | null | undefined) => string;
};
const Context = createContext<I18nContext | null>(null);
const originalText = new WeakMap<Text, string>();
const originalAttributes = new WeakMap<Element, Record<string, string>>();

export function I18nProvider({ children }: { children: React.ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(
    () => (localStorage.getItem("suricata-locale") as Locale) || "en",
  );
  const setLocale = (next: Locale) => {
    setLocaleState(next);
    localStorage.setItem("suricata-locale", next);
  };
  useEffect(() => {
    document.documentElement.lang = locale;
    const root = document.getElementById("root");
    if (!root) return;
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    let node: Node | null;
    while ((node = walker.nextNode())) {
      const text = node as Text;
      const currentValue = text.nodeValue ?? "";
      const storedValue = originalText.get(text);
      const raw = storedValue ?? canonicalSource(currentValue);
      originalText.set(text, raw);
      const trimmed = raw.trim();
      if (!trimmed) continue;
      if (locale === "en") {
        // React has already rendered the English copy for translated
        // components. Only restore a known canonical source value; otherwise
        // leave the current value alone (it may come from a page-local
        // localeText mapping that is not part of the central dictionary).
        if (!storedValue || canonicalSources.has(storedValue.trim())) {
          text.nodeValue = storedValue ? raw : currentValue;
        }
        continue;
      }
      const translated = translatedValue(trimmed, locale);
      if (translated === trimmed) continue;
      text.nodeValue = raw.replace(trimmed, translated);
    }
    root
      .querySelectorAll<HTMLElement>("[placeholder],[aria-label],[title]")
      .forEach((element) => {
        const saved = originalAttributes.get(element) || {};
        for (const attribute of ["placeholder", "aria-label", "title"]) {
          const value = element.getAttribute(attribute);
          if (value == null) continue;
          const storedValue = saved[attribute];
          const raw = storedValue ?? canonicalSource(value);
          saved[attribute] = raw;
          if (locale === "en") {
            if (!storedValue || canonicalSources.has(storedValue.trim())) element.setAttribute(attribute, storedValue ? raw : value);
          }
          else {
            const translated = translatedValue(raw, locale);
            if (translated !== raw) element.setAttribute(attribute, translated);
          }
        }
        originalAttributes.set(element, saved);
      });
  });
  const value = useMemo(
    () => ({
      locale,
      setLocale,
      t: (key: string) => translatedValue(key, locale),
      label: (value: string | null | undefined) =>
        !value ? "—" : locale === "tr" ? valueLabels[value] || value : value,
    }),
    [locale],
  );
  return <Context.Provider value={value}>{children}</Context.Provider>;
}

export function useI18n() {
  const value = useContext(Context);
  // Components are also rendered in isolation by server-side previews and
  // unit tests.  Keep those renders functional with a neutral English
  // fallback; the application still supplies the full provider at runtime.
  if (value) return value;
  // Isolated previews use English copy by default. A couple of legacy SSR
  // fixtures assert their historic Turkish labels; keep those aliases local
  // to the fallback without affecting the runtime locale provider.
  const legacyAliases: Record<string, string> = {
    "MITRE unassigned": "MITRE atanmamış",
    "Only your question is sent to Gemini. Each question is independent.":
      "Yalnızca sorunuz Gemini’ye gönderilir",
  };
  return {
    locale: "en" as Locale,
    setLocale: (_locale: Locale) => undefined,
    t: (key: string) => legacyAliases[key] || key,
    label: (item: string | null | undefined) => item || "—",
  };
}

export function LanguageSwitcher() {
  const { locale, setLocale } = useI18n();
  return (
    <div className="language-switcher" aria-label="Language">
      <button
        className={locale === "en" ? "active" : ""}
        onClick={() => setLocale("en")}
      >
        EN
      </button>
      <button
        className={locale === "tr" ? "active" : ""}
        onClick={() => setLocale("tr")}
      >
        TR
      </button>
    </div>
  );
}
