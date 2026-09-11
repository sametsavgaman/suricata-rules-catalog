# Suricata Rule Agent — Sayfa Sayfa Ürün ve Sunum Rehberi

> Hazırlanma tarihi: 9 Eylül 2026  
> İncelenen kapsam: `frontend` uygulaması, ilgili FastAPI uçları, sınıflandırma/validasyon/aile/senaryo servisleri, çalışan yerel arayüz ve mevcut SQLite verisi.  
> Önemli: Katalogda aktif Qwen batch işlemi çalıştığı için sınıflandırma ve aile sayıları sunum anında birkaç kayıt değişebilir. Aşağıdaki sayılar bir anlık görüntüdür.

## 1. Projeyi tek cümlede nasıl anlatmalısın?

Suricata Rule Agent; büyük bir Suricata imza kümesini içe alan, kuralları deterministik olarak ayrıştıran, sınırlı ve yapılandırılmış bir AI bağlamıyla anlamsal olarak sınıflandıran, çıktıyı yerel taksonomi ve MITRE ATT&CK bilgisiyle doğrulayan ve insan incelemesi ile NDR ürün kararını birbirinden ayrı şekilde yöneten bir detection content karar destek platformudur.

Bu ürünün ana değeri “AI bir etiket üretiyor” değildir. Asıl değer şudur:

1. Ham kural kaybolmaz.
2. Parser sonucu tekrar üretilebilir ve görülebilir.
3. AI yalnızca anlamsal öneri üretir.
4. Validasyon AI çıktısını denetler.
5. İnsan incelemesi AI durumundan ayrıdır.
6. Ürüne alma kararı insan incelemesinden de ayrı tutulur.
7. Her kararın modeli, sürümü, kanıtı ve geçmişi saklanır.

## 2. Mevcut veri fotoğrafı

İnceleme sırasında çalışan sistemde görülen değerler:

| Ölçüm | Değer | Doğru yorum |
|---|---:|---|
| Toplam kural | 52.155 | İçe aktarılmış benzersiz SID + REV kayıtları |
| Başarılı sınıflandırması bulunan kural | yaklaşık 20.952 | En az bir FAILED olmayan classification kaydı bulunan kurallar |
| Toplam model/sınıflandırma çıktısı | yaklaşık 21.923 | Aynı kuralın farklı model/sürüm sonuçları dahil |
| Aile sayısı | yaklaşık 1.160 | Kanıtla oluşturulmuş canonical family kayıtları |
| Aileye atanmış kural | 5.088 | Deterministik aile kanıtı bulunan kurallar |
| Aile atama kapsaması | %9,76 | Düşük olması hata değil; sistem kanıt yoksa `UNASSIGNED` kalır |
| MITRE repository tekniği | 697 | Yerel resmi ATT&CK STIX deposundaki teknik ve alt teknikler |
| Katalogda temsil edilen teknik | 141 | Kural/classification veya kaynak metadata eşlemesi bulunan canonical ID’ler |
| MITRE katalog kapsam oranı | %20,2 | Dağıtılmış NDR algılama oranı değil, katalog eşleme oranı |
| İnsan onaylı classification | 1 | AI sınıflandırması ile insan onayı aynı şey değildir |
| Ürün için onaylı kural | 0 | Ürün karar defteri henüz doldurulmamış |
| Mevcut üründe entegre kural | 0 | Existing Rules sayfasının şu anda boş olmasının nedeni |

### Neden iki farklı “MITRE mapped” sayısı görülebilir?

- Detection Catalog / Rule Explorer tarafındaki yaklaşık 13,9 bin sayı, her kuralın **en son başarılı classification** kaydındaki final MITRE alanını sayar.
- MITRE Intelligence tarafındaki yaklaşık 30,4 bin sayı, katalog ilişkisini daha geniş ele alır; doğrulanmış classification eşlemelerine ek olarak kuralın açık kaynak metadata’sındaki canonical MITRE ilişkisini de dikkate alabilir.
- Dolayısıyla bu iki sayaç aynı soruyu cevaplamaz. Sunumda bunları doğrudan karşılaştırıp “tutarsızlık” demek yerine kapsamlarını açıklamak gerekir.

## 3. Uçtan uca işleyiş

```text
.rules dosyası
    ↓
RuleLoader: yorum/boş satırları atlar, çok satırlı kuralları birleştirir
    ↓
SuricataRuleParser: header ve option alanlarını deterministik çıkarır
    ↓
Rule kaydı: SID + REV benzersiz ve değişmez
    ↓
Deterministik enrichment: entity, kategori, CVE ve MITRE aday sinyalleri
    ↓
ClassificationContext: boyutu ve alanları sınırlandırılmış model girdisi
    ↓
Seçili provider: Gemini / OpenAI / Claude / yerel Qwen
    ↓
V2 pipeline: kanıt kapıları, abstention, MITRE karar katmanı
    ↓
Validator: şema, taxonomy, canonical MITRE ve tutarlılık kontrolleri
    ↓
Classification kaydı + status + provenance
    ↓
İnsan incelemesi → ürün kararı → rule pack
```

### Kim hangi konuda yetkilidir?

| Katman | Yetkili olduğu konu | Yetkili olmadığı konu |
|---|---|---|
| Parser | Suricata sözdizimi ve yapısal alanlar | Tehdidin anlamı |
| Enrichment | Açıklanabilir aday sinyaller | Ground truth |
| AI provider | Anlamsal sınıflandırma önerisi | İnsan onayı ve ürün uygunluğu |
| Validator | Şema/taksonomi/MITRE tutarlılığı | Gerçek ağdaki false positive ve performans |
| İnsan review | Classification’ın analistçe kabulü | Otomatik ürün entegrasyonu |
| Product Planning | Kuralın NDR ürün yol haritasındaki yeri | AI çıktısının doğruluğunu tek başına ispatlamak |

## 4. Sayfa haritası

| Sayfa | Rota | Ana kullanıcı sorusu |
|---|---|---|
| Detection Catalog | `/catalog` ve `/` | Katalogda genel olarak ne var? |
| Detection Families | `/catalog/families` | Binlerce imzayı anlamlı konular altında nasıl gezerim? |
| Family Detail | `/catalog/families/:slug` | Bu aile neden var, hangi kuralları ve MITRE alanlarını kapsıyor? |
| Rules / Rule Explorer | `/catalog/rules` ve `/rules` | Aradığım kuralları nasıl bulur ve daraltırım? |
| Rule Detail | `/rules/:sid` ve `/catalog/rules/:sid` | Bu tek kural gerçekte neye bakıyor ve ürüne alınmalı mı? |
| MITRE Intelligence | `/catalog/mitre` | Katalog ATT&CK üzerinde nereye dağılıyor? |
| MITRE Technique Detail | `/catalog/mitre/:techniqueId` | Bu tekniği hangi kurallar/aileler destekliyor? |
| Coverage & Gap Analysis | `/catalog/coverage` | Hangi ATT&CK tekniklerinde katalog kanıtı yok? |
| Existing Rules | `/catalog/existing` | Üründe zaten entegre olan baseline nedir? |
| Detection Readiness | `/catalog/scenarios` | Müşteri/pentest senaryosunu kural planına nasıl çeviririm? |
| Compare | `/catalog/compare` | Benzer kuralları aynı kanıt merceğiyle nasıl kıyaslarım? |
| Rule Packs | `/catalog/rule-packs` | Seçilen kuralları dağıtım paketine nasıl dönüştürürüm? |
| Model Lab | `/models` | Provider’ları nasıl yapılandırır ve aynı kuralda karşılaştırırım? |
| Docs | `/docs` | Platformun mimarisi, durumları ve entegrasyon sözleşmesi nedir? |

---

## 5. Detection Catalog — ana giriş sayfası

### Bu sayfa nedir?

Kataloğun üst düzey giriş ve yönlendirme ekranıdır. Kullanıcıya veri hacmini, aile sayısını, MITRE eşlemelerini, kategori dağılımını ve taktik dağılımını tek bakışta verir. Ayrıca doğal dil katalog asistanı burada bulunur.

### Sayfadaki işleyiş

- `catalog/stats`, `catalog/facets` ve `families/stats` paralel yüklenir.
- Kartlar Rules, Families, MITRE’li kurallar ve Rule Packs sayfalarına yönlendirir.
- Kategori ağacındaki bir dal seçilince Rule Explorer ilgili kategori query parametresiyle açılır.
- MITRE taktik dalı seçilince Rule Explorer hem taktik hem de `mitre_status=has` filtresiyle açılır.
- “Ask the catalog” alanında yalnızca kullanıcının sorusu Gemini’ye gider.
- Gemini doğrudan kayıt döndürmez ve SQL yazmaz; soruyu izinli bir filtre planına çevirir.
- Backend planı Pydantic ve canonical taxonomy/MITRE kurallarıyla tekrar doğrular, gerçek sayı ve satırları yerel veritabanından üretir.
- Sayfa değiştirme/pagination yeni bir Gemini çağrısı yapmaz; aynı filtrelerle yalnızca DB sorgusu çalışır.

### NDR uzmanı nasıl kullanır?

- “DNS kullanan C2 kurallarını göster” gibi soruyla ilk aday havuzunu çıkarır.
- “T1219 ile ilişkili aileleri göster” diyerek remote access içeriğine hızlı ulaşır.
- Kategori/taktik dağılımından katalog ağırlığını görür.
- Sonucu doğrudan ürüne almaz; Rule Detail’e geçip imza, kanıt, network uygunluğu ve ürün durumunu inceler.

### Sunumda vurgula

“Asistan cevap üretmek için katalog kayıtlarını modele göndermiyor. Model yalnızca kontrollü filtre planlıyor; sonuçların kaynağı yerel SQL kataloğu.”

### Gelebilecek sorular

**Asistan halüsinasyon yaparsa ne olur?**  
Plan yalnızca izinli enum ve filtre alanlarıyla kabul edilir. Bilinmeyen MITRE ID, çelişkili filtre veya desteklenmeyen istek reddedilir/clarify döner. Sayılar modelden değil DB’den gelir.

**Model veritabanını görebiliyor mu?**  
Hayır. Soru, statik taxonomy ve sistem talimatı gönderilir; rule satırları, raw rule, DB URL’si ve secret gönderilmez.

**Neden sadece localhost?**  
Ücretli model ucunun kimlik doğrulaması yok; bu yüzden LAN/public erişime kapalı, origin kontrolü ve rate limit uygulanıyor.

### Demo önerisi

“T1219 ile ilişkili detection ailelerini göster” sorusunu kullan. Sonuçtan aileye, oradan Rule Explorer’a ilerle. Dış kapsamlı soru sorma; demo süresinde provider gecikmesine bağlı risk yaratır.

---

## 6. Detection Families — açıklanabilir gruplama sayfası

### Bu sayfa nedir?

Tek tek binlerce SID yerine AnyDesk, Cobalt Strike, Sliver, CVE veya DNS Tunneling gibi anlaşılır detection konularını gösterir. Bu, model embedding/similarity kümesi değildir; kanıtla oluşturulmuş bir projection katmanıdır.

### Aile nasıl oluşur?

Sistem tek bir savunulabilir primary family arar:

1. Modelin entity’si, deterministik entity candidate ile aynı ve zayıf olmayan kanıta sahipse entity ailesi oluşturulabilir.
2. Mesajda allowlist/regex ile bilinen araç veya malware adı geçiyorsa aile atanabilir.
3. Desteklenen açık davranış kalıpları kullanılabilir: DNS Tunneling, SMB Lateral Movement, Malicious TLS Certificates, Remote Access Software.
4. Raw rule içinde CVE varsa ve classification kategorisi Exploitation/Web Attack ise CVE ailesi oluşturulabilir.
5. Bunların hiçbiri yoksa kural bilerek `UNASSIGNED` kalır.

Bir kuralın yalnızca bir primary family’si vardır. Atamanın `provenance`, `evidence` ve `algorithm_version` bilgisi saklanır.

### Sayfadaki işleyiş

- Arama, kategori, MITRE taktiği/ID’si, protokol ve ürün durumu filtreleri vardır.
- Filtreler server-side çalışır; 24 ailelik sayfalama vardır.
- Kartta aile tipi, rule count, ilk protokoller, MITRE ID’leri, kategori ve ürün seçimi sayısı görünür.
- İstatistikte assigned, unassigned ve conservative coverage ayrılır.

### NDR uzmanı nasıl kullanır?

- Aynı araç/malware/vulnerability ile ilişkili çok sayıda imzayı tek konu altında inceler.
- Bir vendor feed içindeki tekrar eden imzalardan hangilerinin aynı ürün yeteneğini temsil ettiğini görür.
- Önce aile seviyesinde kapsam kararı verir, sonra kural seviyesinde en uygun imzaları seçer.
- Ürün durumuyla filtreleyerek örneğin yalnız shortlisted aileleri görebilir.

### Gelebilecek sorular

**Neden kapsama sadece %9,76?**  
Çünkü sistem benzer göründüğü için kuralı zorla aileye sokmuyor. Düşük oran, conservative abstention tasarımının sonucudur; yanlış aile atamasını azaltır.

**Aile model tarafından mı yaratılıyor?**  
Hayır. Deterministik aday ve açık kalıp kanıtı gerekir. Model metni tek başına yeterli değildir.

**Bir kural birden fazla aileye girebilir mi?**  
Mevcut şemada hayır; `rule_id` üzerinde unique primary family kısıtı vardır.

---

## 7. Family Detail — aile inceleme sayfası

### Bu sayfa nedir?

Seçilen ailenin profilini, atama gerekçelerini, MITRE dağılımını ve gerçek alt kurallarını bir arada gösterir.

### Sayfadaki işleyiş

- Aile tipi ve adı gösterilir.
- Rule, protocol, MITRE technique ve evidence-backed link sayıları özetlenir.
- Coverage profile: protokoller, kategoriler, MITRE ID’leri ve entity type’lar.
- Assignment provenance: explicit entity, known tool, CVE family, behavior pattern gibi gerekçelerin sayısı.
- MITRE paneli: aile içindeki mapped/unmapped kuralları ve technique dağılımını gösterir.
- Alt kurallar 50’lik sayfalarla listelenir; her satırda atama evidence özeti ve provenance görünür.
- “Open in Rule Explorer” aynı aileyi filtreli tabloya taşır.
- “Ask Gemini about this family” ana sayfadaki asistana aile adını hazırlar.

### NDR uzmanı nasıl kullanır?

- Ailenin tek tip bir davranış mı, araç mı, malware mi yoksa vulnerability mi olduğunu anlar.
- Aile içindeki protokol ve MITRE çeşitliliğinin gereğinden fazla geniş olup olmadığını denetler.
- Aynı ailedeki alternatif imzaları Compare sayfasına gönderir.
- Tek bir aileden deploy edilecek minimal ama yeterli kural alt kümesini oluşturur.

### Sunum mesajı

“Aile ekranı sadece gruplama göstermiyor; kuralın neden o aileye dahil olduğunu da saklıyor. Model benzerliği tek başına aile oluşturmuyor.”

---

## 8. Rules / Rule Explorer — ana analist çalışma masası

### Bu sayfa nedir?

52 bin+ kuralı arama, filtreleme, sınıflandırma durumu kontrolü, karşılaştırma ve rule pack’e ekleme için kullanılan merkezi tablo ekranıdır.

### Üst metrikler ne anlama gelir?

- **Total Rules:** tüm SID + REV kayıtları.
- **Classified:** son classification’ı AUTO_CLASSIFIED olanlar.
- **Review Required:** validator nedeniyle sistem incelemesi gerekenler.
- **Failed:** son classification denemesi başarısız olanlar; bu “kural bozuk” demek değildir.
- **MITRE Mapped:** en son başarılı classification’da final MITRE ID bulunan unique kurallar.
- **Approved for Product:** ayrı ürün defterinde onaylı olanlar.
- **Manual durumlar:** classification’a ait insan inceleme kayıtları.

### Filtreler

- Metin: SID, raw/message, entity ve MITRE gibi alanlarda arama.
- Category / subcategory.
- MITRE ID / tactic / mapping method.
- Entity type ve entity var/yok.
- AI status ve manual review status.
- Inspection batch.
- Model, provider, classifier version ve inference mode.
- Product status.
- Family query parametresi.
- Sıralama: SID yeni/eski veya son sınıflandırılan.
- Hazır model filtreleri: Qwen V2.2 ve Gemini V2.1.

### Tablo satırı ne anlatır?

SID/REV, mesaj/protokol/classtype, entity, family, behavior, category, MITRE, karar kontrolleri, sistem/insan durumu ve rule pack eylemi. Satıra tıklanınca Rule Detail açılır; Compare linki kıyas ekranını hazırlar.

### Import işleyişi

- Bir veya birden fazla `.rules` dosyası multipart yüklenir.
- Disabled/commented kurallar atlanır.
- Çok satırlı kurallar parantez dengesi tamamlanınca birleştirilir.
- Parser header ve option alanlarını çıkarır.
- Aynı SID + REV varsa skip edilir; yeni REV ayrı immutable Rule kaydıdır.
- Import otomatik classification anlamına gelmez.

### NDR uzmanı nasıl kullanır?

Örnek ürün seçimi akışı:

1. Hedef use case’i belirle: örneğin DNS C2.
2. Category = Command and Control, protocol = dns veya ilgili MITRE ID ile filtrele.
3. FAILED ve insan incelemesi yapılmamış durumları ayır.
4. Aynı family içindeki kuralları Compare ile kıyasla.
5. Rule Detail’de raw signature, direction, HOME_NET/EXTERNAL_NET, content/PCRE, threshold ve metadata’yı doğrula.
6. İnsan review kaydı oluştur.
7. Product Planning kararı ver.
8. Rule Pack’e ekle ve `.rules` + manifest olarak dışa aktar.

### Kritik sunum nüansı

FAILED sayısının yüksek olması parser başarısızlığı değildir. Mevcut snapshot’ta parser 52.155/52.155 kuralı ayrıştırmıştır. FAILED çoğunlukla classification provider/işlem geçmişinin durumudur. “Not classified”, “classification failed” ve “invalid Suricata rule” farklı kavramlardır.

---

## 9. Rule Detail — tek kural karar ekranı

### Bu sayfa nedir?

Projenin en önemli sayfasıdır. Bir Suricata imzasının ham kaynağını, deterministik parser çıktısını, model sonucunu, MITRE provenance’ını, validator kararını, insan review’unu ve ürün planlama kararını aynı yerde birleştirir.

### Ekran bölümleri

#### Provider ve classification seçimi

- Configured default veya OpenAI, Claude, Gemini, Qwen override seçilebilir.
- Yeniden sınıflandırma `force=true` ile yeni classification geçmişi oluşturur; eski sonuç silinmez.
- Aynı kuralın birden fazla model/sürüm sonucu dropdown’dan seçilebilir.

#### Rule Decision Card

Hızlı özet: detection, MITRE evidence, validator, human review, product status ve family. “Next action” alanı, classification → validator → human review → product decision zincirindeki eksik adımı söyler.

Hazır/ready olma şartı mevcut kodda şudur:

- classification var,
- status `AUTO_CLASSIFIED`,
- validator `PASS`,
- manual review `APPROVED`.

Yine de kart açıkça false-positive ve performans ölçülmediğini söyler.

#### Original Suricata Rule

Ham imza, SID, REV ve source file. Kopyalanabilir. Analist burada action, source/destination, direction, ports, content, threshold ve metadata’yı gerçek Suricata bağlamında okur.

#### AI Classification

Behavior, entity/type, category/subcategory, MITRE tuple ve Kill Chain gösterilir. Her alan `ASSIGNED`, `ABSTAINED`, `NOT_APPLICABLE` veya eski kayıtlarda `UNAVAILABLE` olabilir.

#### Decision Assessment

- Deterministic validator sonucu.
- Semantic verifier sonucu.
- Human review durumu.
- 9 alanın karar durumu.
- Raw model confidence yalnızca kapalı teknik detayda bulunur.

`validator PASS` doğruluk veya ürün uygunluğu garantisi değildir. Sadece tanımlı kontrollerden geçtiğini söyler. Semantic check ayrıca REVIEW olabilir.

#### MITRE Provenance

- `source_mitre_mapping`: kural metadata’sındaki ilişki.
- `final_mitre_mapping`: doğrulama sonrası sistem kararı.
- Method: exact source, derived sub-technique, inferred, source overridden veya no supported mapping.
- Evidence strength: provenance gücü; genel kalite skoru değildir.
- Retrieval score: aday retrieval ilgisi; model confidence değildir.

#### System Decision

Atanan ve abstain edilen alanları, model açıklamasını, evidence listesini, validation issue ve consistency warning’leri gösterir.

#### Manual Review

- Approve, Reject, Needs Review.
- Reject için not zorunludur.
- MITRE eşleme düzeltmeleri ayrı MITRE Intelligence çalışma alanında yapılır; reason zorunludur.
- Orijinal model çıktısı korunur, override ayrı audit kaydıdır.
- Review history gösterilir.

#### Product Planning

- APPROVED_FOR_PRODUCT
- REJECTED_FOR_PRODUCT
- ALREADY_INTEGRATED

Bu durum classification review’dan ayrıdır. Ayrıntılı analist incelemesi ve ekip içi teslim için Rule Pack kullanılır; ürün planlama kartı yalnızca nihai ürün kararını kaydeder.

#### Parsed Input

Parser’ın çıkardığı action, protocol, source/destination, ports, classtype, metadata, references, flow/flowbits, contents, PCRE ve app-layer alanlarını gösterir.

#### Agent Activity

Kullanılan kanıt araçları, candidate listeleri, abstention, MITRE karar katmanı ve validator trace’i. Raw chain-of-thought değildir.

### NDR uzmanı karar verirken neye bakmalı?

1. Trafik yönü ve network değişkenleri kendi mimarisine uyuyor mu?
2. Rule yalnız IOC/IP listesi mi, davranışsal imza mı?
3. İçerik/sticky buffer doğru protokol alanında mı?
4. Threshold/rate-limit var mı?
5. Metadata MITRE association mı söylüyor, doğrudan gözlenebilir davranış mı?
6. Entity gerçekten fingerprint edilmiş mi, yalnız feed etiketi mi?
7. Kuralla NDR’ın görebileceği network telemetry örtüşüyor mu?
8. Şifreli trafikte gereken alan görünür mü?
9. Benzer/duplicate kural var mı?
10. Lab/replay trafik testinde false positive ve performans sonucu nedir?

### Demo için iyi örnek

SID `2527019` sayfası, Cobalt Strike ailesini ve abstention davranışını iyi gösteriyor: sistem behavior/entity/category atıyor fakat savunulabilir MITRE kanıtı bulamadığında MITRE/Kill Chain alanlarında abstain ediyor. Bu, “model her alanı doldurmaya zorlanmıyor” mesajı için güçlü örnektir.

---

## 10. MITRE Intelligence — ATT&CK katalog görünümü

### Bu sayfa nedir?

Katalogdaki rule ve family ilişkilerini canonical MITRE ATT&CK teknik/taktik hiyerarşisi üzerinde gösterir. Bu bir deployed sensor coverage dashboard’u değildir.

### İşleyiş

- Yerel resmi STIX 2.1 repository temel alınır.
- Mapped/unmapped rule, temsil edilen technique/sub-technique/tactic ve mapped family sayıları gösterilir.
- Sol panelde tactic lens vardır.
- Technique ID/ad araması ve technique/sub-technique filtresi bulunur.
- Her satır rule ve family sayısını gösterip detail sayfasına gider.
- “Coverage & Gap Analysis” ayrı gap ekranına bağlanır.
- Kural detayındaki “MITRE eşlemesini incele” bağlantısı bu çalışma alanındaki denetimli düzeltme formunu açar. Taktik, teknik ve ID değişiklikleri gerekçe zorunluluğuyla `classification_overrides` audit kaydına yazılır; özgün model çıktısı değişmez.

### NDR uzmanı nasıl kullanır?

- Kataloğun hangi ATT&CK alanlarında yoğunlaştığını görür.
- Bir teknik için alternatif imza/aileleri bulur.
- Content roadmap ve threat modeling çalışmasına başlangıç verisi sağlar.
- Kapsama iddiası üretmeden önce tekniğin network-visible olup olmadığını ayrıca değerlendirir.

### Gelebilecek soru

**141 teknik temsil ediliyorsa ürün ATT&CK’te %20,2 koruma sağlıyor mu?**  
Hayır. Bu yalnız katalog eşleme oranıdır. Sensor placement, telemetry, encryption, rule enablement, tuning, packet loss ve doğrulama testleri dahil değildir.

---

## 11. MITRE Technique Detail — teknik kanıt sayfası

### Bu sayfa nedir?

Tek bir ATT&CK ID’sinin canonical açıklamasını, taktiklerini, parent/sub-technique ilişkilerini, kategori/protokol dağılımını, ürün durumunu, ilgili aileleri ve gerçek rule listesini gösterir.

### İşleyiş ve kullanım

- ID canonical biçime çevrilir ve local repository’den bulunur.
- Rule count sıfırsa özel gap assessment açılır.
- “Neden gap?”, “ne biliyoruz?”, “önerilen review” ve “decision boundary” metinleri kullanıcıyı yanlış kapsam iddiasından korur.
- Alt kuralların mapping source bilgisi gösterilir.
- Rule Explorer ve Family filtrelerine çapraz geçiş yapılır.

### NDR uzmanı için değer

Bir use case’in ATT&CK açıklaması ile gerçek network imzaları arasındaki köprüdür. “Bu tekniğin adı katalogda var” ile “bu tekniği algılayan deploy edilmiş, test edilmiş kural var” arasındaki farkı görünür kılar.

---

## 12. Coverage & Gap Analysis — boşluk analizi

### Bu sayfa nedir?

697 tekniklik local repository ile katalogda temsil edilen 141 tekniği karşılaştırır; 556 temsil edilmeyen tekniği listeler ve tactic bazında coverage yüzdesi verir.

### İşleyiş

- Tactic bar’ı seçilince gap listesi filtrelenir.
- ID veya teknik adıyla arama yapılabilir.
- İlk 150 gap gösterilir; daha dar filtre önerilir.
- Gap tıklanınca technique detail sayfası açılır.

### Doğru kullanım

1. Hedef threat model/tactic seçilir.
2. Temsil edilmeyen teknik açılır.
3. Tekniğin ağdan gözlenebilirliği değerlendirilir.
4. Parent/sub-technique ve keyword/protocol araması yapılır.
5. Gerçekten network-visible ve önemliyse yeni content yazma veya kaynak bulma backlog’una alınır.

### Yanlış kullanım

- Her gap için Suricata kuralı yazılması gerektiğini düşünmek.
- Host-only bir tekniği NDR eksikliği olarak yorumlamak.
- Teknik sayısını ürün kalite puanına çevirmek.

---

## 13. Existing Rules — mevcut ürün baseline’ı

### Bu sayfa nedir?

Product Planning defterinde `ALREADY_INTEGRATED` işaretlenen kuralları ayrı bir register olarak toplar. Amaç yeni content eklemeden önce mevcut NDR kural setini hesaba katmaktır.

### İşleyiş

- Rule API’ye sabit `product_status=ALREADY_INTEGRATED` filtresi gönderilir.
- Arama ve 40’lık sayfalama vardır.
- Sayfadaki classified ve MITRE mapped metrikleri yalnız mevcut sayfadaki satırlardan hesaplanır; toplam workspace değerleri değildir.
- Satırdan Rule Detail veya Rule Pack’e geçilebilir.

### Mevcut durum

Snapshot’ta tüm 52.155 kayıt `NOT_EVALUATED`; dolayısıyla Existing Rules sayfası boştur. Demo öncesi bilerek bir kuralı `ALREADY_INTEGRATED` işaretlemediysen bu bir bug değildir.

### NDR uzmanı nasıl kullanır?

- Duplicate content eklemeyi önler.
- “Yeni aday mı, zaten üründe mi?” ayrımını netleştirir.
- Mevcut baseline ile yeni rule pack’i karşılaştırır.

---

## 14. Detection Readiness — müşteri/pentest senaryosu

### Bu sayfa nedir?

Doğal dille yazılan karmaşık bir saldırı hikâyesini 1–10 gözlenebilir adıma ayırır; her adım için canonical MITRE ve yerel katalog kanıtı arar; COVERED/PARTIAL/GAP matrisi ve kural önerileri üretir.

### İşleyiş

1. Kullanıcı senaryoyu girer ve Gemini, Claude veya OpenAI provider seçer.
2. Model yalnız bir `ScenarioPlan` üretir: summary, adımlar, olası MITRE ID, keywords, protocols, rationale ve confidence.
3. Server MITRE ID’yi local repository’de doğrular.
4. Önce exact MITRE eşleşmesi aranır.
5. Exact yoksa keyword eşleşmesi aranır.
6. O da yoksa protocol eşleşmesi aranır.
7. Exact MITRE → `COVERED`; yalnız keyword/protocol → `PARTIAL`; hiçbir kanıt yok → `GAP`.
8. Exact bulunduğunda geniş keyword sonuçları öneri listesine terfi ettirilmez; bu, generic eşleşmeyle kirlenmeyi azaltır.
9. En çok 24 unique rule önerilir ve her birinin match type/why bilgisi gösterilir.

### NDR uzmanı nasıl kullanır?

- “Pentest RDP lateral movement, PowerShell, DNS tunneling ve exfiltration kullandı; ürün alert vermedi” gibi bir vakayı davranış checkpoint’lerine ayırır.
- Hangi adımda katalogda exact MITRE kanıtı, yalnız keyword/protocol adayı veya gerçek gap olduğunu görür.
- Önerilen kuralları Rule Pack’e ekleyip daha sonra tek tek inceler.

### Çok önemli sınır

`COVERED` burada “müşteride alert üretildi” anlamına gelmez. Yalnızca local katalogda o adıma exact MITRE mapping taşıyan kural bulunduğunu söyler. Kuralın enable olması, doğru sensor noktasında çalışması ve saldırı trafiğini gerçekten yakalaması ayrıca test edilmelidir.

### Demo riski

- Seçilen provider yapılandırılmamışsa buton disabled olur.
- Mevcut snapshot’ta Gemini ve OpenAI yapılandırılmış, Claude yapılandırılmamıştır.
- Canlı model çağrısı ağ/latency/quota riski taşır. Sunumdan önce bir örnek sonucu ekran görüntüsüyle yedeklemek iyi olur.

---

## 15. Compare — kural kıyaslama sayfası

### Bu sayfa nedir?

2–4 SID’yi aynı sözleşmeyle yan yana gösterir. Amaç modelleri değil, kuralların detection evidence ve ürün hazırlığını karşılaştırmaktır.

### İşleyiş

- En az iki unique SID gerekir.
- Compare linkinden gelince ilk SID prefill edilir; kullanıcı peer SID ekler.
- Son beş comparison set browser `localStorage` içinde tutulur.
- Her kart: family, protocol, behavior, category, MITRE, MITRE evidence, validator, human review ve model bilgisi.
- Kural detail’e veya rule pack’e geçilebilir.

### NDR uzmanı nasıl kullanır?

- Aynı Cobalt Strike ailesindeki IOC tabanlı ve davranışsal kuralları kıyaslar.
- Aynı MITRE tekniğini temsil eden farklı protokol imzalarını görür.
- Duplicate veya daha zayıf kanıtlı rule’u elemek için kullanır.
- Rule pack’e en dengeli/minimal seti ekler.

### Sınır

Sayfa throughput, FP rate, CPU maliyeti, packet replay sonucu veya overlap yüzdesi hesaplamaz. Bunlar gelecekte gerçek rule-selection skoruna eklenmelidir.

---

## 16. Rule Packs — dağıtım koleksiyonu

### Bu sayfa nedir?

Kullanıcının farklı ürün, müşteri veya ortamlar için birden fazla kural listesi oluşturmasını ve seçili paketi `.rules` ile JSON manifest olarak dışa aktarmasını sağlar.

### İşleyiş

- Pack adı ve SID listesi tamamen browser `localStorage` içinde tutulur.
- Backend’de paylaşılan/persist edilen rule pack tablosu yoktur.
- Pack oluşturma, yeniden adlandırma, silme, SID ekleme/çıkarma mümkündür.
- Mapped rule ve unique technique sayıları hesaplanır.
- `.rules` export ham imzaları satır satır birleştirir.
- Manifest; format version, pack adı, timestamp, rule count, SID/REV, source, family, category ve MITRE bilgisini taşır.

### NDR uzmanı nasıl kullanır?

- Lab, pilot, perimeter, internal east-west veya müşteri bazlı paketler oluşturur.
- Seçim listesini manifest ile audit edilebilir hale getirir.
- Nihai deploy’dan önce Suricata syntax test, engine version uyumu, variable ayarı ve performance testinden geçirir.

### Gelebilecek soru

**Pack ekipler arasında paylaşılıyor mu?**  
Şu an hayır. Pack’ler o browser profilindeki localStorage’da. Export edilip paylaşılabilir; merkezi backend kaydı ve RBAC sonraki aşamadır.

**Download edilen `.rules` doğrudan production’a atılır mı?**  
Hayır. Bu bir aday content paketi. `suricata -T`, staging/replay, variable/port uyumu ve FP/performance kontrolü gerekir.

---

## 17. Model Lab — model operasyon ve karşılaştırma sayfası

### Bu sayfa nedir?

Provider konfigürasyonu, bağlantı testi ve aynı canonical rule context’i üzerinde challenger modelleri sabit Qwen3 8B referansıyla kıyaslama ekranıdır.

### İşleyiş

- Runtime settings DB üzerinden okunur/yazılır.
- API key’lerin yalnız “configured” bilgisi frontend’e döner; secret geri gösterilmez.
- Ollama URL’si yalnız localhost/127.0.0.1 olabilir.
- Qwen model adı `qwen3:8b` olarak kilitlidir.
- Gemini veya Qwen default classification provider seçilebilir.
- OpenAI, Gemini, Claude ve Ollama connection testleri minimal structured classification çağrısı yapar.
- Karşılaştırmada bir rule aranır, 1+ challenger seçilir; Qwen her zaman otomatik eklenir.
- Provider’lar aynı Rule ve aynı V2.1 context sözleşmesini alır.
- Her provider ayrı DB session ile çalışır; bir provider hatası diğerinin transaction’ını maskelemez.
- Analist OPENAI/GEMINI/CLAUDE/QWEN/BOTH_ACCEPTABLE/NEITHER/UNSURE tercihi kaydedebilir.

### Mevcut yapılandırma fotoğrafı

- Default provider: Gemini.
- Gemini model: `gemini-3.5-flash-lite`, API key configured.
- OpenAI model: `gpt-5.6-luna`, API key configured.
- Claude: yapılandırılmamış.
- Ollama: `http://127.0.0.1:11434`, `qwen3:8b` local.
- Config endpoint classifier version değeri `v1` gösterirken detail override metni V2.1 kullanıyor; sunumda version kavramlarını “runtime default”, “pipeline/classifier version” ve “Qwen batch qwen-v2.2” olarak ayır.

### NDR uzmanı nasıl kullanır?

- Aynı kuralda model farklarını evidence/abstention/MITRE açısından görür.
- Remote model ile local/offline model arasında maliyet, gizlilik, latency ve çıktı kalitesi dengesi kurar.
- Model seçimini tek bir confidence skoruna değil, reviewed benchmark ve alan bazlı hatalara dayandırır.

### Eldeki karşılaştırma sonucu nasıl anlatılmalı?

250/250 başarılı çift koşuda Gemini ortalama yaklaşık 2,45 sn/rule, Qwen yaklaşık 6,54 sn/rule çalışmıştır. 97 reviewed benchmark kaydında alan bazlı sonuçlar değişir; örneğin category exact accuracy Gemini %80,4, Qwen %78,4; MITRE ID iki modelde de %67’dir. Bu sonuçlar bu sabit run ve mevcut pipeline içindir; model ailesi hakkında evrensel iddia değildir.

50 kayıtlık bağımsız AI incelemesi human ground truth değildir. Semantik tercihte Gemini 12, Qwen 3, eşit 35; katalog kullanılabilirliğinde Gemini 36, Qwen 5, eşit 9 bulunmuştur. Bunu “accuracy” diye sunma.

---

## 18. Docs — uygulama içi mühendislik el kitabı

### Bu sayfa nedir?

Platformun mimarisini, provider farklarını, database tablolarını, API sözleşmesini, state modelini, MITRE/confidence anlamını, runbook’u ve contributor kurallarını anlatır.

### Kim kullanır?

- Yeni detection engineer: sistemin karar sınırlarını öğrenir.
- Backend/frontend geliştirici: API ve veri modeli entegrasyonunu görür.
- Ürün yöneticisi: AI review ile product approval farkını anlar.
- Operasyon ekibi: local/Docker çalışma ve production’a geçiş notlarını okur.

### Dikkat

Türkçe görünüm, İngilizce dokümanın tam ayrıntılı çevirisi değil; dokuz kısa özet bölüm sunuyor. Sunum için bu dosyadaki ayrıntılı rehberi esas al.

---

## 19. `docs-site` hakkında not

Repository’de ayrıca ayrı bir Next.js `docs-site` bulunuyor. Bu, eski V1 mimari anlatımı için hazırlanmış tek sayfalık interaktif rehberdir; mevcut React ürün uygulamasının bir route’u değildir.

Sunumda doğrudan güncel kaynak gibi kullanma; içerikte artık geçerli olmayan ifadeler var:

- Uygulamayı “iki ekranlı” olarak anlatıyor.
- Yalnız OpenAI odaklı eski pipeline metni içeriyor.
- MITRE dosyasını “kompakt ve eksik V1 kümesi” olarak anlatıyor; güncel sistem resmi local STIX repository kullanıyor.
- “İnsan düzeltmesi ve audit geçmişi yok” diyor; güncel Rule Detail’de manual review ve classification override mevcut.
- “Frontend’de pagination yok” diyor; güncel Rule Explorer’da 50’lik pagination var.

Bu site güncellenecekse mevcut sayfa haritası, provider’lar, family/MITRE/scenario/product karar akışlarıyla yeniden yazılmalıdır.

## 20. Durum sözlüğü — karıştırılmaması gereken kavramlar

### Classification status

- `AUTO_CLASSIFIED`: Şema ve tanımlı validation kontrollerinden geçti.
- `REVIEW_REQUIRED`: Bir doğrulama/kanıt sorunu analist incelemesi istiyor.
- `FAILED`: Provider veya işlem hattı çalışması başarısız oldu.
- UI’daki `UNCLASSIFIED`: Başarılı classification yok; ayrı DB enum’u olmak zorunda değil.

### Field decision

- `ASSIGNED`: Alan için değer atandı.
- `ABSTAINED`: Alan değerlendirildi fakat kanıt yetersiz olduğu için null bırakıldı.
- `NOT_APPLICABLE`: Alan mantıken uygulanabilir değil; örneğin entity yoksa entity type.
- `UNAVAILABLE`: Eski kayıtta karar metadata’sı yok.

### Manual review

- `UNREVIEWED`: İnsan kararı yok.
- `APPROVED`: Classification analistçe kabul edildi.
- `REJECTED`: Classification reddedildi.
- `NEEDS_REVIEW`: Karar daha sonra devam edecek.

### Product planning

- `NOT_EVALUATED`: Ürün kararı yok.
- `APPROVED_FOR_PRODUCT`: Ürün için onaylandı.
- `REJECTED_FOR_PRODUCT`: Ürün için reddedildi.
- `ALREADY_INTEGRATED`: Mevcut NDR baseline’ında bulunuyor.

## 21. Confidence ve kanıt sinyallerini nasıl anlatmalısın?

- Model confidence modelin kendi structured response’unda verdiği 0–1 sinyaldir.
- Bağımsız etiketlerle kalibre edilmiş doğruluk olasılığı değildir.
- Gemini ve Qwen skorları ortak bir kalite ölçeği değildir.
- Field coverage yalnız kaç alanın atandığını gösterir; doğruluk puanı değildir.
- MITRE retrieval score adayın sorguyla ilişkisini gösterir; final mapping doğruluğu değildir.
- Evidence strength mapping provenance seviyesidir; tüm classification güveni değildir.
- Validator PASS “ürüne al” kararı değildir.
- İnsan APPROVED bile gerçek ağdaki FP/performance testinin yerine geçmez.

Sunum cümlesi: “Tek bir sihirli skor üretmiyoruz; model sinyali, kanıt provenance’ı, validator, field decision, insan review ve ürün kararını ayrı eksenlerde tutuyoruz.”

## 22. Kalite ve test durumu

9 Eylül 2026’da yapılan doğrulama:

- Frontend production build: başarılı.
- Frontend behavior testleri: 13/13 başarılı.
- Backend pytest: 175 başarılı, 1 başarısız.
- Tek başarısız test: kilitlenmiş bağımsız-review artifact’ındaki 100 classification ID ile bugün kullanılan canlı `suricata_rules.db` satırlarının birebir eşleşmesini bekliyor. En az bir ID/provider/model artık eşleşmiyor.
- Bu durum parser, API veya UI işlevinin çalışmadığını göstermez; benchmark artifact ile mutable canlı katalog DB’sinin birlikte tutulmasının reproducibility riskini gösterir.

### Sunumdan önce önerilen düzeltme stratejisi

Benchmark/review paketinin doğruladığı classification satırlarını immutable bir snapshot DB’de veya content-addressed export içinde sakla. Testi canlı operasyon DB’si yerine bu snapshot’a bağla. Böylece günlük batch yeni classification eklerken locked review doğrulaması bozulmaz.

## 23. Güçlü yanlar

- Parser ve AI sorumlulukları net ayrılmış.
- SID + REV değişmezliği korunuyor.
- Aynı kural için model/sürüm geçmişi kaybolmuyor.
- AI çıktısı strict şema ve allowlist taxonomy ile sınırlandırılıyor.
- Canonical MITRE ID/name/tactic bütünlüğü denetleniyor.
- Kanıt yoksa abstention destekleniyor.
- Manual review ve product decision ayrı audit eksenleri.
- Aile ataması similarity yerine açıklanabilir provenance ile yapılıyor.
- Scenario analysis’te model planı ile yerel kanıt ayrılıyor.
- Katalog asistanı read-only, sınırlı ve local-only.
- Remote API ve local Qwen aynı canonical sözleşmede kıyaslanabiliyor.
- Rule pack çıktısı ham rule ile makinece okunabilir manifesti birlikte sunuyor.

## 24. Mevcut sınırlar ve dürüst cevaplar

### Ürün selection skoru yok

Şu an false-positive, prevalence, performance cost, rule overlap, CVE severity, asset relevance ve network visibility birleşik bir ranking oluşturmaz. Kullanıcı kanıtları görüp manuel karar verir.

### Rule pack merkezi değil

Pack’ler browser localStorage’da; RBAC, ekip paylaşımı, backend audit ve approval workflow yok.

### Authentication yok

Özellikle model uçları bu nedenle local-only korunuyor. Kurumsal kullanım için authn/authz, secret manager ve distributed rate limiting gerekir.

### SQLite operasyonel sınırı

Canlı batch ve yoğun okuma/yazma için PostgreSQL, background queue/worker, job monitoring ve migration yönetimi daha uygundur.

### Aile modeli tek primary family

Çok eksenli tag/family ilişkileri desteklenmiyor. Aynı kural hem tool hem CVE hem behavior boyutunda analiz edilmek istenirse ayrı tag/secondary-family modeli gerekir.

### Katalog mapping’i deployed coverage değildir

Sensor placement, encrypted traffic visibility, rule enablement, HOME_NET değişkenleri, packet loss, engine version ve tuning sonucu sisteme dahil değildir.

### Gerçek üretim validasyonu eksik

PCAP replay, `suricata -T`, Eve JSON alert doğrulaması, FP dataset, throughput/CPU/RAM ölçümü rule kararına otomatik bağlanmıyor.

## 25. Yarınki sunum için önerilen demo akışı

### 8–10 dakikalık akış

1. **Detection Catalog:** 52 bin kuralı ve doğal dil asistanının güvenli sınırını anlat.
2. **Families:** “Cobalt Strike” ara; açıklanabilir gruplamayı ve düşük ama konservatif coverage’ı göster.
3. **Rule Detail / SID 2527019:** raw rule → parsed input → AI classification → abstained MITRE → validator → human review → product decision zincirini göster.
4. **MITRE Intelligence:** represented technique ile deployed coverage ayrımını anlat.
5. **Detection Readiness:** hazır bir pentest senaryosu üzerinden matrix ve candidate rule’ları göster; canlı çağrı başarısız olursa önceden alınmış ekran görüntüsüne geç.
6. **Compare:** aynı aileden 2–3 rule’u yan yana koy.
7. **Rule Packs:** inceleme için bir pack oluştur, analiz ekibine `.rules` ve manifest çıktısını gönder; bunun production deploy olmadığını açıkla.
8. **Model Lab:** aynı canonical context, farklı provider, immutable history ve Qwen reference yaklaşımını anlat.

### Demo sırasında yapmaman gerekenler

- Rastgele büyük `.rules` import etme.
- Canlı classification batch başlatma.
- İnsan review/product decision kayıtlarını plansız değiştirme.
- Rule pack’i “production-ready” diye adlandırma.
- Confidence değerini accuracy yüzdesi gibi okuma.
- MITRE %20,2’yi NDR detection coverage olarak sunma.
- Existing Rules boşken bug varmış gibi davranma.

## 26. Muhtemel jüri/izleyici soruları ve kısa cevaplar

**Bu proje neden sadece ChatGPT’ye bir rule sormaktan daha iyi?**  
Çünkü parser, şema, taxonomy, canonical MITRE doğrulaması, cache, model provenance, field-level abstention, human review ve product ledger sağlar. Sonuç tekrarlanabilir ve denetlenebilir bir kayıt olur.

**AI yanlışsa ne oluyor?**  
Çıktı strict şemadan ve validator’dan geçer; riskli sonuç REVIEW_REQUIRED olabilir. Analist reject/edit yapabilir; orijinal çıktı silinmez. Yine de validator her semantik hatayı garantiyle yakalamaz.

**Model her alanı doldurmak zorunda mı?**  
Hayır. Kanıt yetersizse ABSTAINED, mantıken uygulanmıyorsa NOT_APPLICABLE kullanılır.

**Rule gerçekten saldırıyı yakalar mı?**  
Katalog bunu tek başına kanıtlamaz. PCAP replay, sensor telemetry, variable config, encryption visibility ve performance/FP testi gerekir.

**MITRE mapping nereden geliyor?**  
Önce Suricata metadata’sındaki source mapping ve local repository adayları değerlendirilir; final mapping canonical ID/name/tactic doğrulamasından geçer ve yöntemi ayrı saklanır.

**Neden local Qwen var?**  
Offline/gizlilik ve maliyet kontrolü için yerel referans sağlar. Aynı canonical context ve validation pipeline kullanıldığı için remote provider’larla karşılaştırılabilir.

**Neden Qwen sabit?**  
Karşılaştırma baseline’ının model adı değişerek kaymaması için `qwen3:8b` referans olarak kilitlenmiştir.

**Cache nasıl çalışıyor?**  
Aynı Rule kaydında başarılı sonuç varsa normal sınıflandırma onu döndürür. `force=true` bilinçli yeniden sınıflandırmada yeni geçmiş kaydı oluşturur.

**Veri modeli neden SID + REV?**  
Suricata kural revizyonunu ezmemek, eski ve yeni imzayı ayrı immutable kayıt olarak izlemek için.

**Asistan SQL injection yapabilir mi?**  
Model SQL üretmez. Allowlist filter plan üretir; Pydantic doğrular, SQLAlchemy bound query çalıştırır. Wildcard’lar veri olarak escape edilir.

**Aileler neden embedding ile değil?**  
Ürün kararında yanlış gruplama riskini azaltmak ve “neden bu ailede?” sorusuna somut provenance göstermek için.

**Aile coverage neden düşük?**  
Kanıt yoksa abstain edildiği için. Yüksek kapsama uğruna spekülatif aile üretilmiyor.

**Model confidence ne kadar güvenilir?**  
Self-reported ve kalibre edilmemiştir; accuracy olasılığı değildir. Reviewed benchmark ve alan bazlı hata metrikleri daha anlamlıdır.

**Gemini mi Qwen mi daha iyi?**  
Tek bir evrensel cevap yok. Mevcut sabit karşılaştırmada Gemini genel katalog kullanılabilirliğinde daha güçlü görünürken bazı alanlarda fark küçük, behavior exact match’te Qwen daha iyi çıkmıştır. Sonuç run/pipeline/sample’a bağlıdır.

**Neden FAILED çok yüksek?**  
FAILED classification denemesinin durumudur; parser hatası değildir. Import edilen ama başarılı sınıflandırması bulunmayan veya provider/batch hatası yaşamış kayıtlar bu görünümü oluşturabilir.

**Ürüne alma kararı nasıl veriliyor?**  
AI classification → validator → insan review → network/lab değerlendirmesi → Product Planning → Rule Pack. AI tek başına approve etmez.

**Sistem production-ready mi?**  
Analiz ve içerik karar desteği için güçlü bir prototip/çalışma alanıdır. Kurumsal production için auth/RBAC, PostgreSQL, worker queue, secret management, shared packs, deployment validation ve gözlemlenebilirlik gerekir.

## 27. Kapanış mesajı

“Bu proje AI ile otomatik olarak production kuralı seçen bir kara kutu değil. Ham Suricata imzasından başlayıp canonical MITRE, field-level abstention, validator, insan review ve ürün kararına kadar her adımı ayrı ve incelenebilir tutan bir detection engineering çalışma alanıdır. Amacımız analistin yerini almak değil; 52 bin kural içinden daha hızlı, daha tutarlı ve daha kanıtlı karar verebilmesini sağlamaktır.”
