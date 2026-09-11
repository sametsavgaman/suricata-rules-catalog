# Katalog asistanı — uygulama sözleşmesi

Detection Catalog içindeki **Kataloğa sor** alanı mevcut Gemini modelini kullanır.
Her soru bağımsızdır; sohbet geçmişi saklanmaz. Soru Google'a gönderilir. DB kayıtları,
raw rule, runtime ayarları ve anahtarlar prompt'a eklenmez. Statik taxonomy ve sistem
talimatı sunucuda tutulur; frontend isteği yalnız `question` içerir.

## Akış

1. `POST /api/catalog/assistant/ask` gövdesi: `{"question":"C2 kurallarını getir"}`.
2. Gemini `generate_content` ile CatalogPlan JSON üretir. SQL, URL, araç, rol veya
   serbest cevap alanı yoktur. Çıktı backend'de extra=forbid ile tekrar doğrulanır.
3. LIST_RULES / COUNT_RULES veya LIST_FAMILIES / COUNT_FAMILIES için SQLAlchemy
   izin verilen filtrelerle sorgu kurar.
4. Her SID/REV için en yüksek ID'li başarısız olmayan classification seçilir.
   Provider filtresi varsa seçim o sağlayıcı içinde yapılır. Kategori gibi içerik
   filtreleri son başarılı sonuç üzerinde uygulanır, eski etiketler üzerinden değil.
5. Backend toplamı ve sayfalı kayıtları döndürür. Sayı/özet backend kaynaklıdır.
   EXPLAIN_TOPIC cevapları denetlenmiş platform metinleridir.
6. Sonraki sayfa: `POST /api/catalog/assistant/search` —
   `{"filters":{"category":"Command and Control"},"offset":12,"limit":12}`.
   Bu işlemde Gemini çağrılmaz.

## Senaryo analizi

`POST /api/catalog/assistant/scenario` gövdesi `{"question":"...","provider":"gemini"}` kabul eder.
`provider` değeri `gemini`, `claude` veya `openai` olabilir; arayüzde `openai` Codex / OpenAI
olarak gösterilir. Model Lab'de anahtar ve model tanımlı olmayan sağlayıcılar devre dışı kalır.
Gemini burada serbest bir sonuç üretmez; saldırı anlatısını 1–10 gözlemlenebilir adıma,
MITRE ID'lerine, kısa anahtar kelimelere ve protokollere ayıran `ScenarioPlan` JSON'u
çıkarır. Backend her ID'yi yerel ATT&CK deposunda doğrular ve her adım için yerel
katalogdan exact-MITRE, keyword veya protocol kanıtı arar. `COVERED`, `PARTIAL` ve
`GAP` durumu bu yerel kanıttan deterministik hesaplanır; modelin iddia ettiği kapsam,
SID veya alarm performansı kabul edilmez. Exact MITRE eşleşmesi varsa geniş keyword /
protocol sonuçları öneri listesine yükseltilmez. Endpoint kayıtları değiştirmez ve
dakikada en fazla dört senaryo isteğine izin verir.

Filtreler VE ile birleşir: family_name, category, subcategory, detected_entity, mitre_tactic,
mitre_technique_id, protocol, provider, product_status, entity_status, mitre_status,
search. Ek filtreler: entity_type, model_name, classifier_version, inspection_batch,
cyber_kill_chain_phase, has_cve, classification_status. Provider `openai`,
`gemini`, `claude` veya `ollama` olabilir. Doğal dil planında GPT, OpenAI ve
Codex ifadeleri `openai`; Claude `claude`; Qwen ise `ollama` olarak
kanonikleştirilir. LIKE jokerleri literal aranır.
NOT_EVALUATED, ürün kararı satırı bulunmayan kayıtları da kapsar. Sonuçlar SID, REV
ve classification ID azalan sıradadır. Model confidence sıralama/uygunluk ölçüsü değildir.

## Sınırlar ve güvenlik

- Mevcut uygulamada kullanıcı authentication yok: yeni endpoint'ler doğrudan
  loopback bağlantı + yerel Host kontrolüyle sınırlandırılır. Forwarded headers
  erişim izni vermek için kullanılmaz. İzinli frontend Origin'leri kontrol edilir.
- Vite ve API'yi localhost'a bağlayın. Auth'suz reverse proxy ile internete açmayın:
  proxy loopback'ten gelen istek gibi görünür. LAN/çok kullanıcılı kullanım için
  kimlik doğrulama, kullanıcı yetkileri ve ortak kota deposu gereklidir.
- Catalog sorusu 3–1000, senaryo sorusu 10–3000 karakter; gövde 8 KiB; sayfa 1–50 kayıt; offset en fazla 1.000.000.
- Süreç başına dakikada 6 Gemini sorusu / 60 sayfa sorgusu; bir aktif Gemini çağrısı.
  Limitler bellek içindedir, restart ile sıfırlanır; dağıtık kota değildir.
- Gemini çağrısı toplam 30 saniye; yalnız transient HTTP hatalarında bir tekrar,
  2 saniye bekleme. SDK otomatik retry kapalı. SQLite sorgusu 5 saniyelik VM bütçesi.
- Asistan kayıt güncellemez; serializer yalnız açıkça seçilmiş alanları döndürür.
  HTML/Markdown model çıktısı render edilmez. React kaynak metnini escape eder.
- Model hiçbir katalog satırı, raw rule veya family sonucu görmez. Kayıt içindeki
  prompt-injection benzeri metinler yalnız yerel SQL sonucunda data olarak kalır.
- Hata cevapları sabittir: provider exception/credential/prompt içeriği dönmez.
- Ürün uygunluğu ve yanlış pozitif riski modelden otomatik onay olarak çıkarılmaz.
  Belirsiz, OR, desteklenmeyen veya yazma isteyen sorgular daraltılır/reddedilir.

Bu kontroller tüm uygulama için bağımsız bir penetration test ya da sıfır açık
garantisi değildir. Soru yorumlama yanlış olabilir: kullanıcıya uygulanan filtreler
gösterilir. Catalog sonuçları ground truth değildir. Backend erişim logları soru
gövdesini yazmaz; deployment proxy/log ayarları ayrıca kontrol edilmelidir.

## Doğrulama

`backend`: `.\.venv\Scripts\python.exe -m pytest -q tests/test_catalog_assistant.py`

`frontend`: `node --test tests/catalog-assistant.test.mjs` ve `npm run build`.

Testler: SQL/wildcard injection, extra fields, canonical MITRE, read-only SQL,
provider seçimi, failed attempt exclusion, varsayılan ürün durumu, sayfalama,
Origin/Host/uzak erişim, gövde limiti, rate limit, sanitized error ve XSS escaping.
