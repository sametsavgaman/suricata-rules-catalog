"use client";

import { useMemo, useState } from "react";
import { ArrowDown, ArrowRight, Bot, Braces, CheckCircle2, ChevronRight, CircleAlert, Database, FileCode2, Filter, FolderTree, Gauge, GitBranch, Layers3, Monitor, Network, Search, Server, ShieldCheck, TestTube2, Upload, X } from "lucide-react";

const flow = [
  { icon: FileCode2, label: ".rules dosyası", note: "Yükle & çok satırı birleştir" },
  { icon: Braces, label: "Deterministik parser", note: "Suricata → tipli alanlar" },
  { icon: Database, label: "SQL veritabanı", note: "SID + REV ile sakla" },
  { icon: ShieldCheck, label: "AI + doğrulama", note: "Sınıflandır & denetle" },
];

const steps = [
  { n:"01", title:"Dosya yüklenir", file:"api/rules.py", text:"React arayüzü bir veya daha fazla .rules dosyasını multipart olarak POST /api/rules/import adresine yollar." },
  { n:"02", title:"Kurallar ayrılır", file:"ingestion/rule_loader.py", text:"Boş ve # ile başlayan satırlar atlanır. Parantez dengesi izlenerek çok satırlı kurallar tek metne dönüştürülür." },
  { n:"03", title:"Sözdizimi çözülür", file:"parser/suricata_parser.py", text:"7 parçalı başlık ile option bloğu ayrılır; tırnak, kaçış karakteri ve adres listeleri bozulmadan işlenir." },
  { n:"04", title:"Kayıt kalıcılaşır", file:"database/repository.py", text:"Aynı SID + REV varsa atlanır; yeni revizyon ayrı ve değişmez bir Rule kaydı olarak eklenir." },
  { n:"05", title:"İpuçları üretilir", file:"enrichment/deterministic_enrichment.py", text:"Mesaj ve content alanlarında bilinen araç adları aranır; ET öneki kategori ipucuna çevrilir. Bunlar kanıt değil, yardımcı sinyaldir." },
  { n:"06", title:"Tek AI çağrısı yapılır", file:"agent/classifier.py", text:"Sınırlandırılmış ClassificationContext, Responses API üzerinden doğrudan katı Pydantic şemasına ayrıştırılır. store=false kullanılır." },
  { n:"07", title:"Çıktı doğrulanır", file:"validation/classification_validator.py", text:"MITRE ID biçimi, yerel adayda bulunma, ad/taktik eşleşmesi ve temel davranış çelişkileri kontrol edilir." },
  { n:"08", title:"Sonuç sunulur", file:"services/ → API → React", text:"Sonuç durumuyla birlikte veritabanına yazılır. Dashboard istatistikleri ve RuleDetail kanıtları son sınıflandırmayı gösterir." },
];

type FileItem = { path:string; role:string; detail:string; tags:string[] };
const fileGroups: {name:string; tone:string; files:FileItem[]}[] = [
  { name:"Backend · giriş ve API", tone:"green", files:[
    {path:"backend/app/main.py",role:"Uygulama başlangıcı",detail:"FastAPI nesnesini kurar, CORS ekler, tabloları açılışta oluşturur ve rules/classification/stats router’larını bağlar.",tags:["fastapi","api"]},
    {path:"backend/app/config.py",role:"Merkezi ayarlar",detail:"DATABASE_URL, model, CORS origin ve modele gidecek content bütçelerini ortam değişkenlerinden okur; sonucu önbellekler.",tags:["config"]},
    {path:"backend/app/api/rules.py",role:"Kural HTTP uçları",detail:"Listeleme, filtreleme, arama, detay ve çoklu dosya import akışını yönetir. En güncel classification kaydıyla outer join yapar.",tags:["api","import"]},
    {path:"backend/app/api/classification.py",role:"Sınıflandırma uçları",detail:"Tek SID için sınıflandırma ve en fazla 1000 kuralı sıralı işleyen toplu sınıflandırma uçlarını sunar.",tags:["api","ai"]},
    {path:"backend/app/api/stats.py",role:"Özet istatistikler",detail:"Her rule için son classification’ı baz alarak durum, kategori, varlık, MITRE ve ortalama güven metriklerini SQL ile hesaplar.",tags:["api","sql"]},
    {path:"backend/app/api/schemas.py",role:"API sözleşmeleri",detail:"Okuma, import, batch ve istatistik Pydantic modellerini tanımlar; ORM Rule nesnesini API yanıtına çevirir.",tags:["api","schema"]},
    {path:"backend/app/api/dependencies.py",role:"Bağımlılık birleştirme",detail:"DB oturumu, OpenAI provider, ayarlar ve MITRE deposunu ClassificationService içinde bir araya getirir.",tags:["api","wiring"]},
  ]},
  { name:"Backend · içe alma ve ayrıştırma", tone:"orange", files:[
    {path:"backend/app/ingestion/rule_loader.py",role:"Fiziksel dosya okuyucu",detail:"Yorumları/boş satırları sayar; parantez ve tırnak durumunu izleyerek çok satırlı kuralları birleştirir.",tags:["parser","import"]},
    {path:"backend/app/parser/option_parser.py",role:"Option tokenizer",detail:"Tırnak dışındaki noktalı virgül ve virgüllerde bölme, ilk güvenli iki noktayı bulma ve quote kaldırma yardımcılarını içerir.",tags:["parser"]},
    {path:"backend/app/parser/suricata_parser.py",role:"Ana Suricata parser",detail:"Başlık ve option sınırlarını bulur; SID/REV, content, PCRE, flow, flowbits ve uygulama katmanı seçicilerini ParsedRule’a dönüştürür.",tags:["parser","core"]},
    {path:"backend/app/parser/models.py",role:"Parser veri modelleri",detail:"RuleOption, ParsedRule ve açık RuleParseError tiplerini tanımlar. Bilinmeyen option’lar options içinde korunur.",tags:["parser","schema"]},
  ]},
  { name:"Backend · AI, bilgi ve doğrulama", tone:"lime", files:[
    {path:"backend/app/services/classification_service.py",role:"Ana orkestrasyon",detail:"Cache kontrolü, deterministik ipucu, bağlam budama, provider çağrısı, doğrulama, durum seçimi ve kayıt işlemlerinin tek sahibidir.",tags:["core","ai","cache"]},
    {path:"backend/app/enrichment/deterministic_enrichment.py",role:"Açıklanabilir ipuçları",detail:"Nmap, AnyDesk, Cobalt Strike gibi varlıkları ve ET SCAN/MALWARE/EXPLOIT gibi önekleri regex/sözlük ile yakalar.",tags:["enrichment"]},
    {path:"backend/app/agent/classifier.py",role:"OpenAI adaptörü",detail:"Provider protokolünü uygular; tek Responses API parse çağrısıyla ClassificationOutput üretir. API anahtarı yoksa anlaşılır hata verir.",tags:["ai","openai"]},
    {path:"backend/app/agent/prompt.py",role:"Sistem talimatı",detail:"Muhafazakâr sınıflandırma, spekülasyondan kaçınma, yalnız aday MITRE kayıtlarını kullanma ve somut kanıt gösterme kurallarını taşır.",tags:["ai","prompt"]},
    {path:"backend/app/agent/schemas.py",role:"AI giriş/çıkış şeması",detail:"İzinli entity/category/kill-chain alanlarını, 0–1 güveni, kanıt sınırını ve modele giden ClassificationContext’i tanımlar.",tags:["ai","schema"]},
    {path:"backend/app/validation/classification_validator.py",role:"İkinci savunma hattı",detail:"MITRE üçlüsünün bütünlüğünü, biçimini ve yerel kayıtla tutarlılığını denetler; sorun varsa REVIEW_REQUIRED üretir.",tags:["validation","mitre"]},
    {path:"backend/app/knowledge/mitre_repository.py",role:"Yerel MITRE deposu",detail:"Kompakt JSON’u tembel yükler; ID ile bulur ve modele yalnız id/name/tactics biçiminde sınırlı aday listesi verir.",tags:["knowledge","mitre"]},
    {path:"backend/app/knowledge/taxonomy.py",role:"İzinli kategori sözlüğü",detail:"20 kategori enum’unu ve bazı kategoriler için önerilen alt kategori listelerini tanımlar.",tags:["knowledge"]},
    {path:"backend/app/knowledge/kill_chain.py",role:"Kill Chain enum’u",detail:"Lockheed Martin Cyber Kill Chain’in yedi fazını model çıktısında izinli değerler olarak sınırlar.",tags:["knowledge"]},
  ]},
  { name:"Backend · veri katmanı", tone:"blue", files:[
    {path:"backend/app/database/models.py",role:"SQLAlchemy tabloları",detail:"Rule ve Classification tablolarını, JSON liste alanlarını, SID+REV benzersizliğini ve bire-çok ilişkiyi tanımlar.",tags:["database","schema"]},
    {path:"backend/app/database/session.py",role:"DB bağlantısı",detail:"SQLite için thread ayarını, ortak engine’i, SessionLocal fabrikasını ve FastAPI get_db yaşam döngüsünü kurar.",tags:["database"]},
    {path:"backend/app/database/repository.py",role:"Rule erişim katmanı",detail:"SID+REV ekleme/atlama, en yeni revizyonu bulma ve başarılı sonucu olmayan kuralları seçme sorgularını kapsüller.",tags:["database","repository"]},
  ]},
  { name:"Frontend", tone:"purple", files:[
    {path:"frontend/src/main.tsx",role:"React başlangıcı",detail:"StrictMode içinde App’i #root öğesine bağlar ve global stilleri yükler.",tags:["frontend"]},
    {path:"frontend/src/App.tsx",role:"İstemci rotaları",detail:"Ana dashboard ve /rules/:sid detay görünümünü BrowserRouter ile eşler.",tags:["frontend","routing"]},
    {path:"frontend/src/pages/Dashboard.tsx",role:"Liste ve kontrol yüzeyi",detail:"İstatistikleri ve kuralları paralel yükler; arama/filtreleri query string’e çevirir ve .rules importunu yönetir.",tags:["frontend","ui"]},
    {path:"frontend/src/pages/RuleDetail.tsx",role:"Analist detay yüzeyi",detail:"Ham kural, ayrıştırılmış JSON, AI sınıflandırması, kanıtlar ve validation sorunlarını gösterir; zorla yeniden sınıflandırabilir.",tags:["frontend","ui"]},
    {path:"frontend/src/services/api.ts",role:"HTTP istemcisi",detail:"Fetch hata yönetimini ve stats/rules/import/classify çağrılarını tipli küçük fonksiyonlarda toplar.",tags:["frontend","api"]},
    {path:"frontend/src/types/index.ts",role:"TypeScript sözleşmeleri",detail:"Backend Rule, Classification, Stats ve üç durum değerinin istemci tarafı karşılığını tanımlar.",tags:["frontend","schema"]},
    {path:"frontend/src/components/StatusBadge.tsx",role:"Durum göstergesi",detail:"AUTO_CLASSIFIED, REVIEW_REQUIRED, FAILED ve henüz sınıflandırılmamış durumları görsel etikete çevirir.",tags:["frontend","ui"]},
  ]},
  { name:"Çalıştırma, veri ve kalite", tone:"gray", files:[
    {path:"docker-compose.yml",role:"Üç servisli çalışma ortamı",detail:"PostgreSQL 17, FastAPI backend ve Nginx üstünde frontend’i healthcheck ve portlarla birlikte ayağa kaldırır.",tags:["docker","ops"]},
    {path:"backend/Dockerfile",role:"Backend imajı",detail:"Python 3.13 slim üzerinde gereksinimleri, backend’i ve MITRE datasını kopyalar; Uvicorn başlatır.",tags:["docker","backend"]},
    {path:"frontend/Dockerfile + nginx.conf",role:"Frontend imajı",detail:"Node 22 ile üretim build’i alır; statik dosyaları Nginx’te sunar ve /api ile /health çağrılarını backend’e proxy eder.",tags:["docker","frontend"]},
    {path:"data/mitre/enterprise-techniques.json",role:"Kompakt yerel bilgi",detail:"Modelin seçebileceği enterprise ATT&CK tekniklerinin ID, ad, taktik ve kısa açıklamalarını taşır; bilerek eksik bir V1 kümesidir.",tags:["data","mitre"]},
    {path:"data/samples/v1-synthetic.rules",role:"Sentetik örnek seti",detail:"Gerçek Emerging Threats içeriği olduğu iddia edilmeyen 20 test kuralını içerir.",tags:["data","test"]},
    {path:"backend/tests/",role:"Davranış güvencesi",detail:"Parser uç durumları, enrichment, MITRE validation, tek çağrı/cache ve 20 kurallık API akışını kapsayan pytest testleridir.",tags:["test","quality"]},
  ]},
];

const endpoints = [
  ["GET", "/api/rules", "Kuralları son classification ile listeler; kategori, entity, MITRE, durum, protokol, güven ve metinle filtreler."],
  ["GET", "/api/rules/{sid}", "SID’nin en yeni revizyonunu ve son classification kaydını döndürür."],
  ["POST", "/api/rules/import", "Bir veya daha fazla .rules dosyasını ayrıştırır; imported/skipped/error sayılarını verir."],
  ["POST", "/api/rules/{sid}/classify", "Başarılı cache varsa döndürür; force=true yeni bir sınıflandırma kaydı üretir."],
  ["POST", "/api/classify/all", "Başarılı sonucu olmayan kuralları limit dahilinde sıralı ve birbirinden izole işler."],
  ["GET", "/api/stats", "Son classification’lara göre toplam, durum dağılımı, top entity/MITRE ve ortalama güven üretir."],
  ["GET", "/health", "Basit liveness yanıtı verir."],
];

function FileExplorer(){
  const [query,setQuery]=useState("");
  const filtered=useMemo(()=>fileGroups.map(g=>({...g,files:g.files.filter(f=>(f.path+f.role+f.detail+f.tags.join(" ")).toLocaleLowerCase("tr").includes(query.toLocaleLowerCase("tr")))})).filter(g=>g.files.length),[query]);
  const total=filtered.reduce((n,g)=>n+g.files.length,0);
  return <div className="file-explorer">
    <div className="file-toolbar"><label><Search size={17}/><input value={query} onChange={e=>setQuery(e.target.value)} placeholder="Dosya, katman veya kavram ara…" aria-label="Dosya rehberinde ara"/>{query&&<button onClick={()=>setQuery("")} aria-label="Aramayı temizle"><X size={15}/></button>}</label><span><Filter size={14}/>{total} kayıt</span></div>
    <div className="file-groups">{filtered.map(group=><section className={`file-group ${group.tone}`} key={group.name}><h3>{group.name}<small>{group.files.length}</small></h3>{group.files.map(file=><details key={file.path}><summary><span><code>{file.path}</code><b>{file.role}</b></span><ChevronRight size={17}/></summary><div className="file-detail"><p>{file.detail}</p><div>{file.tags.map(t=><span key={t}>{t}</span>)}</div></div></details>)}</section>)}</div>
    {!total&&<p className="no-results">Bu aramayla eşleşen dosya bulunamadı.</p>}
  </div>
}

export default function Home() {
  return (
    <main>
      <header className="topbar">
        <a className="brand" href="#ust"><span className="brand-mark">SR</span><span>Suricata Rule Agent<br/><small>Mimari Rehberi</small></span></a>
        <nav aria-label="Sayfa bölümleri"><a href="#mimari">Mimari</a><a href="#akis">Akış</a><a href="#dosyalar">Dosyalar</a><a href="#notlar">Teknik notlar</a></nav>
        <span className="version">V1 · kaynak kod analizi</span>
      </header>

      <section className="hero" id="ust">
        <div><p className="eyebrow">PROJEYİ 15 DAKİKADA KAVRA</p><h1>Bir Suricata kuralı,<br/><em>nasıl bilgiye dönüşüyor?</em></h1><p className="lede">Bu proje; ham <code>.rules</code> dosyalarını deterministik olarak ayrıştırır, açıklanabilir ipuçları üretir, her yeni kural revizyonu için tek bir yapılandırılmış AI çağrısı yapar ve sonucu yerel MITRE bilgisiyle doğrular.</p><div className="hero-actions"><a className="primary" href="#mimari">Mimariyi keşfet <ArrowDown size={16}/></a><span>FastAPI · React · SQLAlchemy · OpenAI</span></div></div>
        <aside className="at-a-glance"><p className="card-kicker">TEK BAKIŞTA</p><dl><div><dt>Girdi</dt><dd>Suricata <code>.rules</code></dd></div><div><dt>Kimlik</dt><dd><code>SID + REV</code></dd></div><div><dt>AI çağrısı</dt><dd>Önbelleksiz revizyon başına 1</dd></div><div><dt>Çıktı</dt><dd>Davranış, varlık, kategori, MITRE, güven</dd></div><div><dt>Durum</dt><dd>Otomatik · İnceleme · Hatalı</dd></div></dl></aside>
      </section>

      <section className="section" id="mimari"><div className="section-heading"><span>01</span><div><p className="eyebrow">BÜYÜK RESİM</p><h2>Katmanlı, kontrollü ve açıklanabilir</h2></div></div><p className="section-intro">Ana fikir basit: sözdizimi ve veri hazırlama kodla çözülür; AI yalnızca anlamlandırma aşamasında devreye girer. AI çıktısı da doğrudan kabul edilmez, yerel kurallarla denetlenir.</p><div className="pipeline" aria-label="Projenin ana işlem akışı">{flow.map(({icon:Icon,label,note},i)=><div className="flow-wrap" key={label}><article className="flow-card"><Icon size={22}/><b>{label}</b><small>{note}</small></article>{i<flow.length-1&&<span className="connector">→</span>}</div>)}</div>
        <div className="layer-map">
          <article><Upload/><b>Ingestion + Parser</b><p>Dosya biçimini ve Suricata sözdizimini bilir. AI veya veritabanı kararı vermez.</p><code>ingestion/ · parser/</code></article>
          <article><Bot/><b>Enrichment + Agent</b><p>Açıklanabilir ipuçları ve katı şemalı tek model çağrısı üretir.</p><code>enrichment/ · agent/</code></article>
          <article><CheckCircle2/><b>Validation + Service</b><p>Güven sınırını ve tutarlılığı denetler; cache, durum ve persistence akışını yönetir.</p><code>validation/ · services/</code></article>
          <article><Server/><b>API + UI</b><p>Sonuçları filtrelenebilir HTTP sözleşmesi ve iki ekranlı analist deneyimi olarak sunar.</p><code>api/ · frontend/</code></article>
        </div>
      </section>

      <section className="principles"><article><span>01</span><h3>Parser AI değildir</h3><p>Suricata sözdizimi her zaman aynı Python koduyla ayrıştırılır. Sonuç tekrarlanabilir ve test edilebilirdir.</p></article><article><span>02</span><h3>AI sınırlandırılmıştır</h3><p>Modele ham dosya değil, boyutu sınırlı ve yapılandırılmış bir bağlam ile izin verilen MITRE adayları gönderilir.</p></article><article><span>03</span><h3>Son söz validatördedir</h3><p>MITRE ID, ad ve taktik tutarsızsa kayıt silinmez; analist incelemesine yönlendirilir.</p></article></section>

      <section className="section" id="akis"><div className="section-heading"><span>02</span><div><p className="eyebrow">UÇTAN UCA</p><h2>Bir kuralın yolculuğu</h2></div></div><p className="section-intro">Aşağıdaki zincir hem import hem de sınıflandırma akışını bir arada gösterir. Her aşamanın tek bir net sorumlusu vardır.</p><div className="journey">{steps.map((s,i)=><article key={s.n}><div className="step-no">{s.n}</div><div><h3>{s.title}</h3><code>{s.file}</code><p>{s.text}</p></div>{i<steps.length-1&&<ArrowDown className="step-arrow" size={18}/>}</article>)}</div>
        <div className="decision-grid"><article className="decision-card cache"><GitBranch/><div><p className="eyebrow">CACHE KARARI</p><h3>Aynı kural tekrar sınıflandırılır mı?</h3><p><code>force=false</code> iken aynı Rule kaydına bağlı FAILED olmayan bir sonuç varsa API onu döndürür. Böylece aynı <strong>SID + REV</strong> için gereksiz model çağrısı yapılmaz. <code>force=true</code> yeni bir Classification geçmişi yaratır.</p></div></article><article className="decision-card status"><Gauge/><div><p className="eyebrow">DURUM KARARI</p><h3>Üç sonuç, üç anlam</h3><ul><li><b>AUTO_CLASSIFIED</b> — şema ve yerel kontroller temiz.</li><li><b>REVIEW_REQUIRED</b> — çıktı saklanır fakat validation issues analiste gösterilir.</li><li><b>FAILED</b> — provider, şema veya başka hata açıklamasıyla saklanır; batch devam eder.</li></ul></div></article></div>
      </section>

      <section className="dark-section" id="dosyalar"><div className="dark-inner"><div className="section-heading"><span>03</span><div><p className="eyebrow">İNTERAKTİF HARİTA</p><h2>Hangi dosya ne yapıyor?</h2></div></div><p className="section-intro">Bir dosyayı adına, katmanına veya kavrama göre ara. Satırı açtığında dosyanın mimarideki gerçek sorumluluğunu görürsün.</p><FileExplorer/></div></section>

      <section className="section data-section"><div className="section-heading"><span>04</span><div><p className="eyebrow">VERİ MODELİ</p><h2>Rule değişmez, Classification tarihçe tutar</h2></div></div><p className="section-intro">Aynı SID’nin yeni revizyonu yeni Rule satırıdır. Yeniden sınıflandırma ise Rule’u değiştirmez; yeni Classification satırı ekler.</p><div className="entity-diagram"><article><header><Database size={18}/><b>rules</b><span>1</span></header><ul><li><strong>id</strong> · PK</li><li><strong>sid + rev</strong> · UNIQUE</li><li>raw_rule + header alanları</li><li>metadata / references / flow</li><li>contents / pcre / app_layer</li><li>source_file + created_at</li></ul></article><div className="relation"><span>1</span><i/><span>N</span><small>bir kuralın sınıflandırma geçmişi</small></div><article><header><Bot size={18}/><b>classifications</b><span>N</span></header><ul><li><strong>id</strong> · PK, <strong>rule_id</strong> · FK</li><li>behavior / entity / category</li><li>MITRE tactic / technique / ID</li><li>confidence / evidence / explanation</li><li>model_name / status</li><li>validation_issues + created_at</li></ul></article></div><aside className="callout"><CircleAlert size={20}/><p><strong>Önemli nüans:</strong> Liste ve istatistik sorguları her Rule için en yüksek Classification ID’sini “son sonuç” kabul eder. Detay uç noktası ise SID’nin en yüksek revizyonunu getirir. Böylece revizyon ve sınıflandırma geçmişi birbirinden bağımsız kalır.</p></aside></section>

      <section className="api-section"><div className="api-inner"><div className="section-heading"><span>05</span><div><p className="eyebrow">DIŞ SÖZLEŞME</p><h2>API yüzeyi</h2></div></div><div className="endpoint-list">{endpoints.map(([method,path,text])=><article key={path+method}><span className={`method ${method.toLowerCase()}`}>{method}</span><code>{path}</code><p>{text}</p></article>)}</div></div></section>

      <section className="section"><div className="section-heading"><span>06</span><div><p className="eyebrow">KULLANICI DENEYİMİ</p><h2>Frontend nasıl çalışıyor?</h2></div></div><div className="ui-flow"><article><Monitor/><span>Dashboard</span><h3>Gör, ara, filtrele, içe al</h3><p><code>getStats()</code> ve <code>getRules()</code> paralel çağrılır. Arama veya filtre değişince query string yeniden kurulur. Bir satıra tıklanınca SID detayına gidilir.</p></article><ArrowRight/><article><Network/><span>API katmanı</span><h3>Tipli, ince bir istemci</h3><p><code>services/api.ts</code> ortak fetch/hata davranışını kapsüller. Vite geliştirmede <code>/api</code> çağrılarını 8000 portuna proxy eder.</p></article><ArrowRight/><article><FileCode2/><span>RuleDetail</span><h3>Hamdan kanıta kadar</h3><p>Ham kural, parser sonucu, sınıflandırma alanları, güven, açıklama, kanıt ve doğrulama sorunları tek analist görünümünde sunulur.</p></article></div></section>

      <section className="runtime"><div className="runtime-inner"><div><p className="eyebrow">ÇALIŞMA ORTAMI</p><h2>Yerelde hafif, Docker’da üç servis</h2><p>Geliştirmede backend varsayılan olarak SQLite kullanabilir; Vite proxy’si FastAPI’ye bağlanır. Docker Compose ise PostgreSQL’i kalıcı volume ile, backend’i Uvicorn ile, frontend’i Nginx ile çalıştırır.</p></div><div className="service-stack"><article><Database/><b>db</b><span>PostgreSQL 17 · :5432 internal</span></article><ArrowDown/><article><Server/><b>backend</b><span>FastAPI + Uvicorn · :8000</span></article><ArrowDown/><article><Monitor/><b>frontend</b><span>React build + Nginx · :5173</span></article></div></div></section>

      <section className="section" id="notlar"><div className="section-heading"><span>07</span><div><p className="eyebrow">DEĞERLENDİRME</p><h2>Güçlü yanlar, sınırlar ve okuma rotası</h2></div></div><div className="review-grid"><article className="good"><CheckCircle2/><h3>Neden sağlam bir V1?</h3><ul><li>Deterministik ve AI tabanlı sorumluluklar net ayrılmış.</li><li>Katı Pydantic çıktı şeması serbest metin riskini azaltıyor.</li><li>Yerel MITRE doğrulaması model uydurmalarını görünür kılıyor.</li><li>SID+REV benzersizliği ve classification tarihçesi iyi ayrılmış.</li><li>Batch’te tek kural hatası tüm işi durdurmuyor.</li><li>Parser ve servis davranışları doğrudan test edilmiş.</li></ul></article><article className="limits"><CircleAlert/><h3>Bilerek bırakılan V1 sınırları</h3><ul><li>Tam Suricata grameri yok; seçili semantik alanlar persist ediliyor.</li><li>MITRE JSON kompakt ve eksik; bilinmeyen teknikler reddediliyor.</li><li>Batch sıralı; job queue veya dağıtık worker bulunmuyor.</li><li>İnsan düzeltmesi ve analist audit geçmişi henüz yok.</li><li>RAG, vektör arama, tarama, ikinci agent veya LangGraph yok.</li><li>Frontend’de sayfalama kontrolü yok; dashboard ilk 100 kaydı ister.</li></ul></article></div>
        <div className="reading-order"><div><FolderTree/><p className="eyebrow">ÖNERİLEN OKUMA SIRASI</p><h3>Kodu kaybolmadan gez</h3></div><ol><li><code>README.md</code><span>Ürünün niyetini ve sınırlarını gör.</span></li><li><code>api/rules.py</code><span>Import ve listeleme girişlerini takip et.</span></li><li><code>ingestion/</code> → <code>parser/</code><span>Ham metnin ParsedRule’a dönüşümünü öğren.</span></li><li><code>services/classification_service.py</code><span>Asıl iş akışını merkezinden oku.</span></li><li><code>agent/</code> → <code>validation/</code><span>AI sözleşmesini ve güvenlik ağını gör.</span></li><li><code>database/</code> → <code>api/stats.py</code><span>Kayıtların nasıl sorgulandığını bağla.</span></li><li><code>frontend/src/pages/</code><span>Sonucun kullanıcıya nasıl sunulduğunu tamamla.</span></li><li><code>backend/tests/</code><span>Beklenen davranışı örneklerle doğrula.</span></li></ol></div>
      </section>

      <footer><div><span className="brand-mark">SR</span><div><b>Suricata Rule Agent · Mimari Rehberi</b><p>Kaynak kodun mevcut V1 durumundan, dosya dosya analiz edilerek hazırlanmıştır.</p></div></div><a href="#ust">Başa dön ↑</a></footer>
    </main>
  );
}
