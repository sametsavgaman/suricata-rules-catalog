import { Link } from "react-router-dom";
import { useI18n } from "../i18n";

const sections = [
  [
    "01",
    "Ingestion",
    "ET .rules files are loaded. Disabled rules are skipped and SID + REV is stored as an immutable rule record.",
  ],
  [
    "02",
    "Parser",
    "The deterministic Suricata parser extracts protocol, addresses, ports, content, PCRE, flow, metadata and app-layer fields.",
  ],
  [
    "03",
    "Enrichment",
    "Local, explainable hints identify indicators, candidate entities, CVE references and possible MITRE evidence. Hints are not ground truth.",
  ],
  [
    "04",
    "Provider",
    "The selected provider receives a bounded ClassificationContext and returns the strict Pydantic classification schema.",
  ],
  [
    "05",
    "Validation",
    "Taxonomy, canonical MITRE relationships, evidence gates and consistency checks validate the proposed output.",
  ],
  [
    "06",
    "Family projection",
    "A separate deterministic layer groups only defensible rules into normalized Detection Families and records why each link exists.",
  ],
  [
    "07",
    "Catalog",
    "FastAPI exposes rules, families and grounded assistant results to Rule Explorer, Detection Families, MITRE Catalog and Model Lab.",
  ],
] as const;

const tables = [
  [
    "rules",
    "One row per SID + REV",
    "raw_rule, msg, protocol, ports, contents, pcre, app_layer, metadata, source_file",
  ],
  [
    "classifications",
    "Every provider output",
    "final fields, confidence, provider, model, evidence, validation, provenance and timing",
  ],
  [
    "manual_reviews",
    "Human review history",
    "APPROVED, REJECTED or NEEDS_REVIEW; never created automatically by AI",
  ],
  [
    "classification_runs",
    "Batch/run provenance",
    "run_id, provider, model, totals, timestamps and success/failure counts",
  ],
  [
    "comparison_reviews",
    "Gemini vs Qwen comparisons",
    "Two classification IDs, analyst preference and optional note",
  ],
  [
    "rule_product_decisions",
    "Product planning",
    "Candidate, shortlisted, approved or rejected independently of AI review",
  ],
  [
    "detection_families",
    "Canonical family dictionary",
    "normalized name, stable slug, family type and timestamps",
  ],
  [
    "rule_family_assignments",
    "One explainable primary family per rule",
    "family, source classification, provenance, evidence and algorithm version",
  ],
  [
    "rule_family_evaluations",
    "Resume-safe assigned/unassigned checkpoint",
    "status, source classification, evidence and algorithm version",
  ],
] as const;

const tocItems = [
  "Overview",
  "Architecture",
  "Providers",
  "Database",
  "API contract",
  "Classification states",
  "MITRE & confidence",
  "Operations",
  "Integration rules",
  "MITRE intelligence pipeline",
  "Data lifecycle",
  "Gemini workspaces",
  "Catalog assistant",
];

export function Documentation() {
  const { locale } = useI18n();
  if (locale === "tr") return <TurkishDocumentation />;
  return (
    <div className="docs-page">
      <header className="docs-hero">
        <div className="section-kicker">ENGINEERING HANDBOOK · V2</div>
        <h1>Platform Documentation</h1>
        <p>
          A precise field guide for engineers, analysts and future frontends
          integrating the Suricata Detection Catalog.
        </p>
        <div className="docs-hero-meta">
          <span>FastAPI + SQLite + React</span>
          <span>Gemini API / local Qwen</span>
          <span>Human-reviewed ground truth only</span>
        </div>
      </header>
      <div className="docs-layout">
        <aside className="docs-toc">
          <div className="docs-toc-title">CONTENTS</div>
          {tocItems.map((x, i) => (
            <a href={`#docs-${i + 1}`} key={x}>
              {String(i + 1).padStart(2, "0")} {x}
            </a>
          ))}
          <Link className="docs-back" to="/catalog">
            ← Back to catalog
          </Link>
        </aside>
        <main className="docs-content">
          <section id="docs-1" className="docs-section">
            <div className="docs-index">01 / OVERVIEW</div>
            <h2>What this platform does</h2>
            <p>
              The platform turns a large Emerging Threats Suricata ruleset into
              an inspectable detection catalogue. It preserves the original
              signature, makes parser output visible, asks one configured AI
              provider for a structured classification, validates that result,
              and stores every stage for later comparison.
            </p>
            <div className="docs-callout">
              <strong>Design principle</strong>
              <span>
                Deterministic evidence is authoritative for structure. AI
                proposes semantic labels. Validation decides whether the
                proposal is safe to expose.
              </span>
            </div>
            <div className="docs-quick-grid">
              <div>
                <b>Input</b>
                <span>
                  Suricata <code>.rules</code> files
                </span>
              </div>
              <div>
                <b>Output</b>
                <span>Searchable rule and classification records</span>
              </div>
              <div>
                <b>Users</b>
                <span>Detection engineers, analysts, product owners</span>
              </div>
              <div>
                <b>Review boundary</b>
                <span>
                  AI output never becomes human-approved automatically
                </span>
              </div>
            </div>
          </section>
          <section id="docs-2" className="docs-section">
            <div className="docs-index">02 / ARCHITECTURE</div>
            <h2>End-to-end processing line</h2>
            <p>
              The same pipeline serves the dashboard, batch runner and Model
              Lab. A frontend does not parse or classify rules itself; it reads
              the API's canonical representation.
            </p>
            <div className="docs-pipeline">
              {sections.map(([n, title, text]) => (
                <div className="docs-pipeline-step" key={n}>
                  <b>{n}</b>
                  <div>
                    <h3>{title}</h3>
                    <p>{text}</p>
                  </div>
                </div>
              ))}
            </div>
            <pre className="docs-code">{`ET .rules → RuleLoader → SuricataRuleParser → Enrichment hints
                              ↓
                   ClassificationContext (JSON)
                              ↓
             Gemini generateContent  |  Ollama /api/chat
                              ↓
        Pydantic schema → taxonomy/MITRE validation → SQLite
                              ↓
                         FastAPI → React`}</pre>
          </section>
          <section id="docs-3" className="docs-section">
            <div className="docs-index">03 / PROVIDERS</div>
            <h2>Gemini and Qwen execution</h2>
            <div className="docs-provider-grid">
              <article>
                <div className="docs-provider-label gemini">GEMINI · API</div>
                <h3>Remote structured classification</h3>
                <p>
                  Gemini is selected through <code>AI_PROVIDER=gemini</code>.
                  The API key and model are read from environment/runtime
                  settings. The adapter calls Google's{" "}
                  <code>generateContent</code> method and requests the same
                  structured Pydantic-compatible JSON schema used by the local
                  provider.
                </p>
                <ul>
                  <li>
                    Requires internet and a valid <code>GEMINI_API_KEY</code>.
                  </li>
                  <li>Rate limits use bounded retry/backoff.</li>
                  <li>Secrets and prompts are never written to logs.</li>
                </ul>
              </article>
              <article>
                <div className="docs-provider-label qwen">QWEN3 8B · LOCAL</div>
                <h3>Local deterministic inference</h3>
                <p>
                  Qwen runs through Ollama at <code>OLLAMA_BASE_URL</code>,
                  normally <code>http://127.0.0.1:11434</code>. The adapter
                  sends <code>think: false</code>, temperature 0 and a JSON
                  schema to <code>/api/chat</code>. Its output passes through
                  the same V2 hardening, MITRE decision and validator layers.
                </p>
                <ul>
                  <li>
                    After the model is downloaded, basic classification can run
                    offline.
                  </li>
                  <li>
                    GPU offload and Ollama keep-alive determine throughput.
                  </li>
                  <li>
                    Qwen and Gemini share the same input contract, not the same
                    model.
                  </li>
                </ul>
              </article>
            </div>
            <div className="docs-callout amber">
              <strong>Provider rule</strong>
              <span>
                Changing the provider changes only the inference adapter.
                Parser, taxonomy, database schema, provenance and frontend
                contract remain shared.
              </span>
            </div>
          </section>
          <section id="docs-4" className="docs-section">
            <div className="docs-index">04 / DATABASE</div>
            <h2>SQLite location and data model</h2>
            <p>
              Local development uses SQLite through SQLAlchemy. With the
              documented root-level start command, the default database is{" "}
              <code>suricata_rules.db</code> in the project root (the exact path
              can be changed with <code>DATABASE_URL</code>). SQLite is a file
              database and can be inspected with DB Browser for SQLite or any
              SQLite-compatible client.
            </p>
            <div className="docs-table-wrap">
              <table className="docs-table">
                <thead>
                  <tr>
                    <th>Table</th>
                    <th>Purpose</th>
                    <th>Important fields</th>
                  </tr>
                </thead>
                <tbody>
                  {tables.map(([name, purpose, fields]) => (
                    <tr key={name}>
                      <td>
                        <code>{name}</code>
                      </td>
                      <td>{purpose}</td>
                      <td>{fields}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="docs-note">
              Do not edit live rows while a classifier batch is writing. Make a
              backup first, or use the API for changes that need audit history.
            </p>
          </section>
          <section id="docs-5" className="docs-section">
            <div className="docs-index">05 / API CONTRACT</div>
            <h2>Using the data from another frontend</h2>
            <p>
              Any client can consume the catalogue without importing Python
              code. The API is the integration boundary.
            </p>
            <div className="docs-endpoints">
              {[
                [
                  "GET",
                  "/api/rules?limit=50",
                  "Paginated catalogue with category, provider, model, family, MITRE and batch filters.",
                ],
                [
                  "GET",
                  "/api/rules/{sid}",
                  "Full rule detail: raw signature, parsed input, latest classification and review metadata.",
                ],
                [
                  "GET",
                  "/api/families",
                  "Paginated server-side family aggregation and filters.",
                ],
                [
                  "GET",
                  "/api/families/{slug}",
                  "Family profile, provenance distribution and underlying rules.",
                ],
                [
                  "GET",
                  "/api/families/stats",
                  "Assigned/unassigned family coverage.",
                ],
                [
                  "GET",
                  "/api/stats",
                  "Workspace totals, status counts and distributions.",
                ],
                [
                  "POST",
                  "/api/rules/{sid}/classify",
                  "Classify one rule; successful results are cached unless force=true.",
                ],
                [
                  "GET",
                  "/api/catalog/facets",
                  "Category, tactic, technique and product-planning facets.",
                ],
              ].map(([verb, path, desc]) => (
                <div className="docs-endpoint" key={path}>
                  <b className={verb === "GET" ? "get" : "post"}>{verb}</b>
                  <code>{path}</code>
                  <span>{desc}</span>
                </div>
              ))}
            </div>
            <pre className="docs-code">{`fetch("/api/rules?provider=ollama&model_name=qwen3:8b")
  .then(response => response.json())
  .then(({ items, total }) => renderRules(items, total));`}</pre>
          </section>
          <section id="docs-6" className="docs-section">
            <div className="docs-index">06 / STATE MODEL</div>
            <h2>Classification, validation and human review</h2>
            <div className="docs-state-grid">
              <div>
                <b className="state-green">AUTO_CLASSIFIED</b>
                <span>
                  AI result passed normal validation and is available for
                  catalogue use.
                </span>
              </div>
              <div>
                <b className="state-amber">REVIEW_REQUIRED</b>
                <span>
                  Validator found an issue or insufficient evidence. This is an
                  AI/system state, not human approval.
                </span>
              </div>
              <div>
                <b className="state-red">FAILED</b>
                <span>
                  Provider or processing failure retained as diagnostic history.
                </span>
              </div>
              <div>
                <b className="state-blue">UNREVIEWED</b>
                <span>
                  Human review has not been recorded for an existing
                  classification.
                </span>
              </div>
            </div>
            <p>
              Manual review states (<code>APPROVED</code>, <code>REJECTED</code>
              , <code>NEEDS_REVIEW</code>) are created only by an analyst. A
              rule can be <code>AUTO_CLASSIFIED</code> while individual fields
              remain <code>ABSTAINED</code>.
            </p>
          </section>
          <section id="docs-7" className="docs-section">
            <div className="docs-index">07 / SEMANTICS</div>
            <h2>MITRE provenance and confidence</h2>
            <div className="docs-semantic-grid">
              <div>
                <h3>MITRE mapping</h3>
                <p>
                  <code>source_mitre_mapping</code> records rule metadata.{" "}
                  <code>final_mitre_mapping</code> records the validated system
                  decision. <code>mitre_mapping_method</code> explains exact,
                  derived, inferred, overridden or unsupported decisions.
                </p>
              </div>
              <div>
                <h3>Confidence</h3>
                <p>
                  <code>model_confidence</code> is the model's self-reported
                  overall output confidence. It is not a calibrated probability.
                  Retrieval score, evidence strength and validator status are
                  separate fields.
                </p>
              </div>
            </div>
            <div className="docs-callout">
              <strong>Null semantics</strong>
              <span>
                <code>ABSTAINED</code> means evidence was assessed but
                insufficient. <code>NOT_APPLICABLE</code> means the field does
                not logically apply. <code>UNAVAILABLE</code> means historical
                metadata was not recorded.
              </span>
            </div>
          </section>
          <section id="docs-8" className="docs-section">
            <div className="docs-index">08 / OPERATIONS</div>
            <h2>Runbook</h2>
            <div className="docs-runbook">
              <div>
                <b>Start backend</b>
                <code>
                  backend\\.venv\\Scripts\\python.exe -m uvicorn app.main:app
                  --reload --port 8000
                </code>
              </div>
              <div>
                <b>Start frontend</b>
                <code>cd frontend; npm run dev</code>
              </div>
              <div>
                <b>Open API contract</b>
                <code>http://localhost:8000/docs</code>
              </div>
              <div>
                <b>Open web app</b>
                <code>http://localhost:5173/catalog</code>
              </div>
              <div>
                <b>Run tests</b>
                <code>
                  cd backend; .\\.venv\\Scripts\\python.exe -m pytest -q
                </code>
              </div>
            </div>
            <p className="docs-note">
              For production, move from local SQLite to PostgreSQL, put
              credentials in a secret manager, and run classification as a
              resumable worker rather than a browser request.
            </p>
          </section>
          <section id="docs-9" className="docs-section">
            <div className="docs-index">09 / INTEGRATION RULES</div>
            <h2>Rules for future contributors</h2>
            <ol className="docs-rules">
              <li>
                Keep raw rule data immutable; a new revision is a new{" "}
                <code>SID + REV</code> record.
              </li>
              <li>
                Keep parser, abstention and validation state canonical in the
                API.
              </li>
              <li>Never mark AI proposals as human-reviewed.</li>
              <li>Preserve provider, model, classifier version and run ID.</li>
              <li>
                Never expose API keys, hidden prompts or chain-of-thought.
              </li>
              <li>
                When adding a field, update schema, database model, serializer,
                API type and inspector together.
              </li>
            </ol>
            <div className="docs-final-links">
              <Link to="/catalog/rules">Browse rules →</Link>
              <Link to="/models">Open Model Lab →</Link>
              <Link to="/catalog/mitre">Explore MITRE →</Link>
            </div>
          </section>
          <section id="docs-10" className="docs-section">
            <div className="docs-index">10 / MITRE INTELLIGENCE PIPELINE</div>
            <h2>How a rule becomes a defensible ATT&amp;CK mapping</h2>
            <p>
              MITRE is not stamped onto every rule by a lookup table. The system
              separates what the source explicitly claims from what can be
              derived from observable behavior, then records the decision and
              its evidence.
            </p>
            <div className="docs-pipeline">
              <div className="docs-pipeline-step">
                <b>01</b>
                <div>
                  <h3>Collect candidates</h3>
                  <p>
                    Rule metadata is scanned for ATT&amp;CK IDs, technique
                    names, tactic hints and vendor references. Parser and
                    enrichment signals add candidates only when a rule contains
                    supporting process, network, file, credential or execution
                    evidence.
                  </p>
                </div>
              </div>
              <div className="docs-pipeline-step">
                <b>02</b>
                <div>
                  <h3>Normalize</h3>
                  <p>
                    IDs are canonicalized to ATT&amp;CK format, sub-technique
                    relationships are resolved and aliases are mapped to the
                    stable technique dictionary. Unknown identifiers remain
                    unsupported instead of being silently repaired.
                  </p>
                </div>
              </div>
              <div className="docs-pipeline-step">
                <b>03</b>
                <div>
                  <h3>Gate evidence</h3>
                  <p>
                    Exact source metadata is strongest. Derived mappings require
                    a deterministic relationship; inferred mappings require
                    explicit behavioral evidence. A family name or model guess
                    alone cannot establish MITRE coverage.
                  </p>
                </div>
              </div>
              <div className="docs-pipeline-step">
                <b>04</b>
                <div>
                  <h3>Persist provenance</h3>
                  <p>
                    <code>source_mitre_mapping</code>,{" "}
                    <code>final_mitre_mapping</code>,{" "}
                    <code>mitre_mapping_method</code>, evidence and validator
                    status are stored together so an analyst can reconstruct why
                    the mapping was accepted, abstained or overridden.
                  </p>
                </div>
              </div>
            </div>
            <div className="docs-semantic-grid">
              <div>
                <h3>Decision methods</h3>
                <p>
                  <code>exact_source</code>, <code>derived_subtechnique</code>,{" "}
                  <code>inferred_behavior</code>, <code>overridden</code> and{" "}
                  <code>unsupported</code> describe provenance, not a confidence
                  percentage.
                </p>
              </div>
              <div>
                <h3>Coverage boundary</h3>
                <p>
                  A mapped technique means the rule is relevant to that
                  behavior; it does not prove that the product detects every
                  procedure in the technique. Coverage views expose evidence
                  strength and unassigned gaps.
                </p>
              </div>
            </div>
          </section>
          <section id="docs-11" className="docs-section">
            <div className="docs-index">11 / DATA LIFECYCLE</div>
            <h2>From a rule file to the answer on screen</h2>
            <p>
              Every displayed value has a traceable origin. The browser is a
              projection layer: it never parses a rule, calls a model directly
              or invents a MITRE relationship.
            </p>
            <div className="docs-pipeline">
              <div className="docs-pipeline-step">
                <b>01</b>
                <div>
                  <h3>Import</h3>
                  <p>
                    ET .rules upload is validated by RuleLoader; the raw
                    signature and immutable SID + REV anchor are preserved.
                  </p>
                </div>
              </div>
              <div className="docs-pipeline-step">
                <b>02</b>
                <div>
                  <h3>Parse and enrich</h3>
                  <p>
                    SuricataRuleParser extracts protocol, addresses, ports,
                    content, PCRE and metadata. Enrichment adds explainable
                    indicators, entities, CVE and MITRE candidates.
                  </p>
                </div>
              </div>
              <div className="docs-pipeline-step">
                <b>03</b>
                <div>
                  <h3>Classify and validate</h3>
                  <p>
                    ClassificationContext bounds what Gemini or Ollama may see.
                    Normalizer, taxonomy, MITRE evidence and consistency
                    validators decide each field state.
                  </p>
                </div>
              </div>
              <div className="docs-pipeline-step">
                <b>04</b>
                <div>
                  <h3>Persist and render</h3>
                  <p>
                    SQLAlchemy writes rules, classifications, provenance and run
                    history. FastAPI serializes one canonical JSON contract and
                    React renders the catalog.
                  </p>
                </div>
              </div>
            </div>
            <div className="docs-callout">
              <strong>Immutable anchor</strong>
              <span>
                <code>SID + REV</code> identifies the source rule. A changed
                revision is a new record; classifications and reviews remain
                historical rather than overwriting the original signature.
              </span>
            </div>
            <div className="docs-quick-grid">
              <div>
                <b>Raw truth</b>
                <span>
                  <code>rules.raw_rule</code> and parsed fields
                </span>
              </div>
              <div>
                <b>Semantic proposal</b>
                <span>
                  <code>classifications</code> with provider/model
                </span>
              </div>
              <div>
                <b>Audit trail</b>
                <span>runs, provenance and manual reviews</span>
              </div>
              <div>
                <b>UI answer</b>
                <span>FastAPI JSON, then React components</span>
              </div>
            </div>
          </section>
          <section id="docs-12" className="docs-section">
            <div className="docs-index">12 / GEMINI WORKSPACES</div>
            <h2>Two Gemini surfaces, two different jobs</h2>
            <div className="docs-provider-grid">
              <article>
                <div className="docs-provider-label gemini">
                  GEMINI · CLASSIFIER
                </div>
                <h3>Rule-level semantic classification</h3>
                <p>
                  <code>POST /api/rules/{"{sid}"}/classify</code> sends the
                  bounded <code>ClassificationContext</code> (raw signature,
                  parsed fields, enrichment and allowed taxonomy) to the
                  configured Gemini model. The adapter requests
                  schema-constrained JSON; the same normalizer, MITRE evidence
                  gates and validators used by Qwen run afterwards. A successful
                  result is persisted with provider, model, classifier version,
                  run ID and provenance in <code>classifications</code>.
                </p>
                <ul>
                  <li>One rule in, one auditable classification out.</li>
                  <li>
                    It may abstain; abstention is safer than invented technique
                    IDs.
                  </li>
                  <li>
                    It never creates human approval or a product decision.
                  </li>
                </ul>
              </article>
              <article>
                <div className="docs-provider-label gemini">
                  GEMINI · CATALOG ASSISTANT
                </div>
                <h3>Question and scenario analysis</h3>
                <p>
                  <code>POST /api/catalog/assistant/ask</code> and{" "}
                  <code>/scenario</code> receive a question or customer
                  penetration-test narrative plus static taxonomy instructions.
                  Gemini returns a constrained filter/analysis plan, not
                  database rows. The server validates that plan, queries local
                  SQLite, computes counts, gaps, candidate rules and rule-pack
                  actions, then renders the result.
                </p>
                <ul>
                  <li>
                    The model does not receive the full catalog or raw rule
                    corpus.
                  </li>
                  <li>
                    It cannot write classifications, approve rules or mutate
                    packs.
                  </li>
                  <li>
                    Scenario output is a recommendation to investigate, not
                    proof of detection.
                  </li>
                </ul>
              </article>
            </div>
            <div className="docs-callout amber">
              <strong>Why keep them separate?</strong>
              <span>
                Classifier Gemini answers “what does this rule mean?” Catalog
                Assistant Gemini answers “which existing rules and gaps relate
                to this question?” Sharing schemas and validators keeps both
                explainable while preventing a search prompt from silently
                rewriting model truth.
              </span>
            </div>
          </section>
          <section id="docs-13" className="docs-section">
            <div className="docs-index">CATALOG ASSISTANT</div>
            <h2>Natural-Language Catalog Search</h2>
            <p>
              The Ask the Catalog field on the Detection Catalog page converts a
              question into a structured set of allowed filters using Gemini.
              The backend validates the filters with Pydantic, queries the local
              catalog through SQLAlchemy, and returns results referenced by
              SID/REV or detection family. Counts and the response summary are
              generated by the backend.
            </p>
            <div className="docs-callout">
              <strong>Data flow</strong>
              <span>
                Only the question, static taxonomy, and system instructions are
                sent to Google. Catalog records and raw rules are never sent to
                the model. Each question is independent; conversation history is
                not stored.
              </span>
            </div>
            <pre className="docs-code">
              {
                'POST /api/catalog/assistant/ask\n{"question":"List the AnyDesk rules"}\n\nPOST /api/catalog/assistant/search\n{"resource":"FAMILIES","filters":{"mitre_technique_id":"T1219"},"offset":0,"limit":12}'
              }
            </pre>
            <p>
              The first endpoint uses Gemini; pagination queries only the
              database. The model cannot perform any operation beyond LIST/COUNT
              RULES and LIST/COUNT FAMILIES. Filters are combined with AND
              semantics. Ambiguous requests return a clarification prompt; the
              assistant cannot approve products or modify data. Supported
              filters include family, model, MITRE ID, category, entity,
              protocol, and product status. Verify the applied filters above the
              results.
            </p>
            <p>
              This release is restricted to localhost access. Limits are six
              questions per minute, one active model request, a 1,000-character
              question, and a maximum of 50 records per page. LAN or public
              deployment requires authentication and distributed rate-limit
              management. Technical contracts:{" "}
              <code>docs/detection-families.md</code> and{" "}
              <code>docs/catalog-assistant.md</code>.
            </p>
            <Link to="/catalog">Open the catalog assistant →</Link>
          </section>
        </main>
      </div>
    </div>
  );
}

function TurkishDocumentation() {
  const sections = [
    [
      "Genel Bakış",
      "Platform, Suricata kurallarını incelenebilir bir detection kataloğuna dönüştürür. Özgün imza korunur; parser, enrichment, AI sınıflandırması, doğrulama ve insan incelemesi ayrı aşamalar olarak saklanır.",
    ],
    [
      "Mimari",
      "İşlem hattı .rules → parser → enrichment → ClassificationContext → Gemini/Ollama → taxonomy ve MITRE doğrulama → SQLite → FastAPI → React şeklindedir.",
    ],
    [
      "Sağlayıcılar",
      "Gemini API uzaktan yapılandırılmış sınıflandırma sağlar. Qwen3 8B Ollama üzerinden yerel çalışır. Her iki sağlayıcı aynı kanonik giriş ve doğrulama sözleşmesini kullanır.",
    ],
    [
      "Veritabanı",
      "rules, classifications, manual_reviews, classification_runs, comparison_reviews ve detection_families tabloları özgün veriyi, model geçmişini ve ürün kararlarını audit edilebilir biçimde tutar.",
    ],
    [
      "API sözleşmesi",
      "API; kuralları, aileleri, MITRE görünümünü, facet filtrelerini, istatistikleri ve tek kural sınıflandırmasını frontend'lere sunar. API entegrasyon sınırıdır.",
    ],
    [
      "Sınıflandırma durumları",
      "AUTO_CLASSIFIED otomatik doğrulamadan geçmiş sonucu, REVIEW_REQUIRED yetersiz kanıtı, FAILED işlem hatasını, UNREVIEWED ise insan incelemesinin henüz yapılmadığını belirtir.",
    ],
    [
      "MITRE ve güven",
      "source_mitre_mapping kaynak metadata'sını, final_mitre_mapping doğrulanmış kararı taşır. model_confidence kalibre edilmiş doğruluk olasılığı değildir; evidence strength ve validator status ayrı sinyallerdir.",
    ],
    [
      "Operasyonlar",
      "Backend için uvicorn, frontend için npm run dev kullanın. Canlı SQLite satırlarını batch yazımı sırasında doğrudan değiştirmeyin; audit geçmişi için API'yi kullanın.",
    ],
    [
      "Entegrasyon kuralları",
      "Özgün kural verisini değişmez tutun, AI önerilerini insan onayı olarak işaretlemeyin, provider/model/run ID bilgisini koruyun ve gizli promptları açığa çıkarmayın.",
    ],
    [
      "MITRE istihbarat hattı",
      "MITRE eşleştirmesi basit bir tablo damgası değildir. Kaynak metadata içindeki açık ATT&CK ID'leri, parser ve enrichment katmanlarının davranış kanıtlarıyla birlikte adaylara dönüştürülür; ID'ler kanonikleştirilir, alt teknik ilişkileri çözülür ve kanıt kapıları uygulanır. exact_source, derived_subtechnique, inferred_behavior, overridden ve unsupported provenance değerleri kararı açıklar. source_mitre_mapping kaynak iddiasını, final_mitre_mapping doğrulanmış sonucu taşır; aile adı veya model tahmini tek başına kapsam kanıtı değildir.",
    ],
    [
      "Verinin yaşam döngüsü",
      ".rules dosyası RuleLoader tarafından doğrulanır ve ham imza SID + REV değişmez çıpasıyla rules tablosuna yazılır. SuricataRuleParser protokol, adres, port, content, PCRE ve metadata alanlarını çıkarır. Enrichment açıklanabilir gösterge, varlık, CVE ve MITRE adayları ekler. ClassificationContext sağlayıcıya giden sınırı belirler; Gemini veya Ollama katı şemaya yanıt verir. Normalizer ve taxonomy/MITRE/evidence/consistency validator'ları alan durumlarını belirler. SQLAlchemy classifications, provenance ve run geçmişini kaydeder; FastAPI kanonik JSON'u üretir, React katalog ve detay ekranlarını çizer.",
    ],
    [
      "İki Gemini çalışma alanı",
      "Birinci yüzey /api/rules/{sid}/classify çağrısıdır: tek kuralın bounded ClassificationContext'ini alır, Qwen ile aynı şema ve validator'lardan geçirir, provider/model/run ID ve provenance ile classifications tablosuna yazar. İkinci yüzey /api/catalog/assistant/ask ve /scenario uçlarıdır: doğal dil sorusu veya müşteri sızma testi anlatısını alır, filtre/analiz planı üretir; sunucu bu planı doğrular, yerel SQLite'tan sayım, boşluk ve aday kuralları hesaplar. İkinci yüzey sınıflandırma yazmaz, onay vermez ve rule pack'i kendiliğinden değiştirmez.",
    ],
    [
      "Katalog asistanı",
      "Katalog Asistanı'na yalnızca soru, statik taksonomi ve sistem talimatları gönderilir; ham katalog ve kurallar Gemini'ye aktarılmaz. Gemini'nin döndürdüğü izinli filtreler Pydantic ile doğrulanır, sorgu yerel veritabanında çalışır ve sonuçlar SID/REV, aile, MITRE, ürün durumu ve kanıt bilgileriyle gösterilir. Belirsiz istekler açıklama ister; altı soru/dakika, tek aktif istek, 1.000 karakter ve sayfa başına 50 kayıt sınırı vardır.",
    ],
  ];
  return (
    <div className="docs-page">
      <header className="docs-hero">
        <div className="section-kicker">MÜHENDİSLİK EL KİTABI · V2</div>
        <h1>Platform Dokümantasyonu</h1>
        <p>Suricata Detection Catalog için Türkçe teknik rehber.</p>
        <div className="docs-hero-meta">
          <span>FastAPI + SQLite + React</span>
          <span>Gemini API / yerel Qwen</span>
          <span>İnsan incelemesi ayrı tutulur</span>
        </div>
      </header>
      <div className="docs-layout">
        <aside className="docs-toc">
          <div className="docs-toc-title">İÇİNDEKİLER</div>
          {sections.map(([title], i) => (
            <a href={`#tr-doc-${i}`} key={title}>
              {String(i + 1).padStart(2, "0")} {title}
            </a>
          ))}
          <Link className="docs-back" to="/catalog">
            ← Kataloğa dön
          </Link>
        </aside>
        <main className="docs-content">
          {sections.map(([title, text], i) => (
            <section id={`tr-doc-${i}`} className="docs-section" key={title}>
              <div className="docs-index">
                {String(i + 1).padStart(2, "0")} / {title.toUpperCase()}
              </div>
              <h2>{title}</h2>
              <p>{text}</p>
              {i === 0 && (
                <div className="docs-callout">
                  <strong>Tasarım ilkesi</strong>
                  <span>
                    Deterministik kanıt yapısal bilgilerde yetkilidir; AI
                    anlamsal etiket önerir, doğrulama güvenli gösterimi
                    belirler.
                  </span>
                </div>
              )}
              {i === 5 && (
                <div className="docs-state-grid">
                  <div>
                    <b className="state-green">AUTO_CLASSIFIED</b>
                    <span>Doğrulamadan geçti.</span>
                  </div>
                  <div>
                    <b className="state-amber">REVIEW_REQUIRED</b>
                    <span>İnceleme gerekiyor.</span>
                  </div>
                  <div>
                    <b className="state-red">FAILED</b>
                    <span>İşlem başarısız.</span>
                  </div>
                  <div>
                    <b className="state-blue">UNREVIEWED</b>
                    <span>İnsan incelemesi yok.</span>
                  </div>
                </div>
              )}
            </section>
          ))}
        </main>
      </div>
    </div>
  );
}
