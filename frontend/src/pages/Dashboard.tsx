import {
  ChangeEvent,
  MouseEvent,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { DecisionAssessment } from "../components/DecisionAssessment";
import { StatusBadge } from "../components/StatusBadge";
import { AddToRulePack } from "../components/AddToRulePack";
import {
  exportCatalogCsv,
  getCatalogStats,
  getClassificationFilters,
  getRules,
  getStats,
  importRules,
  saveProductDecision,
} from "../services/api";
import type { Rule, Stats } from "../types";
import { useI18n } from "../i18n";

const emptyStats: Stats = {
  total_rules: 0,
  classified_rules: 0,
  review_required: 0,
  failed: 0,
  pending_classification: 0,
  category_distribution: {},
  top_detected_entities: [],
  top_mitre_techniques: [],
  average_confidence: 0,
};

export function Dashboard() {
  const { t, label, locale } = useI18n();
  const navigate = useNavigate();
  const [urlParams] = useSearchParams();
  const [stats, setStats] = useState(emptyStats);
  const [catalogStats, setCatalogStats] = useState<{
    total_rules: number;
    mitre_mapped: number;
    product_status: Record<string, number>;
  }>({ total_rules: 0, mitre_mapped: 0, product_status: {} });
  const [rules, setRules] = useState<Rule[]>([]);
  const [total, setTotal] = useState(0);
  const [search, setSearch] = useState("");
  const [filters, setFilters] = useState({
    category: urlParams.get("category") || "",
    subcategory: urlParams.get("subcategory") || "",
    mitre_technique_id: urlParams.get("mitre_technique_id") || "",
    mitre_tactic: urlParams.get("mitre_tactic") || "",
    entity_type: "",
    status: "",
    manual_review_status: "",
    entity_status: "",
    mitre_status: "",
    mitre_mapping_method: "",
    inspection_batch: urlParams.get("inspection_batch") || "",
    model_name: "",
    provider: "",
    classifier_version: "",
    inference_mode: "",
    product_status: urlParams.get("product_status") || "",
    sort: "recent",
  });
  const [page, setPage] = useState(1);
  const pageSize = 50;
  const [error, setError] = useState("");
  const [initialLoading, setInitialLoading] = useState(true);
  const loadSequence = useRef(0);
  const [busy, setBusy] = useState(false);
  const [productBusySid, setProductBusySid] = useState<number | null>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const [modelFilters, setModelFilters] = useState<{
    models: string[];
    providers: string[];
    classifier_versions: string[];
    inference_modes: string[];
  }>({
    models: [],
    providers: [],
    classifier_versions: [],
    inference_modes: [],
  });
  const selectedFamilies = useMemo(
    () => urlParams.getAll("family"),
    [urlParams],
  );
  useEffect(() => {
    void getClassificationFilters()
      .then(setModelFilters)
      .catch(() => undefined);
  }, []);

  const params = useMemo(() => {
    const value = new URLSearchParams({
      limit: String(pageSize),
      offset: String((page - 1) * pageSize),
    });
    if (search) value.set("search", search);
    Object.entries(filters).forEach(
      ([key, item]) => item && value.set(key, item),
    );
    value.delete("family");
    selectedFamilies.forEach((f) => value.append("family", f));
    return value;
  }, [search, filters, selectedFamilies, page]);
  const activeFilterCount =
    Object.entries(filters).filter(
      ([key, value]) => key !== "sort" && Boolean(value),
    ).length +
    selectedFamilies.length +
    (search ? 1 : 0);

  const load = async () => {
    const sequence = ++loadSequence.current;
    try {
      const [statsData, rulesData, catalogData] = await Promise.all([
        getStats(),
        getRules(params),
        getCatalogStats(),
      ]);
      if (sequence !== loadSequence.current) return;
      setStats(statsData);
      setCatalogStats(catalogData);
      setRules(rulesData.items);
      setTotal(rulesData.total);
      setError("");
    } catch (e) {
      if (sequence !== loadSequence.current) return;
      setError(e instanceof Error ? e.message : "Request failed");
    } finally {
      if (sequence === loadSequence.current) setInitialLoading(false);
    }
  };
  useEffect(() => {
    void load();
  }, [params.toString()]);
  useEffect(() => {
    const next = new URLSearchParams();
    if (search) next.set("search", search);
    Object.entries(filters).forEach(([key, value]) => {
      if (value && key !== "sort") next.set(key, value);
    });
    selectedFamilies.forEach((f) => next.append("family", f));
    window.history.replaceState(
      null,
      "",
      `${window.location.pathname}${next.toString() ? `?${next}` : ""}`,
    );
  }, [search, filters, selectedFamilies]);
  useEffect(() => {
    setPage(1);
  }, [search, filters, selectedFamilies]);
  useEffect(() => {
    const onShortcut = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        searchRef.current?.focus();
      }
    };
    window.addEventListener("keydown", onShortcut);
    return () => window.removeEventListener("keydown", onShortcut);
  }, []);

  const upload = async (event: ChangeEvent<HTMLInputElement>) => {
    if (!event.target.files?.length) return;
    setBusy(true);
    try {
      await importRules(event.target.files);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Import failed");
    } finally {
      setBusy(false);
      event.target.value = "";
    }
  };

  const exportCsv = async () => {
    const exportParams = new URLSearchParams();
    if (search) exportParams.set("search", search);
    if (filters.category) exportParams.set("category", filters.category);
    if (filters.mitre_tactic)
      exportParams.set("mitre_tactic", filters.mitre_tactic);
    if (filters.product_status)
      exportParams.set("product_status", filters.product_status);
    try {
      const blob = await exportCatalogCsv(exportParams);
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = "suricata-catalog.csv";
      link.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Export failed");
    }
  };

  const toggleExistingRule = async (
    rule: Rule,
    event: MouseEvent<HTMLButtonElement>,
  ) => {
    event.stopPropagation();
    const current = rule.product_decision?.status || "NOT_EVALUATED";
    const next =
      current === "ALREADY_INTEGRATED" ? "NOT_EVALUATED" : "ALREADY_INTEGRATED";
    setProductBusySid(rule.sid);
    try {
      const decision = await saveProductDecision(String(rule.sid), next);
      setRules((items) =>
        items.map((item) =>
          item.id === rule.id ? { ...item, product_decision: decision } : item,
        ),
      );
      setCatalogStats((value) => {
        const counts = { ...value.product_status };
        counts[current] = Math.max(0, (counts[current] || 0) - 1);
        counts[next] = (counts[next] || 0) + 1;
        return { ...value, product_status: counts };
      });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Product decision save failed");
    } finally {
      setProductBusySid(null);
    }
  };

  const cards = [
    ["Total Rules", stats.total_rules],
    ["Classified", stats.classified_rules],
    ["Review Required", stats.review_required],
    ["Unclassified / awaiting processing", stats.pending_classification ?? stats.failed],
    ["MITRE Mapped", catalogStats.mitre_mapped],
    [
      "Approved for Product",
      catalogStats.product_status.APPROVED_FOR_PRODUCT || 0,
    ],
  ];
  return (
    <div className="rules-page">
      <svg
        className="rules-tulip-background"
        viewBox="0 0 1440 940"
        preserveAspectRatio="xMidYMid slice"
        aria-hidden="true"
      >
        <defs>
          <linearGradient id="tulipStroke" x1="0" y1="0" x2="1" y2="1">
            <stop stopColor="#70e0ad" />
            <stop offset="1" stopColor="#c7ad6b" />
          </linearGradient>
        </defs>
        <g
          className="tulip-motif tulip-left"
          fill="none"
          stroke="url(#tulipStroke)"
          strokeWidth="2"
        >
          <path d="M146 846C142 696 175 585 250 492C287 446 312 398 310 339" />
          <path d="M309 341C268 305 262 248 306 198C335 231 344 272 329 310C354 284 380 272 412 273C403 326 366 354 309 341Z" />
          <path d="M223 533C164 505 125 519 91 573C149 581 193 567 223 533Z" />
          <path d="M185 642C238 607 280 609 316 648C260 666 216 660 185 642Z" />
          <path d="M148 762C101 726 61 724 25 757C69 782 110 784 148 762Z" />
          <path d="M300 364C257 389 232 425 224 472M329 365C370 395 394 432 399 478" />
          <circle cx="401" cy="485" r="7" />
          <circle cx="218" cy="481" r="5" />
        </g>
        <g
          className="tulip-motif tulip-right"
          fill="none"
          stroke="url(#tulipStroke)"
          strokeWidth="2"
        >
          <path d="M1301 907C1308 749 1267 634 1187 535C1148 487 1122 437 1125 376" />
          <path d="M1126 378C1168 340 1174 280 1129 228C1099 262 1090 305 1106 344C1080 317 1052 304 1019 305C1028 361 1067 390 1126 378Z" />
          <path d="M1214 577C1275 548 1316 563 1351 620C1291 628 1245 613 1214 577Z" />
          <path d="M1254 691C1199 654 1155 656 1118 697C1176 716 1222 709 1254 691Z" />
          <path d="M1292 817C1341 779 1383 777 1420 812C1374 838 1331 841 1292 817Z" />
          <path d="M1134 402C1179 428 1205 465 1213 514M1105 403C1062 434 1038 473 1032 521" />
          <circle cx="1030" cy="529" r="7" />
          <circle cx="1219" cy="523" r="5" />
        </g>
        <g
          className="ottoman-floral-fill"
          fill="none"
          stroke="url(#tulipStroke)"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <path
            d="M0 886C120 810 178 806 263 856C350 907 430 906 512 850C600 791 676 793 744 846C812 793 888 791 976 850C1058 906 1138 907 1225 856C1310 806 1370 810 1440 886"
            strokeWidth="2.2"
          />
          <path
            d="M0 902C120 839 185 838 264 879C349 923 432 922 512 876C600 825 676 826 744 870C812 826 888 825 976 876C1056 922 1139 923 1224 879C1303 838 1370 839 1440 902"
            strokeWidth="1"
            opacity=".65"
          />
          <g className="small-tulip small-tulip-a">
            <path d="M174 820C171 780 179 748 196 721" />
            <path d="M196 722C180 710 180 683 197 667C212 685 213 704 206 719C218 707 231 704 245 709C239 731 220 743 196 722Z" />
            <path d="M190 758C169 744 151 746 136 763C156 772 174 770 190 758Z" />
          </g>
          <g className="small-tulip small-tulip-b">
            <path d="M1265 820C1268 780 1260 748 1243 721" />
            <path d="M1243 722C1259 710 1259 683 1242 667C1227 685 1226 704 1233 719C1221 707 1208 704 1194 709C1200 731 1219 743 1243 722Z" />
            <path d="M1249 758C1270 744 1288 746 1303 763C1283 772 1265 770 1249 758Z" />
          </g>
          <g className="bird bird-left">
            <path d="M336 237C350 222 365 222 379 237C394 222 409 222 423 237C408 235 395 242 379 252C364 242 351 235 336 237Z" />
            <path d="M379 252C377 260 377 266 380 272" />
          </g>
          <g className="bird bird-right">
            <path d="M1043 190C1057 175 1072 175 1086 190C1101 175 1116 175 1130 190C1115 188 1102 195 1086 205C1071 195 1058 188 1043 190Z" />
            <path d="M1086 205C1084 213 1084 219 1087 225" />
          </g>
          <g className="bird bird-center">
            <path d="M680 318C692 306 704 306 716 318C728 306 740 306 752 318C739 316 728 322 716 331C704 322 693 316 680 318Z" />
            <path d="M716 331C715 338 715 343 717 348" />
          </g>
          <path
            className="arabesque"
            d="M54 438C118 402 171 403 223 438C277 475 329 475 381 438C432 401 485 401 538 438C590 475 643 475 696 438C748 401 801 401 854 438C907 475 960 475 1012 438C1065 401 1118 401 1171 438C1223 475 1276 475 1329 438C1382 401 1403 402 1386 438"
            strokeWidth="1.4"
            opacity=".55"
          />
        </g>
      </svg>
      <header className="topbar reveal">
        <div>
          <div className="brand-line">
            <span className="brand-mark">◈</span>
            <span className="eyebrow">AI SECURITY ANALYSIS PLATFORM</span>
          </div>
          <h1>Suricata Rule Agent</h1>
          <p>
            {localeText(
              t,
              locale,
              "Evidence-backed classification for every detection rule.",
            )}
          </p>
        </div>
        <div className="topbar-actions">
          <span className="live-status">
            <i /> {localeText(t, locale, "System online")}
          </span>
          <label className="import-button">
            {busy
              ? localeText(t, locale, "Importing…")
              : localeText(t, locale, "Import .rules")}
            <input
              type="file"
              accept=".rules,text/plain"
              multiple
              disabled={busy}
              onChange={upload}
            />
          </label>
        </div>
      </header>
      {error && <div className="error">{error}</div>}
      <section className="stats-grid">
        {cards.map(([cardLabel, value], index) => (
          <article
            className={`stat reveal reveal-${Math.min(index + 1, 5)}`}
            key={cardLabel}
          >
            <span>{t(String(cardLabel))}</span>
            <strong className={initialLoading ? "dashboard-stat-loading" : undefined}>
              {initialLoading ? "···" : value}
            </strong>
            <em>
              {cardLabel === "Total Rules"
                ? localeText(t, locale, "in current workspace")
                : localeText(t, locale, "live queue")}
            </em>
          </article>
        ))}
        {[
          ["Manual unreviewed", stats.manual_review?.UNREVIEWED || 0],
          ["Manual approved", stats.manual_review?.APPROVED || 0],
          ["Manual rejected", stats.manual_review?.REJECTED || 0],
          ["Manual needs review", stats.manual_review?.NEEDS_REVIEW || 0],
          [
            "AI classified · human review pending",
            stats.manual_review?.CLASSIFIED_UNREVIEWED || 0,
          ],
        ].map(([cardLabel, value]) => (
          <article className="stat manual-stat reveal" key={cardLabel}>
            <span>{localeText(t, locale, String(cardLabel))}</span>
            <strong className={initialLoading ? "dashboard-stat-loading" : undefined}>
              {initialLoading ? "···" : value}
            </strong>
          </article>
        ))}
      </section>
      <section className="panel">
        <div className="panel-heading">
          <div>
            <div className="section-kicker">{t("LIVE DATASET")}</div>
            <h2>{t("Rule Explorer")}</h2>
            <p className="result-count">
              <strong>{initialLoading ? "—" : total}</strong>{" "}
              {locale === "tr"
                ? `kayıt bulundu · sayfa ${page} · ${activeFilterCount ? `${activeFilterCount} aktif filtre` : "filtre uygulanmadı"}`
                : `records found · page ${page} · ${activeFilterCount ? `${activeFilterCount} active filters` : "no filters applied"}`}
            </p>
          </div>
          <div className="explorer-actions">
            <button
              className="export-button"
              onClick={exportCsv}
              disabled={!rules.length}
            >
              ↓ CSV
            </button>
            <button
              className="export-button"
              onClick={() => window.print()}
              disabled={!rules.length}
            >
              ▣ PDF / Print
            </button>
            <label className="search-wrap">
              <span>⌕</span>
              <input
                ref={searchRef}
                className="search"
                aria-label={t("Search rules")}
                placeholder={t("Search SID, rule, entity, MITRE…")}
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
              <kbd>Ctrl K</kbd>
            </label>
          </div>
        </div>
        <div className="filters rules-filter-grid">
          <select
            value={filters.category}
            onChange={(e) =>
              setFilters({ ...filters, category: e.target.value })
            }
          >
            <option value="">All categories</option>
            {Object.keys(stats.category_distribution).map((x) => (
              <option key={x}>{x}</option>
            ))}
          </select>
          <input
            placeholder="MITRE ID"
            value={filters.mitre_technique_id}
            onChange={(e) =>
              setFilters({ ...filters, mitre_technique_id: e.target.value })
            }
          />
          <input
            placeholder="MITRE tactic"
            value={filters.mitre_tactic}
            onChange={(e) =>
              setFilters({ ...filters, mitre_tactic: e.target.value })
            }
          />
          <input
            placeholder="Subcategory"
            value={filters.subcategory}
            onChange={(e) =>
              setFilters({ ...filters, subcategory: e.target.value })
            }
          />
          <select
            value={filters.entity_type}
            onChange={(e) =>
              setFilters({ ...filters, entity_type: e.target.value })
            }
          >
            <option value="">All entity types</option>
            {[
              "Attack Tool",
              "Malware",
              "Remote Access Tool",
              "Product",
              "Software",
              "Protocol",
              "Other",
              "Unknown",
            ].map((x) => (
              <option key={x}>{x}</option>
            ))}
          </select>
          <select
            value={filters.status}
            onChange={(e) => setFilters({ ...filters, status: e.target.value })}
          >
            <option value="">All statuses</option>
            <option value="AUTO_CLASSIFIED">Classified</option>
            <option value="REVIEW_REQUIRED">Review required</option>
            <option value="FAILED">Failed</option>
          </select>
          <select
            value={filters.manual_review_status}
            onChange={(e) =>
              setFilters({ ...filters, manual_review_status: e.target.value })
            }
          >
            <option value="">Manual review: any</option>
            <option value="UNREVIEWED">Unreviewed</option>
            <option value="APPROVED">Approved</option>
            <option value="REJECTED">Rejected</option>
            <option value="NEEDS_REVIEW">Needs review</option>
          </select>
          <select
            value={filters.entity_status}
            onChange={(e) =>
              setFilters({ ...filters, entity_status: e.target.value })
            }
          >
            <option value="">Entity: any</option>
            <option value="has">Has entity</option>
            <option value="none">Null entity</option>
          </select>
          <select
            value={filters.mitre_status}
            onChange={(e) =>
              setFilters({ ...filters, mitre_status: e.target.value })
            }
          >
            <option value="">MITRE: any</option>
            <option value="has">Has MITRE</option>
            <option value="none">Null MITRE</option>
          </select>
          <select
            value={filters.inspection_batch}
            onChange={(e) =>
              setFilters({ ...filters, inspection_batch: e.target.value })
            }
          >
            <option value="">Inspection batch: any</option>
            <option value="operational-250">Operational 250</option>
          </select>
          <select
            value={filters.model_name}
            onChange={(e) =>
              setFilters({ ...filters, model_name: e.target.value })
            }
          >
            <option value="">Model: any</option>
            {modelFilters.models.map((x) => (
              <option key={x}>{x}</option>
            ))}
          </select>
          <select
            value={filters.provider}
            onChange={(e) =>
              setFilters({ ...filters, provider: e.target.value })
            }
          >
            <option value="">Provider: any</option>
            {modelFilters.providers.map((x) => (
              <option key={x}>{x}</option>
            ))}
          </select>
          <select
            value={filters.classifier_version}
            onChange={(e) =>
              setFilters({ ...filters, classifier_version: e.target.value })
            }
          >
            <option value="">Classifier: any</option>
            {modelFilters.classifier_versions.map((x) => (
              <option key={x}>{x}</option>
            ))}
          </select>
          <select
            value={filters.inference_mode}
            onChange={(e) =>
              setFilters({ ...filters, inference_mode: e.target.value })
            }
          >
            <option value="">Inference: any</option>
            {modelFilters.inference_modes.map((x) => (
              <option key={x}>{x}</option>
            ))}
          </select>
          <select
            value={filters.mitre_mapping_method}
            onChange={(e) =>
              setFilters({ ...filters, mitre_mapping_method: e.target.value })
            }
          >
            <option value="">MITRE provenance: any</option>
            <option value="EXACT_SOURCE_MAPPING">Exact source</option>
            <option value="DERIVED_SUBTECHNIQUE">Derived sub-technique</option>
            <option value="INFERRED_MAPPING">Inferred</option>
            <option value="SOURCE_MAPPING_OVERRIDDEN">Source overridden</option>
            <option value="NO_SUPPORTED_MAPPING">No mapping</option>
          </select>
          <select
            value={filters.product_status}
            onChange={(e) =>
              setFilters({ ...filters, product_status: e.target.value })
            }
          >
            <option value="">Product status: any</option>
            <option value="NOT_EVALUATED">Not evaluated</option>
            <option value="APPROVED_FOR_PRODUCT">Approved</option>
            <option value="REJECTED_FOR_PRODUCT">Rejected</option>
            <option value="ALREADY_INTEGRATED">Integrated</option>
          </select>
          <select
            value={filters.sort}
            onChange={(e) => setFilters({ ...filters, sort: e.target.value })}
          >
            <option value="recent">{t("Last classified")}</option>
            <option value="first_classified">{t("First classified")}</option>
          </select>
        </div>
        <div className="pagination">
          <button disabled={page <= 1} onClick={() => setPage(page - 1)}>
            ← Previous
          </button>
          <span>
            Page {page} / {Math.max(1, Math.ceil(total / pageSize))}
          </span>
          <button
            disabled={page >= Math.ceil(total / pageSize)}
            onClick={() => setPage(page + 1)}
          >
            Next →
          </button>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>SID</th>
                <th>Message</th>
                <th>Entity</th>
                <th>Families</th>
                <th>Behavior</th>
                <th>Category</th>
                <th>MITRE</th>
                <th>Decision checks</th>
                <th>Status</th>
                <th>Rule pack</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => {
                const c = rule.classification;
                const existing =
                  rule.product_decision?.status === "ALREADY_INTEGRATED";
                return (
                  <tr
                    className={existing ? "rule-row-existing" : undefined}
                    key={rule.id}
                    onClick={() => navigate(`/rules/${rule.sid}`)}
                  >
                    <td className="mono sid-cell">
                      <span>{rule.sid}</span>
                      <small>rev {rule.rev}</small>
                      <Link
                        className="row-compare-link"
                        to={`/catalog/compare?sids=${rule.sid}`}
                        onClick={(event) => event.stopPropagation()}
                      >
                        Compare
                      </Link>
                    </td>
                    <td className="message">
                      {rule.msg || "—"}
                      <small>
                        {rule.protocol} · {rule.classtype || "unclassified"}
                      </small>
                    </td>
                    <td>
                      {c?.detected_entity || (
                        <span className="dim">Not assigned</span>
                      )}
                    </td>
                    <td>
                      <div
                        className="family-chips-inline"
                        aria-label="Detection families"
                      >
                        {rule.families?.length ? (
                          rule.families.map((f) => (
                            <span key={f.slug} title={f.family_type}>
                              {f.name}
                            </span>
                          ))
                        ) : (
                          <span className="dim">Unassigned</span>
                        )}
                      </div>
                    </td>
                    <td>
                      {c?.detected_behavior || (
                        <span className="dim">Not assigned</span>
                      )}
                    </td>
                    <td>
                      {c?.category ? (
                        label(c.category)
                      ) : (
                        <span className="dim">—</span>
                      )}
                      <small>
                        {c?.subcategory ? label(c.subcategory) : ""}
                      </small>
                    </td>
                    <td className="mono">
                      {c?.mitre_technique_id || <span className="dim">—</span>}
                      <small>{c?.mitre_technique}</small>
                    </td>
                    <td>
                      <DecisionAssessment classification={c} compact />
                    </td>
                    <td>
                      <StatusBadge status={c?.classification_status} />
                      <small
                        className={`review-label ${c ? c.manual_review?.status?.toLowerCase() || "unreviewed" : "not-classified"}`}
                      >
                        {c?.manual_review?.status
                          ? label(c.manual_review.status)
                          : c
                            ? t("UNREVIEWED")
                            : t("NOT CLASSIFIED")}
                      </small>
                      {c?.manual_review?.status === "APPROVED" && (
                        <span className="review-shield" role="img" aria-label={t("Manually reviewed and approved")} title={t("Manually reviewed and approved")}>🛡</span>
                      )}
                      {c?.manual_review?.status === "NEEDS_REVIEW" && (
                        <span className="review-attention" role="img" aria-label={t("Human review requested")} title={t("Human review requested")}>!</span>
                      )}
                      <button
                        type="button"
                        className={`existing-rule-toggle ${existing ? "active" : ""}`}
                        disabled={productBusySid === rule.sid}
                        onClick={(event) =>
                          void toggleExistingRule(rule, event)
                        }
                      >
                        {productBusySid === rule.sid
                          ? "…"
                          : existing
                            ? `✓ ${t("In product")}`
                            : t("Mark existing")}
                      </button>
                    </td>
                    <td>
                      <AddToRulePack sid={rule.sid} compact />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {initialLoading ? (
            <div className="empty dashboard-data-loader"><i aria-hidden="true" />{t("Preparing Rule Explorer…")}</div>
          ) : !rules.length && (
            <div className="empty">{t("No rules match the current filters.")}</div>
          )}
        </div>
      </section>
    </div>
  );
}

function localeText(
  t: (key: string) => string,
  locale: "en" | "tr",
  text: string,
) {
  const values: Record<string, string> = {
    "Evidence-backed classification for every detection rule.":
      "Her tespit kuralı için kanıta dayalı sınıflandırma.",
    "System online": "Sistem çevrimiçi",
    "Importing…": "İçe aktarılıyor…",
    "Import .rules": ".rules içe aktar",
    "in current workspace": "mevcut çalışma alanında",
    "live queue": "canlı kuyruk",
    "Manual unreviewed": "Manuel: incelenmedi",
    "Manual approved": "Manuel: onaylandı",
    "Manual rejected": "Manuel: reddedildi",
    "Manual needs review": "Manuel: inceleme gerekli",
    "AI classified · human review pending":
      "AI sınıflandırdı · insan incelemesi bekliyor",
  };
  return locale === "tr"
    ? t(text) === text
      ? values[text] || text
      : t(text)
    : text;
}
