import { ChangeEvent, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { DecisionAssessment } from "../components/DecisionAssessment";
import { StatusBadge } from "../components/StatusBadge";
import { exportCatalogCsv, getCatalogStats, getClassificationFilters, getRules, getStats, importRules } from "../services/api";
import type { Rule, Stats } from "../types";

const emptyStats: Stats = { total_rules: 0, classified_rules: 0, review_required: 0, failed: 0, category_distribution: {}, top_detected_entities: [], top_mitre_techniques: [], average_confidence: 0 };

export function Dashboard() {
  const navigate = useNavigate();
  const [urlParams] = useSearchParams();
  const [stats, setStats] = useState(emptyStats);
  const [catalogStats, setCatalogStats] = useState<{total_rules:number;mitre_mapped:number;product_status:Record<string,number>}>({total_rules:0,mitre_mapped:0,product_status:{}});
  const [rules, setRules] = useState<Rule[]>([]);
  const [total, setTotal] = useState(0);
  const [search, setSearch] = useState("");
  const [filters, setFilters] = useState({ category: urlParams.get("category") || "", subcategory: urlParams.get("subcategory") || "", mitre_technique_id: urlParams.get("mitre_technique_id") || "", mitre_tactic: urlParams.get("mitre_tactic") || "", entity_type: "", status: "", manual_review_status: "", entity_status: "", mitre_status: "", mitre_mapping_method: "", inspection_batch: urlParams.get("inspection_batch") || "", model_name: "", provider: "", classifier_version: "", inference_mode: "", product_status: urlParams.get("product_status") || "", sort: "sid_desc" });
  const [page, setPage] = useState(1);
  const pageSize = 50;
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const searchRef = useRef<HTMLInputElement>(null);
  const [modelFilters, setModelFilters] = useState<{models:string[]; providers:string[]; classifier_versions:string[]; inference_modes:string[]; runs:string[]}>({models:[],providers:[],classifier_versions:[],inference_modes:[],runs:[]});
  useEffect(() => { void getClassificationFilters().then(setModelFilters).catch(() => undefined); }, []);

  const params = useMemo(() => {
    const value = new URLSearchParams({ limit: String(pageSize), offset: String((page - 1) * pageSize) });
    if (search) value.set("search", search);
    Object.entries(filters).forEach(([key, item]) => item && value.set(key, item));
    return value;
  }, [search, filters, page]);
  const activeFilterCount = Object.entries(filters).filter(([key, value]) => key !== "sort" && Boolean(value)).length + (search ? 1 : 0);

  const load = async () => {
    try {
      const [statsData, rulesData, catalogData] = await Promise.all([getStats(), getRules(params), getCatalogStats()]);
      setStats(statsData); setCatalogStats(catalogData); setRules(rulesData.items); setTotal(rulesData.total); setError("");
    } catch (e) { setError(e instanceof Error ? e.message : "Request failed"); }
  };
  useEffect(() => { void load(); }, [params.toString()]);
  useEffect(() => { const next = new URLSearchParams(); if (search) next.set("search", search); Object.entries(filters).forEach(([key,value]) => { if (value && key !== "sort") next.set(key,value); }); window.history.replaceState(null,"",`${window.location.pathname}${next.toString() ? `?${next}` : ""}`); }, [search, filters]);
  useEffect(() => { setPage(1); }, [search, filters]);
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
    try { await importRules(event.target.files); await load(); } catch (e) { setError(e instanceof Error ? e.message : "Import failed"); }
    finally { setBusy(false); event.target.value = ""; }
  };

  const exportCsv = async () => {
    const exportParams = new URLSearchParams(); if (search) exportParams.set("search", search); if (filters.category) exportParams.set("category", filters.category); if (filters.mitre_tactic) exportParams.set("mitre_tactic", filters.mitre_tactic); if (filters.product_status) exportParams.set("product_status", filters.product_status);
    try { const blob = await exportCatalogCsv(exportParams); const url = URL.createObjectURL(blob); const link = document.createElement("a"); link.href=url; link.download="suricata-catalog.csv"; link.click(); URL.revokeObjectURL(url); } catch(e) { setError(e instanceof Error ? e.message : "Export failed"); }
  };

  const cards = [
    ["Total Rules", stats.total_rules], ["Classified", stats.classified_rules], ["Review Required", stats.review_required],
    ["Failed", stats.failed], ["MITRE Mapped", catalogStats.mitre_mapped], ["Product Candidates", catalogStats.product_status.CANDIDATE || 0],
  ];
  return <>
    <header className="topbar reveal"><div><div className="brand-line"><span className="brand-mark">◈</span><span className="eyebrow">AI SECURITY ANALYSIS PLATFORM</span></div><h1>Suricata Rule Agent</h1><p>Evidence-backed classification for every detection rule.</p></div><div className="topbar-actions"><span className="live-status"><i/> System online</span><label className="import-button">{busy ? "Importing…" : "Import .rules"}<input type="file" accept=".rules,text/plain" multiple disabled={busy} onChange={upload}/></label></div></header>
    {error && <div className="error">{error}</div>}
    <section className="stats-grid">{cards.map(([label, value], index) => <article className={`stat reveal reveal-${Math.min(index + 1, 5)}`} key={label}><span>{label}</span><strong>{value}</strong><em>{label === "Total Rules" ? "in current workspace" : "live queue"}</em></article>)}{[
      ["Manual unreviewed", stats.manual_review?.UNREVIEWED || 0],
      ["Manual approved", stats.manual_review?.APPROVED || 0],
      ["Manual rejected", stats.manual_review?.REJECTED || 0],
      ["Manual needs review", stats.manual_review?.NEEDS_REVIEW || 0],
      ["AI classified · human review pending", stats.manual_review?.CLASSIFIED_UNREVIEWED || 0],
    ].map(([label, value]) => <article className="stat manual-stat reveal" key={label}><span>{label}</span><strong>{value}</strong></article>)}</section>
    <section className="panel">
      <div className="panel-heading"><div><div className="section-kicker">LIVE DATASET</div><h2>Rule Explorer</h2><p className="result-count"><strong>{total}</strong> kayıt bulundu · sayfa {page} · {activeFilterCount ? `${activeFilterCount} aktif filtre` : "filtre uygulanmadı"}</p></div><div className="explorer-actions"><button className="export-button" onClick={exportCsv} disabled={!rules.length}>↓ CSV</button><button className="export-button" onClick={() => window.print()} disabled={!rules.length}>▣ PDF / Print</button><label className="search-wrap"><span>⌕</span><input ref={searchRef} className="search" aria-label="Search rules" placeholder="Search SID, rule, entity, MITRE…" value={search} onChange={e => setSearch(e.target.value)} /><kbd>Ctrl K</kbd></label></div></div>
      <div className="filters"><div className="model-presets" aria-label="Model quick filters"><button type="button" className={filters.classifier_version === "qwen-v2.2" ? "active" : ""} onClick={() => setFilters({...filters, provider:"ollama", model_name:"qwen3:8b", classifier_version:"qwen-v2.2"})}>Qwen V2.2</button><button type="button" className={filters.provider === "gemini" && filters.classifier_version === "v2.1" ? "active" : ""} onClick={() => setFilters({...filters, provider:"gemini", model_name:"", classifier_version:"v2.1"})}>Gemini V2.1</button></div>
        <select value={filters.category} onChange={e => setFilters({...filters, category:e.target.value})}><option value="">All categories</option>{Object.keys(stats.category_distribution).map(x => <option key={x}>{x}</option>)}</select>
        <input placeholder="MITRE ID" value={filters.mitre_technique_id} onChange={e => setFilters({...filters, mitre_technique_id:e.target.value})}/><input placeholder="MITRE tactic" value={filters.mitre_tactic} onChange={e => setFilters({...filters, mitre_tactic:e.target.value})}/>
        <input placeholder="Subcategory" value={filters.subcategory} onChange={e => setFilters({...filters, subcategory:e.target.value})}/>
        <select value={filters.entity_type} onChange={e => setFilters({...filters, entity_type:e.target.value})}><option value="">All entity types</option>{["Attack Tool","Malware","Remote Access Tool","Product","Software","Protocol","Other","Unknown"].map(x=><option key={x}>{x}</option>)}</select>
        <select value={filters.status} onChange={e => setFilters({...filters, status:e.target.value})}><option value="">All statuses</option><option value="AUTO_CLASSIFIED">Classified</option><option value="REVIEW_REQUIRED">Review required</option><option value="FAILED">Failed</option></select>
        <select value={filters.manual_review_status} onChange={e => setFilters({...filters, manual_review_status:e.target.value})}><option value="">Manual review: any</option><option value="UNREVIEWED">Unreviewed</option><option value="APPROVED">Approved</option><option value="REJECTED">Rejected</option><option value="NEEDS_REVIEW">Needs review</option></select>
        <select value={filters.entity_status} onChange={e => setFilters({...filters, entity_status:e.target.value})}><option value="">Entity: any</option><option value="has">Has entity</option><option value="none">Null entity</option></select>
        <select value={filters.mitre_status} onChange={e => setFilters({...filters, mitre_status:e.target.value})}><option value="">MITRE: any</option><option value="has">Has MITRE</option><option value="none">Null MITRE</option></select>
        <select value={filters.inspection_batch} onChange={e => setFilters({...filters, inspection_batch:e.target.value})}><option value="">Inspection batch: any</option><option value="operational-250">Operational 250</option></select>
        <select value={filters.model_name} onChange={e => setFilters({...filters, model_name:e.target.value})}><option value="">Model: any</option>{modelFilters.models.map(x=><option key={x}>{x}</option>)}</select>
        <select value={filters.provider} onChange={e => setFilters({...filters, provider:e.target.value})}><option value="">Provider: any</option>{modelFilters.providers.map(x=><option key={x}>{x}</option>)}</select>
        <select value={filters.classifier_version} onChange={e => setFilters({...filters, classifier_version:e.target.value})}><option value="">Classifier: any</option>{modelFilters.classifier_versions.map(x=><option key={x}>{x}</option>)}</select>
        <select value={filters.inference_mode} onChange={e => setFilters({...filters, inference_mode:e.target.value})}><option value="">Inference: any</option>{modelFilters.inference_modes.map(x=><option key={x}>{x}</option>)}</select>
        <select value={filters.mitre_mapping_method} onChange={e => setFilters({...filters, mitre_mapping_method:e.target.value})}><option value="">MITRE provenance: any</option><option value="EXACT_SOURCE_MAPPING">Exact source</option><option value="DERIVED_SUBTECHNIQUE">Derived sub-technique</option><option value="INFERRED_MAPPING">Inferred</option><option value="SOURCE_MAPPING_OVERRIDDEN">Source overridden</option><option value="NO_SUPPORTED_MAPPING">No mapping</option></select>
        <select value={filters.product_status} onChange={e => setFilters({...filters, product_status:e.target.value})}><option value="">Product status: any</option><option value="NOT_EVALUATED">Not evaluated</option><option value="CANDIDATE">Candidate</option><option value="SHORTLISTED">Shortlisted</option><option value="APPROVED_FOR_PRODUCT">Approved</option><option value="REJECTED_FOR_PRODUCT">Rejected</option><option value="ALREADY_INTEGRATED">Integrated</option></select>
        <select value={filters.sort} onChange={e => setFilters({...filters, sort:e.target.value})}><option value="sid_desc">Newest SID</option><option value="sid_asc">Oldest SID</option><option value="recent">Recently classified</option></select>
      </div><div className="pagination"><button disabled={page <= 1} onClick={() => setPage(page - 1)}>← Previous</button><span>Page {page} / {Math.max(1, Math.ceil(total / pageSize))}</span><button disabled={page >= Math.ceil(total / pageSize)} onClick={() => setPage(page + 1)}>Next →</button></div>
      <div className="table-wrap"><table><thead><tr><th>SID</th><th>Message</th><th>Entity</th><th>Behavior</th><th>Category</th><th>MITRE</th><th>Decision checks</th><th>Status</th></tr></thead><tbody>{rules.map(rule => {
        const c = rule.classification; return <tr key={rule.id} onClick={() => navigate(`/rules/${rule.sid}`)}><td className="mono sid-cell"><span>{rule.sid}</span><small>rev {rule.rev}</small></td><td className="message">{rule.msg || "—"}<small>{rule.protocol} · {rule.classtype || "unclassified"}</small></td><td>{c?.detected_entity || <span className="dim">Not assigned</span>}</td><td>{c?.detected_behavior || <span className="dim">Not assigned</span>}</td><td>{c?.category || <span className="dim">—</span>}<small>{c?.subcategory}</small></td><td className="mono">{c?.mitre_technique_id || <span className="dim">—</span>}<small>{c?.mitre_technique}</small></td><td><DecisionAssessment classification={c} compact/></td><td><StatusBadge status={c?.classification_status}/><small className={`review-label ${c ? (c.manual_review?.status?.toLowerCase() || "unreviewed") : "not-classified"}`}>{c?.manual_review?.status || (c ? "UNREVIEWED" : "NOT CLASSIFIED")}</small></td></tr>;
      })}</tbody></table>{!rules.length && <div className="empty">No rules match the current filters.</div>}</div>
    </section>
  </>;
}
