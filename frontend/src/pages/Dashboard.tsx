import { ChangeEvent, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { StatusBadge } from "../components/StatusBadge";
import { getClassificationFilters, getRules, getStats, importRules } from "../services/api";
import type { Rule, Stats } from "../types";

const emptyStats: Stats = { total_rules: 0, classified_rules: 0, review_required: 0, failed: 0, category_distribution: {}, top_detected_entities: [], top_mitre_techniques: [], average_confidence: 0 };

export function Dashboard() {
  const navigate = useNavigate();
  const [urlParams] = useSearchParams();
  const [stats, setStats] = useState(emptyStats);
  const [rules, setRules] = useState<Rule[]>([]);
  const [total, setTotal] = useState(0);
  const [search, setSearch] = useState("");
  const [filters, setFilters] = useState({ category: "", subcategory: "", mitre_technique_id: "", entity_type: "", status: "", manual_review_status: "", entity_status: "", mitre_status: "", mitre_mapping_method: "", inspection_batch: urlParams.get("inspection_batch") || "", model_name: "", provider: "", classifier_version: "", inference_mode: "", confidence: "", sort: "sid_desc" });
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

  const load = async () => {
    try {
      const [statsData, rulesData] = await Promise.all([getStats(), getRules(params)]);
      setStats(statsData); setRules(rulesData.items); setTotal(rulesData.total); setError("");
    } catch (e) { setError(e instanceof Error ? e.message : "Request failed"); }
  };
  useEffect(() => { void load(); }, [params.toString()]);
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

  const exportCsv = () => {
    const columns = ["SID", "REV", "MSG", "SOURCE_FILE", "PROTOCOL", "ENTITY", "BEHAVIOR", "CATEGORY", "SUBCATEGORY", "MITRE_ID", "MITRE_TECHNIQUE", "MODEL_CONFIDENCE", "STATUS"];
    const cell = (value: unknown) => {
      const text = value == null ? "" : String(value);
      return /[",\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
    };
    const rows = rules.map(rule => {
      const c = rule.classification;
      return [rule.sid, rule.rev, rule.msg, rule.source_file, rule.protocol, c?.detected_entity, c?.detected_behavior, c?.category, c?.subcategory, c?.mitre_technique_id, c?.mitre_technique, Math.round((c?.model_confidence ?? c?.confidence ?? 0) * 100) + "%", c?.classification_status];
    });
    const csv = [columns, ...rows].map(row => row.map(cell).join(",")).join("\r\n");
    const blob = new Blob(["\uFEFF" + csv], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob); const link = document.createElement("a");
    link.href = url; link.download = `suricata-rules-page-${page}.csv`; link.click(); URL.revokeObjectURL(url);
  };

  const cards = [
    ["Total Rules", stats.total_rules], ["Classified", stats.classified_rules], ["Review Required", stats.review_required],
    ["Failed", stats.failed], ["Average Model Confidence", `${Math.round(stats.average_confidence * 100)}%`],
  ];
  return <>
    <header className="topbar reveal"><div><div className="brand-line"><span className="brand-mark">◈</span><span className="eyebrow">AI SECURITY ANALYSIS PLATFORM</span></div><h1>Suricata Rule Agent</h1><p>Evidence-backed classification for every detection rule.</p></div><div className="topbar-actions"><span className="live-status"><i/> System online</span><label className="import-button">{busy ? "Importing…" : "Import .rules"}<input type="file" accept=".rules,text/plain" multiple disabled={busy} onChange={upload}/></label></div></header>
    {error && <div className="error">{error}</div>}
    <section className="stats-grid">{cards.map(([label, value], index) => <article className={`stat reveal reveal-${Math.min(index + 1, 5)}`} key={label}><span>{label}</span><strong>{value}</strong><em>{label === "Average Model Confidence" ? "uncalibrated model signal" : label === "Total Rules" ? "in current workspace" : "live queue"}</em></article>)}{Object.entries(stats.manual_review || {}).map(([label,value]) => <article className="stat manual-stat reveal" key={label}><span>Manual {label.replaceAll("_"," ")}</span><strong>{value}</strong></article>)}</section>
    <section className="panel">
      <div className="panel-heading"><div><div className="section-kicker">LIVE DATASET</div><h2>Rule Explorer</h2><p>{total} matching rules · server-side page {page}</p></div><div className="explorer-actions"><button className="export-button" onClick={exportCsv} disabled={!rules.length}>↓ CSV</button><button className="export-button" onClick={() => window.print()} disabled={!rules.length}>▣ PDF / Print</button><label className="search-wrap"><span>⌕</span><input ref={searchRef} className="search" aria-label="Search rules" placeholder="Search SID, rule, entity, MITRE…" value={search} onChange={e => setSearch(e.target.value)} /><kbd>Ctrl K</kbd></label></div></div>
      <div className="filters">
        <select value={filters.category} onChange={e => setFilters({...filters, category:e.target.value})}><option value="">All categories</option>{Object.keys(stats.category_distribution).map(x => <option key={x}>{x}</option>)}</select>
        <input placeholder="MITRE ID" value={filters.mitre_technique_id} onChange={e => setFilters({...filters, mitre_technique_id:e.target.value})}/>
        <input placeholder="Subcategory" value={filters.subcategory} onChange={e => setFilters({...filters, subcategory:e.target.value})}/>
        <select value={filters.entity_type} onChange={e => setFilters({...filters, entity_type:e.target.value})}><option value="">All entity types</option>{["Attack Tool","Malware","Remote Access Tool","Product","Software","Protocol","Other","Unknown"].map(x=><option key={x}>{x}</option>)}</select>
        <select value={filters.status} onChange={e => setFilters({...filters, status:e.target.value})}><option value="">All statuses</option><option value="AUTO_CLASSIFIED">Classified</option><option value="REVIEW_REQUIRED">Review required</option><option value="FAILED">Failed</option></select>
        <select value={filters.manual_review_status} onChange={e => setFilters({...filters, manual_review_status:e.target.value})}><option value="">Manual review: any</option><option value="UNREVIEWED">Unreviewed</option><option value="APPROVED">Approved</option><option value="REJECTED">Rejected</option><option value="NEEDS_REVIEW">Needs review</option></select>
        <select value={filters.confidence} onChange={e => setFilters({...filters, confidence:e.target.value})}><option value="">Any confidence</option><option value="0.9">90%+</option><option value="0.75">75%+</option><option value="0.5">50%+</option></select>
        <select value={filters.entity_status} onChange={e => setFilters({...filters, entity_status:e.target.value})}><option value="">Entity: any</option><option value="has">Has entity</option><option value="none">Null entity</option></select>
        <select value={filters.mitre_status} onChange={e => setFilters({...filters, mitre_status:e.target.value})}><option value="">MITRE: any</option><option value="has">Has MITRE</option><option value="none">Null MITRE</option></select>
        <select value={filters.inspection_batch} onChange={e => setFilters({...filters, inspection_batch:e.target.value})}><option value="">Inspection batch: any</option><option value="operational-250">Operational 250</option></select>
        <select value={filters.model_name} onChange={e => setFilters({...filters, model_name:e.target.value})}><option value="">Model: any</option>{modelFilters.models.map(x=><option key={x}>{x}</option>)}</select>
        <select value={filters.provider} onChange={e => setFilters({...filters, provider:e.target.value})}><option value="">Provider: any</option>{modelFilters.providers.map(x=><option key={x}>{x}</option>)}</select>
        <select value={filters.classifier_version} onChange={e => setFilters({...filters, classifier_version:e.target.value})}><option value="">Classifier: any</option>{modelFilters.classifier_versions.map(x=><option key={x}>{x}</option>)}</select>
        <select value={filters.inference_mode} onChange={e => setFilters({...filters, inference_mode:e.target.value})}><option value="">Inference: any</option>{modelFilters.inference_modes.map(x=><option key={x}>{x}</option>)}</select>
        <select value={filters.mitre_mapping_method} onChange={e => setFilters({...filters, mitre_mapping_method:e.target.value})}><option value="">MITRE provenance: any</option><option value="EXACT_SOURCE_MAPPING">Exact source</option><option value="DERIVED_SUBTECHNIQUE">Derived sub-technique</option><option value="INFERRED_MAPPING">Inferred</option><option value="SOURCE_MAPPING_OVERRIDDEN">Source overridden</option><option value="NO_SUPPORTED_MAPPING">No mapping</option></select>
        <select value={filters.sort} onChange={e => setFilters({...filters, sort:e.target.value})}><option value="sid_desc">Newest SID</option><option value="sid_asc">Oldest SID</option><option value="confidence_desc">Confidence ↓</option><option value="confidence_asc">Confidence ↑</option><option value="recent">Recently classified</option></select>
      </div><div className="pagination"><button disabled={page <= 1} onClick={() => setPage(page - 1)}>← Previous</button><span>Page {page} / {Math.max(1, Math.ceil(total / pageSize))}</span><button disabled={page >= Math.ceil(total / pageSize)} onClick={() => setPage(page + 1)}>Next →</button></div>
      <div className="table-wrap"><table><thead><tr><th>SID</th><th>Message</th><th>Entity</th><th>Behavior</th><th>Category</th><th>MITRE</th><th>Model Confidence</th><th>Status</th></tr></thead><tbody>{rules.map(rule => {
        const c = rule.classification; return <tr key={rule.id} onClick={() => navigate(`/rules/${rule.sid}`)}><td className="mono sid-cell"><span>{rule.sid}</span><small>rev {rule.rev}</small></td><td className="message">{rule.msg || "—"}<small>{rule.protocol} · {rule.classtype || "unclassified"}</small></td><td>{c?.detected_entity || <span className="dim">Not assigned</span>}</td><td>{c?.detected_behavior || <span className="dim">Not assigned</span>}</td><td>{c?.category || <span className="dim">—</span>}<small>{c?.subcategory}</small></td><td className="mono">{c?.mitre_technique_id || <span className="dim">—</span>}<small>{c?.mitre_technique}</small></td><td>{c ? <span className="confidence"><i style={{width:`${Math.round((c.model_confidence ?? c.confidence)*100)}%`}}/>{Math.round((c.model_confidence ?? c.confidence)*100)}%</span> : "—"}</td><td><StatusBadge status={c?.classification_status}/><small className={`review-label ${rule.manual_review?.status?.toLowerCase() || "unreviewed"}`}>{rule.manual_review?.status || "UNREVIEWED"}</small></td></tr>;
      })}</tbody></table>{!rules.length && <div className="empty">No rules match the current filters.</div>}</div>
    </section>
  </>;
}
