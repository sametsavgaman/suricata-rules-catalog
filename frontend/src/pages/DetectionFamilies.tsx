import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { getCatalogFacets, getFamilies, getFamilyStats, type DetectionFamily } from "../services/api";
import { useI18n } from "../i18n";

export function DetectionFamilies() {
  const { t, label, locale } = useI18n();
  const [url] = useSearchParams();
  const [search,setSearch] = useState(url.get("search") || "");
  const [category,setCategory] = useState(url.get("category") || "");
  const [mitreTactic,setMitreTactic] = useState(url.get("mitre_tactic") || "");
  const [mitre,setMitre] = useState(url.get("mitre_technique_id") || "");
  const [protocol,setProtocol] = useState(url.get("protocol") || "");
  const [page,setPage] = useState(1); const limit=24;
  const [items,setItems] = useState<DetectionFamily[]>([]); const [total,setTotal] = useState(0);
  const [stats,setStats] = useState<Awaited<ReturnType<typeof getFamilyStats>>|null>(null);
  const [facets,setFacets] = useState<Awaited<ReturnType<typeof getCatalogFacets>>|null>(null);
  const [error,setError] = useState(""); const [loading,setLoading] = useState(true);
  const params=useMemo(()=>{const p=new URLSearchParams({offset:String((page-1)*limit),limit:String(limit)});if(search)p.set("search",search);if(category)p.set("category",category);if(mitreTactic)p.set("mitre_tactic",mitreTactic);if(mitre)p.set("mitre_technique_id",mitre);if(protocol)p.set("protocol",protocol);return p;},[search,category,mitreTactic,mitre,protocol,page]);
  useEffect(()=>{void Promise.all([getFamilyStats(),getCatalogFacets()]).then(([s,f])=>{setStats(s);setFacets(f)}).catch(e=>setError(e instanceof Error?e.message:t("Catalog could not be loaded")));},[]);
  useEffect(()=>{setLoading(true);void getFamilies(params).then(r=>{setItems(r.items);setTotal(r.total);setError("")}).catch(e=>setError(e instanceof Error?e.message:t("Family list could not be loaded"))).finally(()=>setLoading(false));window.history.replaceState(null,"",`${location.pathname}${params.toString()?`?${params}`:""}`);},[params.toString()]);
  useEffect(()=>setPage(1),[search,category,mitreTactic,mitre,protocol]);
  const pages=Math.max(1,Math.ceil(total/limit));
  return <div className="families-page">
    <header className="family-hero"><div className="family-ornament" aria-hidden="true"><i/><i/><i/></div><div className="section-kicker">{t("INTELLIGENT DETECTION NAVIGATION")}</div><h1>{t("Detection Families")}</h1><p>{t("Explore thousands of signatures through meaningful detection subjects and capability groups. Only families supported by explainable evidence are shown.")}</p><div className="family-hero-stats"><span><b>{stats?.families ?? "—"}</b> {t("canonical family")}</span><span><b>{stats?.assigned_rules ?? "—"}</b> {t("assigned rules")}</span><span><b>{stats ? `${(stats.assignment_coverage*100).toFixed(1)}%` : "—"}</b> {t("conservative coverage")}</span></div></header>
    {error&&<div className="error">{error}</div>}
    <section className="family-filter-panel"><label className="family-search"><span>⌕</span><input aria-label={t("Search detection families")} value={search} onChange={e=>setSearch(e.target.value)} placeholder={t("AnyDesk, Cobalt Strike, DNS Tunneling…")}/></label><select aria-label={t("Family category")} value={category} onChange={e=>setCategory(e.target.value)}><option value="">{t("All categories")}</option>{facets?.categories.map(x=><option key={x.value} value={x.value}>{label(x.value)}</option>)}</select><select aria-label={t("MITRE tactic")} value={mitreTactic} onChange={e=>setMitreTactic(e.target.value)}><option value="">{t("All MITRE tactics")}</option>{facets?.mitre_tactics.map(x=><option key={x.value} value={x.value}>{label(x.value)}</option>)}</select><input aria-label={t("MITRE technique")} value={mitre} onChange={e=>setMitre(e.target.value.toUpperCase())} placeholder="MITRE ID · T1219"/><select aria-label={t("Family protocol")} value={protocol} onChange={e=>setProtocol(e.target.value)}><option value="">{t("All protocols")}</option>{facets?.protocols.map(x=><option key={x.value} value={x.value}>{label(x.value)}</option>)}</select></section>
    <div className="family-results-line"><span><b>{total.toLocaleString(locale === "tr" ? "tr-TR" : "en-US")}</b> {t("families found")}</span><small>{t("Each rule is counted only within its evidence-backed primary family.")}</small></div>
    {loading?<div className="family-loading">{t("Preparing canonical families…")}</div>:items.length?<section className="family-grid">{items.map((family,index)=><FamilyCard family={family} index={index} key={family.id}/>)}</section>:<div className="family-empty"><b>{t("No detection families match.")}</b><span>{t("Broaden the filters. Rules without evidence intentionally remain UNASSIGNED.")}</span></div>}
    <div className="pagination"><button disabled={page===1} onClick={()=>setPage(p=>p-1)}>{t("← Previous")}</button><span>{t("Page")} {page} / {pages}</span><button disabled={page>=pages} onClick={()=>setPage(p=>p+1)}>{t("Next →")}</button></div>
  </div>;
}

function FamilyCard({family,index}:{family:DetectionFamily;index:number}) {
  const { t, label } = useI18n();
  const product=family.product_status.APPROVED_FOR_PRODUCT||0;
  return <Link className="family-card" to={`/catalog/families/${family.slug}`} style={{"--family-delay":`${Math.min(index,8)*35}ms`} as React.CSSProperties}><div className="family-card-top"><span className={`family-kind kind-${family.family_type.toLowerCase()}`}>{label(family.family_type)}</span><span className="family-arrow">↗</span></div><h2>{family.name}</h2><div className="family-rule-count"><b>{family.rule_count.toLocaleString("tr-TR")}</b><span>{t("underlying rules")}</span></div><div className="family-chips">{family.protocols.slice(0,3).map(x=><span key={x}>{x.toUpperCase()}</span>)}{family.mitre_ids.slice(0,2).map(x=><span className="mitre" key={x}>{x}</span>)}</div><div className="family-card-meta"><span>{family.categories.slice(0,2).map(label).join(" · ")||t("Classification pending")}</span><b>{family.mitre_count} MITRE · {product} {t("product picks")}</b></div></Link>;
}
