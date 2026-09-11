import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { getMitreOverview, getMitreTechniques, type MitreOverview, type MitreTechniqueList } from "../services/api";
import { useI18n } from "../i18n";
import { MitreMappingReview } from "../components/MitreMappingReview";

export function MitreCatalog(){
  const { t, label, locale } = useI18n();
  const [url]=useSearchParams();
  const reviewSid = url.get("review_sid") || "";
  const parsedClassificationId = Number(url.get("classification_id"));
  const reviewClassificationId = Number.isSafeInteger(parsedClassificationId) && parsedClassificationId > 0 ? parsedClassificationId : null;
  const [overview,setOverview]=useState<MitreOverview|null>(null);
  const [data,setData]=useState<MitreTechniqueList|null>(null);
  const [search,setSearch]=useState(url.get("search")||"");
  const [tactic,setTactic]=useState(url.get("tactic")||"");
  const [kind,setKind]=useState(url.get("kind")||"all");
  const [page,setPage]=useState(1); const limit=100;
  const [error,setError]=useState(""); const [loading,setLoading]=useState(true);
  const params=useMemo(()=>{const p=new URLSearchParams({offset:String((page-1)*limit),limit:String(limit),kind});if(search)p.set("search",search);if(tactic)p.set("tactic",tactic);return p;},[search,tactic,kind,page]);
  useEffect(()=>{void getMitreOverview().then(setOverview).catch(e=>setError(e instanceof Error?e.message:"MITRE overview could not be loaded"));},[]);
  useEffect(()=>{setLoading(true);void getMitreTechniques(params).then(value=>{setData(value);setError("")}).catch(e=>setError(e instanceof Error?e.message:"MITRE techniques could not be loaded")).finally(()=>setLoading(false));const preserved=reviewSid?`&review_sid=${encodeURIComponent(reviewSid)}${reviewClassificationId?`&classification_id=${reviewClassificationId}`:""}`:"";window.history.replaceState(null,"",`${location.pathname}?${params}${preserved}`);},[params.toString(),reviewSid,reviewClassificationId]);
  useEffect(()=>setPage(1),[search,tactic,kind]);
  const metrics=overview?[{label:"Mapped rules",value:overview.summary.mapped_rules},{label:"Unmapped rules",value:overview.summary.unmapped_rules},{label:"Techniques",value:overview.summary.techniques_represented},{label:"Sub-techniques",value:overview.summary.subtechniques_represented},{label:"Tactics",value:overview.summary.tactics_represented},{label:"Mapped families",value:overview.summary.families_with_mappings}]:[];
  return <div className="mitre-page">
    <header className="mitre-hero"><div className="mitre-hero-mark" aria-hidden="true"><i/><i/><i/></div><div className="section-kicker">{t("CATALOG INTELLIGENCE · MITRE ATT&amp;CK")}</div><h1>{t("Technique coverage, with evidence.")}</h1><p>{t("Explore how the Suricata catalogue maps across ATT&amp;CK. This view describes catalogue mappings; it is not a claim of validated NDR product coverage.")}</p><div className="mitre-source"><span>{t("CANONICAL SOURCE")}</span><b>{overview?.data_source||"MITRE ATT&CK local repository"}</b></div><Link className="primary mitre-gap-link" to="/catalog/coverage">{t("Open Coverage &amp; Gap Analysis →")}</Link></header>
    <MitreMappingReview initialSid={reviewSid} initialClassificationId={reviewClassificationId} />
    {error&&<div className="error">{error}</div>}
    <section className="mitre-metrics">{metrics.length?metrics.map(item=><div key={item.label}><b>{item.value.toLocaleString(locale === "tr" ? "tr-TR" : "en-US")}</b><span>{t(item.label)}</span></div>):Array.from({length:6},(_,i)=><div key={i}><b>—</b><span>{t("Loading")}</span></div>)}</section>
    <section className="mitre-workbench">
      <aside className="mitre-tactics"><div className="section-kicker">{t("TACTIC LENS")}</div><h2>{t("ATT&amp;CK tactics")}</h2><button className={!tactic?"active":""} onClick={()=>setTactic("")}><span>{t("All tactics")}</span><b>{overview?.summary.techniques_represented??"—"}</b></button>{overview?.tactics.map(item=><button className={tactic===item.name?"active":""} key={item.name} onClick={()=>setTactic(item.name)}><span>{label(item.name)}</span><small>{item.rule_count.toLocaleString(locale === "tr" ? "tr-TR" : "en-US")} {t("rules")}</small><b>{item.technique_count}</b></button>)}</aside>
      <div className="mitre-technique-browser"><div className="mitre-browser-head"><div><div className="section-kicker">{t("TACTIC → TECHNIQUE → SUB-TECHNIQUE")}</div><h2>{tactic||t("Represented techniques")}</h2><p>{data?.total??0} {t("canonical IDs represented in the current filter.")}</p></div><div className="mitre-controls"><label><span>{t("Search techniques")}</span><input aria-label={t("Search MITRE techniques")} value={search} onChange={e=>setSearch(e.target.value)} placeholder="T1071.001 or Web Protocols"/></label><select aria-label={t("Technique level")} value={kind} onChange={e=>setKind(e.target.value)}><option value="all">{t("All levels")}</option><option value="technique">{t("Techniques")}</option><option value="subtechnique">{t("Sub-techniques")}</option></select></div></div>
        {loading?<div className="family-loading">{t("Preparing ATT&amp;CK hierarchy…")}</div>:data?.items.length?<TechniqueRows items={data.items}/>:<div className="family-empty"><b>{t("No ATT&amp;CK techniques match.")}</b><span>{t("Broaden the search or tactic filter.")}</span></div>}
        <div className="pagination"><button disabled={!data||data.page===1} onClick={()=>setPage(value=>value-1)}>{t("← Previous")}</button><span>{t("Page")} {data?.page??1} / {data?.total_pages??1}</span><button disabled={!data||data.page>=data.total_pages} onClick={()=>setPage(value=>value+1)}>{t("Next →")}</button></div>
      </div>
    </section>
  </div>;
}

export function TechniqueRows({items}:{items:MitreTechniqueList["items"]}){const { t, label, locale } = useI18n();return <div className="mitre-technique-list">{items.map(item=><Link className={item.is_subtechnique?"sub-technique":""} to={`/catalog/mitre/${item.technique_id}`} key={item.technique_id}><div className="mitre-id-stack"><span>{item.is_subtechnique?"SUB":"TECH"}</span><b>{item.technique_id}</b></div><div className="mitre-technique-name">{item.parent&&<small>{item.parent.technique_id} · {label(item.parent.name)}</small>}<strong>{label(item.name)}</strong><div>{item.tactics.map(value=><em key={value}>{label(value)}</em>)}</div></div><div className="mitre-technique-count"><b>{item.rule_count.toLocaleString(locale === "tr" ? "tr-TR" : "en-US")}</b><span>{t("rules")}</span><small>{item.family_count} {t("families")}</small></div><span className="family-arrow">↗</span></Link>)}</div>}
