import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { getMitreCoverage, type MitreCoverage as CoverageData } from "../services/api";
import { useI18n } from "../i18n";

export function MitreCoverage() {
  const { t, label, locale } = useI18n();
  const [data,setData]=useState<CoverageData|null>(null);
  const [query,setQuery]=useState(""); const [tactic,setTactic]=useState(""); const [error,setError]=useState("");
  useEffect(()=>{void getMitreCoverage().then(setData).catch(e=>setError(e instanceof Error?e.message:t("Coverage could not be loaded")));},[]);
  const gaps=useMemo(()=>data?.gaps.filter(item=>(!tactic||item.tactics.includes(tactic))&&(!query||`${item.technique_id} ${item.name}`.toLowerCase().includes(query.toLowerCase())))||[],[data,query,tactic]);
  if(error)return <div className="error page-error">{error}</div>;
  return <div className="product-intelligence-page">
    <header className="intelligence-hero"><div className="section-kicker">{t("MITRE COVERAGE · GAP ANALYSIS")}</div><h1>{t("See what the catalogue maps — and what it does not.")}</h1><p>{t("Coverage is measured against the local ATT&amp;CK repository. It describes catalogue mappings, not validated detection coverage in a deployed NDR sensor.")}</p></header>
    <section className="intelligence-metrics">{data?[<Metric key="c" label={t("Catalogue coverage")} value={`${data.summary.coverage_percent}%`}/>,<Metric key="r" label={t("Represented techniques")} value={data.summary.represented_techniques}/>,<Metric key="g" label={t("Technique gaps")} value={data.summary.gap_techniques}/>,<Metric key="m" label={t("Mapped rules")} value={data.summary.mapped_rules}/>,<Metric key="u" label={t("Unmapped rules")} value={data.summary.unmapped_rules}/>,<Metric key="a" label={t("ATT&CK repository")} value={data.summary.repository_techniques}/>]:<Metric label={t("Loading")} value="—"/>}</section>
    <section className="coverage-layout"><article className="panel coverage-tactics"><div className="section-title"><span>01</span><h2>{t("Tactic coverage")}</h2></div><div className="coverage-bars">{data?.tactics.map(item=><button className={tactic===item.name?"active":""} key={item.name} onClick={()=>setTactic(tactic===item.name?"":item.name)}><span>{label(item.name)}</span><i><em style={{width:`${item.coverage_percent}%`}}/></i><b>{item.coverage_percent}%</b><small>{item.represented_techniques}/{item.total_techniques} {t("techniques")} · {item.rule_count} {t("rules")}</small></button>)}</div></article>
      <article className="panel coverage-gaps"><div className="section-title"><span>02</span><h2>{t("Unrepresented techniques")}</h2><strong>{gaps.length}</strong></div><div className="coverage-controls"><input value={query} onChange={e=>setQuery(e.target.value)} placeholder={t("Search T1059 or technique name")}/><button onClick={()=>{setQuery("");setTactic("")}}>{t("Clear filters")}</button></div><div className="gap-list">{gaps.slice(0,150).map(item=><Link key={item.technique_id} to={`/catalog/mitre/${item.technique_id}`}><span>{item.is_subtechnique?"SUB":"TECH"}</span><b>{item.technique_id}</b><strong>{label(item.name)}</strong><small>{item.tactics.map(label).join(" · ")||t("No tactic")}</small></Link>)}</div>{gaps.length>150&&<p className="coverage-note">{t("Showing the first 150 gaps. Refine the filters to narrow the list.")}</p>}</article></section>
  </div>;
}
function Metric({label,value}:{label:string;value:string|number}){return <div><b>{typeof value==="number"?value.toLocaleString():value}</b><span>{label}</span></div>}
