import { Link } from "react-router-dom";
import { useEffect, useState } from "react";
import { getCatalogFacets, getCatalogStats } from "../services/api";

export function CatalogOverview() {
  const [stats,setStats] = useState<{total_rules:number;classified_rules:number;mitre_mapped:number;classification_records:number;product_status:Record<string,number>}|null>(null);
  const [facets,setFacets] = useState<Awaited<ReturnType<typeof getCatalogFacets>>|null>(null);
  useEffect(()=>{ void Promise.all([getCatalogStats(),getCatalogFacets()]).then(([s,f])=>{setStats(s);setFacets(f)}); },[]);
  const card=(label:string,value:number|undefined,href:string,detail:string)=><Link className="catalog-card" to={href} key={label}><span>{label}</span><strong>{value ?? "—"}</strong><small>{detail} →</small></Link>;
  return <><header className="catalog-hero"><div className="section-kicker">DETECTION CONTENT WORKSPACE</div><h1>Detection Catalog</h1><p>Search, understand and shortlist Suricata detections for the NDR product.</p></header>
    <section className="catalog-cards">{card("Total Rules",stats?.total_rules,"/catalog/rules","Unique imported rules")}{card("Rules with MITRE",stats?.mitre_mapped,"/catalog/rules?mitre_status=has","Unique latest classifications")}{card("Candidates",stats?.product_status.CANDIDATE,"/catalog/candidates?status=CANDIDATE","Product planning queue")}{card("Shortlisted",stats?.product_status.SHORTLISTED,"/catalog/candidates?status=SHORTLISTED","Priority detections")}</section>
    <p className="catalog-note">{stats ? `${stats.classification_records} classification/model outputs are stored for ${stats.classified_rules} rules. Facet counts below count each rule once, using its latest successful classification.` : "Loading catalog counts…"}</p>
    <section className="catalog-columns"><article className="panel catalog-section"><div className="section-title"><span>01</span><h2>Rules by Category</h2></div><div className="facet-list">{facets?.categories.slice(0,12).map(x=><Link to={`/catalog/rules?category=${encodeURIComponent(x.value)}`} key={x.value}><span>{x.value}</span><strong>{x.count}</strong></Link>) || <div className="loading">Loading categories…</div>}</div></article><article className="panel catalog-section"><div className="section-title"><span>02</span><h2>MITRE Tactics</h2></div><div className="facet-list">{facets?.mitre_tactics.slice(0,12).map(x=><Link to={`/catalog/rules?mitre_tactic=${encodeURIComponent(x.value)}`} key={x.value}><span>{x.value}</span><strong>{x.count}</strong></Link>) || <div className="loading">Loading tactics…</div>}</div></article></section>
    <section className="panel catalog-cta"><h2>Start with the catalog table</h2><p>Filter by category, protocol, MITRE, model provenance or product status. Open a rule to inspect the original signature and make a product decision.</p><Link className="primary" to="/catalog/rules">Open Rule Explorer →</Link></section></>;
}
