import { Link } from "react-router-dom";
import { useEffect, useState } from "react";
import { getCatalogFacets, getCatalogStats, getFamilyStats } from "../services/api";
import { CatalogAssistant } from "../components/CatalogAssistant";
import { useI18n } from "../i18n";

export function CatalogOverview() {
  const { t, label, locale } = useI18n();
  const [stats,setStats] = useState<{total_rules:number;classified_rules:number;mitre_mapped:number;classification_records:number;product_status:Record<string,number>}|null>(null);
  const [facets,setFacets] = useState<Awaited<ReturnType<typeof getCatalogFacets>>|null>(null);
  const [familyCount,setFamilyCount] = useState<number>();
  useEffect(()=>{ void Promise.all([getCatalogStats(),getCatalogFacets(),getFamilyStats()]).then(([s,f,fs])=>{setStats(s);setFacets(f);setFamilyCount(fs.families)}); },[]);
  const card=(key:string,value:number|undefined,href:string,detail:string)=><Link className="catalog-card" to={href} key={key}><span>{t(key)}</span><strong>{value ?? "—"}</strong><small>{t(detail)} →</small></Link>;
  return <div className="catalog-page"><header className="catalog-hero"><div className="section-kicker">DETECTION CONTENT WORKSPACE</div><h1>{t("Detection Catalog")}</h1><p>{localeText(t, locale, "Search, understand and shortlist Suricata detections for the NDR product.")}</p><div className="catalog-hero-rule" aria-hidden="true"><span/><span/><span/><span/><span/></div></header>
    <section className="catalog-cards">{card("Total Rules",stats?.total_rules,"/catalog/rules","Unique imported rules")}{card("Detection Families",familyCount,"/catalog/families","Explainable rule groupings")}{card("Rules with MITRE",stats?.mitre_mapped,"/catalog/rules?mitre_status=has","Unique latest classifications")}{card("Rule Packs",undefined,"/catalog/rule-packs","Curated deployment collections")}</section>
    <p className="catalog-note">{stats ? (locale === "tr" ? `${stats.classification_records} sınıflandırma/model çıktısı ${stats.classified_rules} kural için saklanıyor. Aşağıdaki facet sayıları, en son başarılı sınıflandırmayı kullanarak her kuralı bir kez sayar.` : `${stats.classification_records} classification/model outputs are stored for ${stats.classified_rules} rules. Facet counts below count each rule once, using its latest successful classification.`) : t("Loading catalog counts…")}</p>
    <CatalogAssistant/>
    <section className="catalog-visuals">
      <article className="panel category-tree-panel"><div className="section-title"><span>01</span><h2>{t("Rules by Category")}</h2><span className="visual-caption">{t("classification branches")}</span></div><div className="category-tree" aria-label={t("Rules by Category")}><div className="tree-root"><span>{locale === "tr" ? <>TESPİT<br/><b>KATALOG</b></> : <>DETECTION<br/><b>CATALOG</b></>}</span></div><div className="tree-trunk" aria-hidden="true"/><div className="tree-branches">{facets?.categories.slice(0,12).map((x,i)=><Link className={`tree-node tree-node-${i % 4}`} to={`/catalog/rules?category=${encodeURIComponent(x.value)}`} key={x.value}><i aria-hidden="true"/><span>{label(x.value)}</span><strong>{x.count}</strong></Link>) || <div className="loading">Loading categories…</div>}</div></div></article>
      <article className="panel tactic-vine-panel"><div className="section-title"><span>02</span><h2>{t("MITRE Tactics")}</h2><span className="visual-caption">{t("evidence pathways")}</span></div><div className="tactic-vine" aria-label={t("MITRE Tactics")}><div className="vine-stem" aria-hidden="true"/>{facets?.mitre_tactics.slice(0,12).map((x,i)=><Link className={`vine-node vine-node-${i % 3}`} key={x.value} to={`/catalog/rules?mitre_tactic=${encodeURIComponent(x.value)}&mitre_status=has`}><i aria-hidden="true"/><span>{label(x.value)}</span><strong>{x.count}</strong></Link>) || <div className="loading">Loading tactics…</div>}</div></article>
    </section>
    <section className="panel catalog-cta"><h2>{t("Start with the catalog table")}</h2><p>{localeText(t, locale, "Filter by category, protocol, MITRE, model provenance or product status. Open a rule to inspect the original signature and make a product decision.")}</p><Link className="primary" to="/catalog/rules">{t("Open Rule Explorer →")}</Link></section></div>;
}

function localeText(t: (key: string) => string, locale: "en" | "tr", text: string) {
  const values: Record<string, string> = { "Search, understand and shortlist Suricata detections for the NDR product.": "NDR ürünü için Suricata tespitlerini arayın, inceleyin ve kısa listeye alın.", "Filter by category, protocol, MITRE, model provenance or product status. Open a rule to inspect the original signature and make a product decision.": "Kategori, protokol, MITRE, model kökeni veya ürün durumuna göre filtreleyin. Özgün imzayı incelemek ve ürün kararı vermek için bir kural açın." };
  return locale === "tr" ? (t(text) === text ? values[text] || text : t(text)) : text;
}
