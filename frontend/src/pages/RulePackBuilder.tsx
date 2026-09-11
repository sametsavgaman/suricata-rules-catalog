import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { getCatalogFacets, getRule, getRules } from "../services/api";
import { AddToRulePack } from "../components/AddToRulePack";
import { CompareSelectButton } from "../components/CompareSelectButton";
import {
  addRuleToPack,
  createRulePack,
  deleteRulePack,
  getActiveRulePackId,
  loadRulePacks,
  removeRuleFromPack,
  setActiveRulePack,
  updateRulePack,
  type StoredRulePack,
} from "../services/rulePack";
import type { Rule } from "../types";
import { useI18n } from "../i18n";

type RuleFacets = Awaited<ReturnType<typeof getCatalogFacets>>;

function download(name: string, content: string, type = "text/plain") {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  anchor.click();
  URL.revokeObjectURL(url);
}

export function RulePackBuilder() {
  const { t } = useI18n();
  const [packs, setPacks] = useState<StoredRulePack[]>([]);
  const [activeId, setActiveId] = useState("");
  const [newName, setNewName] = useState("");
  const [sid, setSid] = useState("");
  const [rules, setRules] = useState<Rule[]>([]);
  const [error, setError] = useState("");
  const [facets, setFacets] = useState<RuleFacets | null>(null);
  const [mitreTactic, setMitreTactic] = useState("");
  const [mitreTechnique, setMitreTechnique] = useState("");
  const [suggestions, setSuggestions] = useState<Rule[]>([]);
  const [suggestionsLoading, setSuggestionsLoading] = useState(false);
  const [suggestionsError, setSuggestionsError] = useState("");
  const [downloading, setDownloading] = useState<"rules" | "manifest" | null>(null);

  const refresh = () => {
    const next = loadRulePacks();
    setPacks(next);
    setActiveId((current) => next.some((pack) => pack.id === current)
      ? current
      : (getActiveRulePackId() || next[0]?.id || ""));
  };

  useEffect(() => {
    refresh();
    window.addEventListener("rule-pack-change", refresh);
    return () => window.removeEventListener("rule-pack-change", refresh);
  }, []);

  useEffect(() => {
    void getCatalogFacets()
      .then(setFacets)
      .catch(() => setSuggestionsError(t("MITRE categories could not be loaded.")));
  }, [t]);

  const active = packs.find((pack) => pack.id === activeId) || null;

  useEffect(() => {
    let cancelled = false;
    if (!active) {
      setRules([]);
      setError("");
      return () => { cancelled = true; };
    }
    setError("");
    setActiveRulePack(active.id);
    void Promise.allSettled(active.sids.map((value) => getRule(String(value))))
      .then((results) => {
        if (cancelled) return;
        const loaded = results.flatMap((result) => result.status === "fulfilled" ? [result.value] : []);
        setRules(loaded);
        if (loaded.length < active.sids.length) {
          setError(loaded.length
            ? t("Some rules in this pack are no longer in the catalogue.")
            : t("The selected pack has no rules available in the catalogue."));
        }
      })
      .catch(() => { if (!cancelled) setError(t("Pack rules could not be loaded")); });
    return () => { cancelled = true; };
  }, [activeId, active?.updatedAt]);

  useEffect(() => {
    const selected = mitreTechnique || mitreTactic;
    if (!selected) {
      setSuggestions([]);
      setSuggestionsError("");
      setSuggestionsLoading(false);
      return;
    }
    const params = new URLSearchParams({ offset: "0", limit: "12", sort: "recent", mitre_status: "has" });
    if (mitreTechnique) params.set("mitre_technique_id", mitreTechnique);
    if (mitreTactic) params.set("mitre_tactic", mitreTactic);
    setSuggestionsLoading(true);
    setSuggestionsError("");
    void getRules(params)
      .then((response) => setSuggestions(response.items))
      .catch(() => setSuggestionsError(t("Recommended rules could not be loaded.")))
      .finally(() => setSuggestionsLoading(false));
  }, [mitreTactic, mitreTechnique, t]);

  const create = () => {
    if (!newName.trim()) return;
    const pack = createRulePack(newName);
    setNewName("");
    setActiveId(pack.id);
  };

  const removePack = () => {
    if (!active) return;
    if (!window.confirm(`${t("Delete rule pack")} “${active.name}”?`)) return;
    deleteRulePack(active.id);
    setActiveId("");
    setError("");
  };

  const add = () => {
    const value = Number(sid);
    if (!active || !Number.isSafeInteger(value)) {
      setError(t("Choose a pack and enter a valid SID."));
      return;
    }
    addRuleToPack(active.id, value);
    setSid("");
  };

  const remove = (value: number) => {
    if (active) removeRuleFromPack(active.id, value);
  };

  const mapped = useMemo(() => rules.filter((rule) => rule.classification?.mitre_technique_id), [rules]);
  const techniques = [...new Set(mapped.map((rule) => rule.classification!.mitre_technique_id!))];
  const name = (active?.name || "rule-pack").replace(/[^a-zA-Z0-9-_]/g, "-");
  const manifest = () => ({
    format_version: "suricata-rule-pack-v1",
    name: active?.name,
    generated_at: new Date().toISOString(),
    rule_count: rules.length,
    sids: rules.map((rule) => ({
      sid: rule.sid,
      rev: rule.rev,
      source_file: rule.source_file,
      families: rule.families || [],
      classification: {
        category: rule.classification?.category || null,
        mitre_technique_id: rule.classification?.mitre_technique_id || null,
      },
    })),
  });

  const downloadPack = async (kind: "rules" | "manifest") => {
    if (!rules.length || downloading) return;
    setDownloading(kind);
    // Yield once so the loading state is painted before serialising a large pack.
    await new Promise<void>((resolve) => window.setTimeout(resolve, 0));
    try {
      if (kind === "rules") {
        download(`${name}.rules`, `${rules.map((rule) => rule.raw_rule).join("\n")}\n`);
      } else {
        download(`${name}-manifest.json`, `${JSON.stringify(manifest(), null, 2)}\n`, "application/json");
      }
    } finally {
      setDownloading(null);
    }
  };

  return (
    <div className="product-intelligence-page">
      <header className="intelligence-hero">
        <div className="section-kicker">{t("RULE PACK BUILDER")}</div>
        <h1>{t("Build and manage multiple rule packs.")}</h1>
        <p>{t("Keep separate packs for different products, environments or deployment decisions, then export the currently selected pack.")}</p>
      </header>
      <section className="pack-layout">
        <aside className="panel pack-summary">
          <div className="section-title"><span>01</span><h2>{t("Your rule packs")}</h2></div>
          <div className="pack-tabs">{packs.map((pack) => <button className={pack.id === activeId ? "active" : ""} onClick={() => setActiveId(pack.id)} key={pack.id}><b>{pack.name}</b><span>{pack.sids.length} {t("rules")}</span></button>)}</div>
          <div className="pack-add"><input value={newName} onChange={(event) => setNewName(event.target.value)} placeholder={t("New pack name")} /><button onClick={create}>{t("Create pack")}</button></div>
          {active && <>
            <label>{t("Selected pack name")}<input value={active.name} onChange={(event) => updateRulePack(active.id, { name: event.target.value })} /></label>
            <button className="pack-delete" onClick={removePack}>{t("Delete this pack")}</button>
            <div className="pack-add"><input value={sid} onChange={(event) => setSid(event.target.value)} placeholder={t("Add SID")} /><button onClick={add}>{t("Add")}</button></div>
            <dl><Row name={t("Rules")} value={rules.length} /><Row name={t("Mapped rules")} value={mapped.length} /><Row name={t("Techniques")} value={techniques.length} /></dl>
            <div className="pack-exports"><button type="button" className="primary pack-download-button" disabled={!rules.length || downloading !== null} onClick={() => { void downloadPack("rules"); }}>{downloading === "rules" ? <><span className="download-spinner" aria-hidden="true" />{t("Preparing .rules download…")}</> : t("Download .rules")}</button><button type="button" className="pack-download-button" disabled={!rules.length || downloading !== null} onClick={() => { void downloadPack("manifest"); }}>{downloading === "manifest" ? <><span className="download-spinner" aria-hidden="true" />{t("Preparing manifest download…")}</> : t("Download manifest")}</button></div>
          </>}
        </aside>
        <article className="panel pack-rules">
          <div className="section-title"><span>02</span><h2>{active?.name || t("Choose or create a rule pack")}</h2><strong>{rules.length}</strong></div>
          {error && <div className="error">{error}</div>}
          {rules.length ? rules.map((rule) => (
            <div className="pack-rule" key={rule.sid}>
              <div><Link to={`/rules/${rule.sid}`}>SID {rule.sid} / {rule.rev}</Link><strong>{rule.msg || t("Untitled rule")}</strong><small>{rule.classification?.category || t("Unclassified")} · {rule.classification?.mitre_technique_id || t("MITRE unmapped")}</small></div>
              <div><CompareSelectButton sid={rule.sid} compact /><button onClick={() => remove(rule.sid)}>{t("Remove")}</button></div>
            </div>
          )) : <div className="family-empty"><b>{t("No rules in this pack.")}</b><span>{t("Use “Add to Rule Pack” on any rule row, or enter a SID here.")}</span></div>}
        </article>
      </section>
      <section className="panel pack-recommendations">
        <div className="panel-heading">
          <div>
            <div className="section-kicker">{t("MITRE RULE RECOMMENDER")}</div>
            <h2>{t("Find rules by MITRE category")}</h2>
            <p>{t("Choose a tactic or technique to see locally classified rules that can be reviewed and added to a pack.")}</p>
          </div>
          <strong>{suggestions.length}</strong>
        </div>
        <div className="pack-recommendation-filters">
          <label>
            <span>{t("MITRE tactic")}</span>
            <select value={mitreTactic} onChange={(event) => setMitreTactic(event.target.value)}>
              <option value="">{t("Choose a tactic")}</option>
              {facets?.mitre_tactics.map((item) => <option value={item.value} key={item.value}>{item.value} ({item.count})</option>)}
            </select>
          </label>
          <label>
            <span>{t("MITRE technique")}</span>
            <select value={mitreTechnique} onChange={(event) => setMitreTechnique(event.target.value)}>
              <option value="">{t("Choose a technique")}</option>
              {facets?.mitre_techniques.map((item) => <option value={item.value} key={item.value}>{item.value} ({item.count})</option>)}
            </select>
          </label>
          {(mitreTactic || mitreTechnique) && <button type="button" onClick={() => { setMitreTactic(""); setMitreTechnique(""); }}>{t("Clear MITRE filter")}</button>}
        </div>
        {suggestionsLoading && <div className="loading">{t("Loading recommended rules…")}</div>}
        {suggestionsError && <div className="error pack-recommendation-error">{suggestionsError}</div>}
        {!suggestionsLoading && !suggestionsError && !(mitreTactic || mitreTechnique) && <div className="pack-recommendation-empty">{t("Select a MITRE tactic or technique to see recommendations.")}</div>}
        {!suggestionsLoading && !suggestionsError && (mitreTactic || mitreTechnique) && !suggestions.length && <div className="pack-recommendation-empty">{t("No classified rules match this MITRE selection.")}</div>}
        {!suggestionsLoading && suggestions.length > 0 && <div className="pack-recommendation-list">
          {suggestions.map((rule) => (
            <div className="pack-recommendation-row" key={rule.sid}>
              <div className="pack-recommendation-main">
                <Link to={`/rules/${rule.sid}`}>SID {rule.sid} / {rule.rev}</Link>
                <strong>{rule.msg || t("Untitled rule")}</strong>
                <small>{rule.classification?.mitre_technique_id || t("MITRE unmapped")} · {rule.classification?.mitre_technique || t("Technique name unavailable")}</small>
              </div>
              <div className="pack-recommendation-actions">
                <AddToRulePack sid={rule.sid} compact />
              </div>
            </div>
          ))}
        </div>}
      </section>
    </div>
  );
}

function Row({ name, value }: { name: string; value: number }) {
  return <div><dt>{name}</dt><dd>{value.toLocaleString()}</dd></div>;
}
