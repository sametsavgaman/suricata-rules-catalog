import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { getRule } from "../services/api";
import { AddToRulePack } from "../components/AddToRulePack";
import { useI18n } from "../i18n";
import type { Rule } from "../types";

const RECENT_KEY = "suricata-recent-comparisons";
function loadRecent(): string[][] { try { const value = JSON.parse(localStorage.getItem(RECENT_KEY) || "[]"); return Array.isArray(value) ? value.filter((item): item is string[] => Array.isArray(item) && item.length >= 2).slice(0, 5) : []; } catch { return []; } }

export function CompareRules() {
  const { t } = useI18n();
  const [params, setParams] = useSearchParams();
  const initial = (params.get("sids") || "").split(",").filter(Boolean).slice(0, 4);
  const [inputs, setInputs] = useState<string[]>(initial.length ? [...initial, ...Array(Math.max(0, 2 - initial.length)).fill("")] : ["", ""]);
  const [rules, setRules] = useState<Rule[]>([]);
  const [recent, setRecent] = useState<string[][]>(() => loadRecent());
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const compare = async (source = inputs) => {
    const sids = [...new Set(source.map((value) => value.trim()).filter(Boolean))].slice(0, 4);
    if (sids.length < 2) { setError(t("Enter at least two SIDs, or open Compare from a rule row.")); return; }
    setLoading(true); setError("");
    try { const values = await Promise.all(sids.map(getRule)); setRules(values); setInputs([...sids, ...Array(Math.max(0, 2 - sids.length)).fill("")]); setParams({ sids: sids.join(",") }); const next = [sids, ...recent.filter((item) => item.join(",") !== sids.join(","))].slice(0, 5); setRecent(next); localStorage.setItem(RECENT_KEY, JSON.stringify(next)); }
    catch (cause) { setError(cause instanceof Error ? cause.message : t("Rules could not be loaded")); }
    finally { setLoading(false); }
  };
  useEffect(() => { if (initial.length >= 2) void compare(initial); }, []);
  const setInput = (index: number, value: string) => setInputs((current) => current.map((item, itemIndex) => itemIndex === index ? value : item));
  const useRecent = (sids: string[]) => setInputs([...sids, ...Array(Math.max(0, 2 - sids.length)).fill("")]);

  return <div className="product-intelligence-page compare-page">
    <header className="intelligence-hero compare-hero"><div className="section-kicker">{t("RULE COMPARISON · EVIDENCE DESK")}</div><h1>{t("Compare rules by evidence, not guesswork.")}</h1><p>{t("Build a set from any rule row or family profile, then inspect detection behavior, MITRE provenance, validation and product readiness side by side.")}</p><div className="compare-hero-notes"><span><b>01</b> {t("Select from the catalogue")}</span><span><b>02</b> {t("Keep the same evidence lens")}</span><span><b>03</b> {t("Decide what to review next")}</span></div></header>
    <section className="compare-workbench"><div className="panel compare-console"><div className="compare-console-head"><div><div className="section-kicker">{t("COMPARISON SET")}</div><h2>{t("Assemble your evidence desk")}</h2><p>{t("Use the Compare action on a rule to prefill one slot, then add one to three peers.")}</p></div><span className="compare-count">{inputs.filter(Boolean).length} / 4</span></div><div className="compare-inputs">{inputs.map((value, index) => <label key={index}><span>{t("Rule")} {index + 1} · SID</span><input value={value} onChange={(event) => setInput(index, event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") void compare(); }} placeholder={index === 0 ? "e.g. 2060513" : t("Add a peer SID")}/></label>)}{inputs.length < 4 && <button className="compare-add-rule" onClick={() => setInputs([...inputs, ""])}><span aria-hidden="true">+</span><b>{t("Add another rule")}</b><small>{inputs.length}/4</small></button>}</div><div className="compare-console-actions"><button className="primary compare-run" disabled={loading} onClick={() => void compare()}>{loading ? t("Loading evidence…") : t("Compare selected rules")}</button><Link className="compare-browse-link" to="/catalog/rules">{t("Browse Rule Explorer →")}</Link></div>{recent.length > 0 && <div className="compare-recent"><span>{t("Recent sets")}</span>{recent.map((set) => <button key={set.join(",")} onClick={() => useRecent(set)}>{set.join(" × ")}</button>)}</div>}</div><aside className="compare-guide"><div className="section-kicker">{t("HOW TO USE THIS VIEW")}</div><h2>{rules.length ? t("Evidence set loaded") : t("Start anywhere in the catalogue")}</h2><p>{rules.length ? t("Each card is the same rule contract, so differences stay visible and reviewable.") : t("You no longer need to remember two SIDs before arriving here. Open Compare directly from a rule, a family, or a catalogue row.")}</p><div className="compare-steps"><div><b>01</b><span>{t("Open a rule and choose ")}<strong>{t("Compare")}</strong>.</span></div><div><b>02</b><span>{t("Add a peer from the same family or tactic.")}</span></div><div><b>03</b><span>{t("Review evidence, then add the right rule to a pack.")}</span></div></div>{!rules.length && <Link to="/catalog/families" className="compare-guide-link">{t("Explore detection families ↗")}</Link>}</aside></section>
    {error && <div className="error">{error}</div>}{rules.length > 0 && <section className="rule-comparison-grid">{rules.map((rule) => <ComparisonCard key={rule.sid} rule={rule}/>)}</section>}
  </div>;
}

function ComparisonCard({ rule }: { rule: Rule }) {
  const { t, label } = useI18n();
  const c = rule.classification;
  return <article className="panel comparison-rule-card"><div className="comparison-rule-head"><div><span>SID {rule.sid} · REV {rule.rev}</span><h2>{rule.msg || t("Untitled rule")}</h2></div><Link to={`/rules/${rule.sid}`}>{t("Open ↗")}</Link></div><dl><Row name={t("Family")} value={rule.families?.map((x) => x.name).join(", ") || t("Unassigned")}/><Row name={t("Protocol")} value={label(rule.protocol)}/><Row name={t("Behavior")} value={c?.detected_behavior || t("Not classified")}/><Row name={t("Category")} value={c ? [c.category, c.subcategory].filter(Boolean).join(" / ") : "—"}/><Row name="MITRE" value={c?.mitre_technique_id ? `${c.mitre_technique_id} · ${c.mitre_technique}` : t("Unmapped")}/><Row name={t("MITRE evidence")} value={c?.evidence_strength || t("Unavailable")}/><Row name={t("Validator")} value={c?.validation?.status || t("Unavailable")}/><Row name={t("Human review")} value={c?.manual_review?.status || "UNREVIEWED"}/><Row name={t("Model")} value={c ? `${c.model_display_name || c.model_name} · ${c.classifier_version}` : "—"}/></dl><AddToRulePack sid={rule.sid}/></article>;
}
function Row({ name, value }: { name: string; value: string }) { return <div><dt>{name}</dt><dd>{value}</dd></div>; }
