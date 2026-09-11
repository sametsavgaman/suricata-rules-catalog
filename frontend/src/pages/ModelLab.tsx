import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { DecisionAssessment } from "../components/DecisionAssessment";
import { ModelRulePicker } from "../components/ModelRulePicker";
import { ProviderSettings } from "../components/ProviderSettings";
import {
  compareModels,
  getModelConfig,
  getModelStatus,
  saveComparisonReview,
  testModel,
  updateModelConfig,
  type ProviderHealth,
} from "../services/api";
import { useI18n } from "../i18n";

const fields = [
  ["detected_behavior", "Behavior"],
  ["detected_entity", "Entity"],
  ["entity_type", "Entity Type"],
  ["category", "Category"],
  ["subcategory", "Subcategory"],
  ["mitre_tactic", "MITRE Tactic"],
  ["mitre_technique", "MITRE Technique"],
  ["mitre_technique_id", "MITRE ID"],
  ["cyber_kill_chain_phase", "Kill Chain"],
] as const;

const challengers = [
  { id: "gemini", label: "Gemini", tone: "gemini" },
  { id: "claude", label: "Claude", tone: "claude" },
  { id: "openai", label: "ChatGPT / Codex", tone: "openai" },
] as const;
const qwen = { id: "ollama", label: "Qwen3 8B", tone: "qwen" };

function valueOf(item: any, key: string) { return item?.[key] || "Not assigned"; }
function providerOf(item: any) { return String(item?.provider || "").toLowerCase(); }
function labelFor(id: string, config: any) {
  if (id === "ollama") return `${qwen.label} · LOCAL`;
  const provider = challengers.find((item) => item.id === id);
  const model = config?.[id]?.model;
  return `${provider?.label || id}${model ? ` · ${model}` : " · API"}`;
}

export function ModelLab() {
  const { t, label } = useI18n();
  const [config, setConfig] = useState<any>(null);
  const [form, setForm] = useState<any>({});
  const [notice, setNotice] = useState("");
  const [noticeKind, setNoticeKind] = useState<"success" | "error">("error");
  const [busy, setBusy] = useState("");
  const [health, setHealth] = useState<Record<string, ProviderHealth>>({});
  const [healthBusy, setHealthBusy] = useState(true);
  const [rule, setRule] = useState<any>(null);
  const [search, setSearch] = useState("");
  const [comparison, setComparison] = useState<any>(null);
  const [selected, setSelected] = useState<string[]>(["gemini"]);
  const [preference, setPreference] = useState("UNSURE");
  const [note, setNote] = useState("");

  const notify = (message: string, kind: "success" | "error" = "error") => {
    setNotice(message);
    setNoticeKind(kind);
  };

  useEffect(() => {
    let active = true;
    setHealthBusy(true);
    void getModelConfig().then((value) => {
      if (!active) return;
      setConfig(value);
      setForm({
        openai_base_url: value.openai?.base_url || "https://api.openai.com/v1",
        openai_model: value.openai?.model || "",
        gemini_model: value.gemini?.model || "",
        ollama_base_url: value.ollama?.base_url || "http://127.0.0.1:11434",
        ai_provider: value.default_provider,
        helper_provider: value.helper_provider || "gemini",
      });
    }).catch((cause) => {
      if (active) notify(cause instanceof Error ? cause.message : "Configuration failed");
    });
    void getModelStatus().then((status) => {
      if (!active) return;
      setHealth(status.providers || {});
      setSelected((current) => current.filter((id) => status.providers?.[id]?.ok));
    }).catch(() => undefined).finally(() => {
      if (active) setHealthBusy(false);
    });
    return () => { active = false; };
  }, []);

  const isAvailable = (id: string) => health[id]?.ok === true;
  const healthLabel = (id: string) => healthBusy ? t("Checking…") : isAvailable(id) ? t("Active") : t("Unavailable");

  const save = async (provider: "gemini" | "ollama") => {
    setBusy("save");
    try {
      const { helper_provider: _helperProvider, ...classificationForm } = form;
      const value = await updateModelConfig({ ...classificationForm, ai_provider: provider });
      setConfig(value);
      setForm({ ...form, ai_provider: provider });
      const status = await getModelStatus();
      setHealth(status.providers || {});
      notify(`${provider === "gemini" ? "Gemini" : "Qwen3 8B"} saved and selected for classification. Qwen3 8B remains locked as the comparison reference.`, "success");
    } catch (cause) {
      notify(cause instanceof Error ? cause.message : "Save failed");
    } finally {
      setBusy("");
    }
  };

  const saveHelper = async () => {
    const provider = form.helper_provider || config.helper_provider || "gemini";
    if (!isAvailable(provider)) {
      notify(t("Test and activate this provider before selecting it as the helper model."));
      return;
    }
    setBusy("helper");
    try {
      const value = await updateModelConfig({ helper_provider: provider });
      setConfig(value);
      setForm((current: any) => ({ ...current, helper_provider: provider }));
      notify(t("Helper model saved. Auxiliary workflows will use this provider."), "success");
    } catch (cause) {
      notify(cause instanceof Error ? cause.message : "Save failed");
    } finally {
      setBusy("");
    }
  };

  const test = async (provider: "openai" | "gemini" | "claude" | "ollama") => {
    setBusy(provider);
    try {
      const result = await testModel(provider);
      setHealth((current) => ({ ...current, [provider]: result }));
      notify(result.ok ? `${provider} connected · ${result.model} · ${result.latency_ms} ms` : (result.error || "Connection test failed"), result.ok ? "success" : "error");
    } catch (cause) {
      notify(cause instanceof Error ? cause.message : "Test failed");
    } finally {
      setBusy("");
    }
  };

  const toggle = (id: string) => setSelected((current) => current.includes(id) ? current.filter((item) => item !== id) : [...current, id]);
  const run = async () => {
    if (!rule || !selected.length) return;
    setBusy("compare");
    setComparison(null);
    try {
      setComparison(await compareModels({ sid: rule.sid, rev: rule.rev, models: selected }));
    } catch (cause) {
      notify(cause instanceof Error ? cause.message : "Comparison failed");
    } finally {
      setBusy("");
    }
  };

  const results: any[] = comparison?.results || [];
  const cards = useMemo(() => [...selected, "ollama"].map((id) => ({ id, item: results.find((item) => providerOf(item) === id) })), [results, selected]);
  const qwenResult = results.find((item) => providerOf(item) === "ollama");
  const reviewTarget = cards.find((item) => item.id !== "ollama" && item.item)?.item;
  if (!config) return <div className="loading">{t("Loading Model Lab…")}</div>;

  return <>
    <header className="topbar">
      <div>
        <Link className="back" to="/">← {t("Rule Explorer")}</Link>
        <div className="brand-line"><span className="eyebrow">{t("MODEL OPERATIONS")}</span></div>
        <h1>{t("Model Control Center")}</h1>
        <p>{t("Select challengers and compare them against the immutable Qwen reference.")}</p>
      </div>
      <div className="topbar-actions"><div className="live-status"><i /> {t("Classifier")} {config.classifier_version}</div><button onClick={() => window.location.reload()} disabled={!!busy}>{t("Refresh services")}</button></div>
    </header>
    {notice && <div className={noticeKind === "success" ? "success-message" : "error"} role="status" aria-live="polite">{notice}</div>}
    <ProviderSettings onConfigChange={setConfig} providerHealth={health} onHealthChange={(provider, result) => setHealth((current) => ({ ...current, [provider]: result }))} />
    <section className="panel helper-model-panel">
      <div className="panel-heading"><div><div className="section-kicker">{t("AUXILIARY AI")}</div><h2>{t("Select helper model")}</h2><p>{t("Catalog questions and forced MITRE requests use this model. The main Qwen classification pipeline remains unchanged.")}</p></div><span className="badge auto_classified">{t("Current")}: {(config.helper_provider || "gemini").toUpperCase()}</span></div>
      <div className="model-form"><label>{t("Helper provider")}<select value={form.helper_provider || config.helper_provider || "gemini"} onChange={(event) => setForm({ ...form, helper_provider: event.target.value })}>{challengers.map((provider) => <option key={provider.id} value={provider.id} disabled={!isAvailable(provider.id)}>{provider.label} · {healthLabel(provider.id)}{config[provider.id]?.model ? ` · ${config[provider.id].model}` : ""}</option>)}</select></label><p>{t("Only configured providers that pass the connection check can be selected. API keys remain on the backend.")}</p><div className="review-actions"><button className="primary" onClick={() => void saveHelper()} disabled={!!busy || !isAvailable(form.helper_provider || config.helper_provider || "gemini")}>{busy === "helper" ? t("Saving…") : t("Save helper model")}</button></div></div>
    </section>
    <section className="model-cards">
      <article className="panel model-card"><div className="section-title"><span>GEMINI</span><h2>Gemini API</h2><span className={`badge ${health.gemini?.ok ? "auto_classified" : "neutral"}`}>{healthLabel("gemini")}</span></div><div className="model-form"><label>{t("Model")}<input value={form.gemini_model || ""} onChange={(event) => setForm({ ...form, gemini_model: event.target.value })} /></label><p>{t("Default comparison challenger · API")}</p><div className="review-actions"><button className="primary" onClick={() => void save("gemini")} disabled={!!busy}>{busy === "save" ? t("Saving…") : t("Save & Use for Classification")}</button><button onClick={() => void test("gemini")} disabled={!!busy}>{t("Test Connection")}</button></div></div></article>
      <article className="panel model-card"><div className="section-title"><span>QWEN REFERENCE</span><h2>Qwen3 8B</h2><span className={`badge ${health.ollama?.ok ? "auto_classified" : "neutral"}`}>{healthBusy ? t("Checking…") : health.ollama?.ok ? "ACTIVE · LOCKED" : `${t("Unavailable")} · LOCKED`}</span></div><div className="model-form"><label>{t("Base URL")}<input value={form.ollama_base_url || ""} onChange={(event) => setForm({ ...form, ollama_base_url: event.target.value })} /></label><label>{t("Model")}<input value="qwen3:8b" readOnly /></label><p>{t("Immutable baseline. The model name cannot be changed.")}</p><div className="review-actions"><button className="primary" onClick={() => void save("ollama")} disabled={!!busy}>{busy === "save" ? t("Saving…") : t("Save & Use for Classification")}</button><button onClick={() => void test("ollama")} disabled={!!busy}>{t("Test Local Model")}</button></div></div></article>
    </section>
    <section className="panel comparison-lab">
      <div className="panel-heading"><div><div className="section-kicker">MODEL CONTROL CENTER · BENCHMARK DECK</div><h2>{t("Choose your challengers")}</h2><p>{t("Qwen3 8B is always included. Select one or more configured models before running the comparison.")}</p></div></div>
      <div className="comparison-selector">{challengers.map((provider) => { const available = isAvailable(provider.id); return <button key={provider.id} className={`model-choice ${provider.tone} ${selected.includes(provider.id) ? "selected" : ""} ${available ? "available" : "unavailable"}`} onClick={() => toggle(provider.id)} disabled={!!busy || !available}><span className="choice-orb" /><span><b>{provider.label}</b><small>{healthLabel(provider.id)} · {config[provider.id]?.model || t("Not configured")}</small></span><i>{available ? (selected.includes(provider.id) ? "✓" : "+") : "—"}</i></button>; })}</div>
      <ModelRulePicker value={search} selectedRule={rule} onChange={(value) => { setSearch(value); setRule(null); setComparison(null); }} onSelect={(item) => { setRule(item); setComparison(null); }} />
      {rule && <><div className="rule-meta"><span>SID {rule.sid}</span><span>REV {rule.rev}</span><span>{rule.msg || t("No message")}</span></div><pre className="raw-rule">{rule.raw_rule}</pre><div className="comparison-launch"><div className="comparison-radar"><span className="radar-ring ring-one" /><span className="radar-ring ring-two" /><span className="radar-core" /><span className="radar-scan" /></div><div><small>{t("READY TO COMPARE")}</small><strong>{selected.map((id) => labelFor(id, config)).join(" × ")} × {labelFor("ollama", config)}</strong><p>{t("Every model receives the same canonical rule context.")}</p></div><button className="primary run-compare" onClick={() => void run()} disabled={!!busy || !selected.length}>{busy === "compare" ? t("Running comparison…") : t("Run Comparison")}</button></div></>}
      {comparison && <div className="comparison-grid multi">{cards.map(({ id, item }) => <article className={`panel result-card ${id === "ollama" ? "reference-card" : ""}`} key={id}><div className="section-title"><span>{labelFor(id, config)}</span><span className={`badge ${item?.classification_status === "FAILED" || !item ? "failed" : "auto_classified"}`}>{item ? label(item.classification_status) : t("UNAVAILABLE")}</span></div>{item ? <><DecisionAssessment classification={item} /><div className="classification-grid">{fields.map(([key, fieldLabel]) => <label key={key}>{t(fieldLabel)}<div className="value">{valueOf(item, key)}</div></label>)}</div></> : <div className="empty">{t("Provider result unavailable.")}</div>}</article>)}</div>}
      {comparison && qwenResult && reviewTarget && <div className="comparison-review"><strong>{t("Which result is better?")}</strong><select value={preference} onChange={(event) => setPreference(event.target.value)}><option value="UNSURE">{t("Unsure")}</option>{selected.map((id) => <option key={id} value={id.toUpperCase()}>{labelFor(id, config)}</option>)}<option value="QWEN">Qwen3 8B</option><option value="BOTH_ACCEPTABLE">{t("Both acceptable")}</option><option value="NEITHER">{t("Neither")}</option></select><input placeholder={t("Optional comparison note")} value={note} onChange={(event) => setNote(event.target.value)} /><button onClick={() => void saveComparisonReview(rule.sid, { classification_a_id: reviewTarget.id, classification_b_id: qwenResult.id, preference, note })}>{t("Save Comparison Review")}</button></div>}
    </section>
  </>;
}
