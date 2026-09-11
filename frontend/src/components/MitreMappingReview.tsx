import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import { getRule, getRuleOverrides, saveRuleOverrides } from "../services/api";
import { useI18n } from "../i18n";

type RuleSnapshot = any;

export function MitreMappingReview({ initialSid = "", initialClassificationId = null }: { initialSid?: string; initialClassificationId?: number | null }) {
  const { t } = useI18n();
  const [sid, setSid] = useState(initialSid);
  const [rule, setRule] = useState<RuleSnapshot | null>(null);
  const [classificationId, setClassificationId] = useState<number | null>(initialClassificationId);
  const [tactic, setTactic] = useState("");
  const [technique, setTechnique] = useState("");
  const [techniqueId, setTechniqueId] = useState("");
  const [reason, setReason] = useState("");
  const [history, setHistory] = useState<any[]>([]);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [saved, setSaved] = useState(false);

  const loadRule = async (value = sid) => {
    if (!/^\d+$/.test(value.trim())) {
      setError(t("Enter a valid SID."));
      return;
    }
    setBusy("load");
    setError("");
    setSaved(false);
    try {
      const item = await getRule(value.trim());
      const current = item.classification_options?.find((x: any) => Number(x.id) === classificationId) || item.classification;
      setRule(item);
      setClassificationId(current?.id || item.classification?.id || null);
      setTactic(current?.mitre_tactic || "");
      setTechnique(current?.mitre_technique || "");
      setTechniqueId(current?.mitre_technique_id || "");
      setHistory((await getRuleOverrides(value.trim())).items || []);
    } catch (e) {
      setRule(null);
      setHistory([]);
      setError(e instanceof Error ? e.message : t("Rule could not be loaded"));
    } finally {
      setBusy("");
    }
  };

  useEffect(() => {
    if (initialSid) void loadRule(initialSid);
  }, [initialSid]);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!rule) return;
    if (reason.trim().length < 3) {
      setError(t("A reason is required for every MITRE correction."));
      return;
    }
    setBusy("save");
    setError("");
    setSaved(false);
    try {
      const result = await saveRuleOverrides(String(rule.sid), {
        classification_id: classificationId,
        corrections: {
          mitre_tactic: tactic.trim() || null,
          mitre_technique: technique.trim() || null,
          mitre_technique_id: techniqueId.trim().toUpperCase() || null,
        },
        reason: reason.trim(),
      });
      setHistory(result.items || []);
      setReason("");
      setSaved(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : t("MITRE correction could not be saved"));
    } finally {
      setBusy("");
    }
  };

  const options = rule?.classification_options || (rule?.classification ? [rule.classification] : []);
  const current = options.find((x: any) => x.id === classificationId) || rule?.classification;
  return <section className="panel mitre-review-workbench">
    <div className="section-title"><span>REVIEW</span><h2>{t("MITRE Mapping Review")}</h2><span className="ai-badge">{t("AUDIT LOGGED")}</span></div>
    <div className="mitre-review-intro"><p>{t("Correct only the MITRE mapping here. Original model output remains immutable and every change is recorded with its reason.")}</p></div>
    <form className="mitre-review-lookup" onSubmit={e => { e.preventDefault(); void loadRule(); }}>
      <label>{t("Rule SID")}<input inputMode="numeric" value={sid} onChange={e => setSid(e.target.value)} placeholder="2527019" /></label>
      <button className="primary" disabled={busy === "load"}>{busy === "load" ? t("Loading…") : t("Load rule")}</button>
    </form>
    {error && <div className="error" role="alert">{error}</div>}
    {saved && <div className="success-message" role="status">{t("MITRE correction saved and added to the audit history.")}</div>}
    {rule && <form className="mitre-review-form" onSubmit={submit}>
      <div className="mitre-review-context"><b>SID {rule.sid}</b><span>{rule.msg || t("Untitled rule")}</span>{options.length > 1 && <label>{t("Classification result")}<select value={classificationId || ""} onChange={e => { const id = Number(e.target.value); const item = options.find((x: any) => x.id === id); setClassificationId(id || null); setTactic(item?.mitre_tactic || ""); setTechnique(item?.mitre_technique || ""); setTechniqueId(item?.mitre_technique_id || ""); }}>{options.map((x: any) => <option key={x.id} value={x.id}>{x.provider || "provider"} · {x.model_name || x.model || x.id}</option>)}</select></label>}</div>
      <div className="mitre-review-current"><span>{t("Current mapping")}</span><strong>{[current?.mitre_technique_id, current?.mitre_technique, current?.mitre_tactic].filter(Boolean).join(" · ") || t("No supported mapping")}</strong></div>
      <div className="mitre-review-fields"><label>{t("MITRE Tactic")}<input value={tactic} onChange={e => setTactic(e.target.value)} placeholder={t("Leave blank to clear")}/></label><label>{t("MITRE Technique")}<input value={technique} onChange={e => setTechnique(e.target.value)} placeholder={t("Leave blank to clear")}/></label><label>{t("MITRE ID")}<input value={techniqueId} onChange={e => setTechniqueId(e.target.value.toUpperCase())} placeholder="T1071.004"/></label></div>
      <label className="mitre-review-reason">{t("Reason (required)")}<textarea value={reason} onChange={e => setReason(e.target.value)} minLength={3} maxLength={2000} placeholder={t("Explain the evidence for this mapping change.")} /></label>
      <div className="review-actions"><button className="primary" disabled={busy === "save"}>{busy === "save" ? t("Saving…") : t("Save MITRE correction")}</button></div>
    </form>}
    {history.length > 0 && <details className="mitre-review-history"><summary>{t("MITRE audit history")} ({history.length})</summary><ul>{history.map((item: any) => <li key={item.id}><strong>{item.field_name}</strong>: {item.original_value || t("Not assigned")} → {item.corrected_value || t("Not assigned")} · {item.reason} · {new Date(item.created_at).toLocaleString()}</li>)}</ul></details>}
  </section>;
}
