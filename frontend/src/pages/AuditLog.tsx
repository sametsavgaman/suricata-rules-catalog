import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { getAuditLogs, type AuditLogItem } from "../services/api";
import { useI18n } from "../i18n";

const PAGE_SIZE = 25;

export function AuditLog() {
  const { t, label, locale } = useI18n();
  const [searchParams, setSearchParams] = useSearchParams();
  const [items, setItems] = useState<AuditLogItem[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const action = searchParams.get("action") || "";
  const sid = searchParams.get("sid") || "";
  const from = searchParams.get("date_from") || "";
  const to = searchParams.get("date_to") || "";
  const offset = Number(searchParams.get("offset") || 0);
  const update = (key: string, value: string, resetOffset = true) => {
    const next = new URLSearchParams(searchParams);
    if (value) next.set(key, value); else next.delete(key);
    if (resetOffset) next.delete("offset");
    setSearchParams(next);
  };
  useEffect(() => {
    const params = new URLSearchParams();
    if (action) params.set("action", action);
    if (sid) params.set("sid", sid);
    if (from) params.set("date_from", `${from}T00:00:00`);
    if (to) params.set("date_to", `${to}T23:59:59`);
    params.set("offset", String(offset)); params.set("limit", String(PAGE_SIZE));
    setLoading(true); setError("");
    void getAuditLogs(params).then((result) => { setItems(result.items); setTotal(result.total); }).catch((e) => setError(e instanceof Error ? e.message : t("Audit log could not be loaded"))).finally(() => setLoading(false));
  }, [action, sid, from, to, offset, t]);
  const clear = () => setSearchParams(new URLSearchParams());
  const formatAction = (value: string) => value === "MANUAL_REVIEW" ? t("Manual review") : value === "FIELD_CORRECTION" ? t("Field correction") : value === "FORCED_MITRE" ? (locale === "tr" ? "Zorla MITRE" : "Forced MITRE") : t("Product decision");
  const formatField = (value: string | null) => {
    if (!value) return "";
    const fields: Record<string, string> = {
      detected_behavior: t("Detected behavior"), detected_entity: t("Detected entity"), entity_type: t("Entity Type"),
      category: t("Category"), subcategory: t("Subcategory"), mitre_tactic: t("MITRE tactic"),
      mitre_technique: t("MITRE technique"), mitre_technique_id: t("MITRE technique ID"),
      cyber_kill_chain_phase: t("Cyber Kill Chain phase"),
    };
    return fields[value] || value.replaceAll("_", " ");
  };
  const formatValue = (value: string | null) => value ? label(value) : t("Not assigned");
  const describeEvent = (item: AuditLogItem) => {
    if (item.action === "FORCED_MITRE") return locale === "tr" ? "Normal sonuç eşleme üretmediği için kullanıcı isteğiyle Gemini üzerinden uyarılı bir MITRE eşlemesi oluşturuldu." : "A warning-labelled MITRE mapping was created through Gemini at the user's request after the normal result abstained.";
    if (item.action === "FIELD_CORRECTION") return t("A classification field was corrected and the original model output was preserved.");
    if (item.action === "MANUAL_REVIEW") {
      if (item.to_value === "APPROVED") return t("The rule's manual review was approved.");
      if (item.to_value === "REJECTED") return t("The rule's manual review was rejected.");
      if (item.to_value === "NEEDS_REVIEW") return t("The rule was sent for additional analyst review.");
      return t("The rule's manual review status was updated.");
    }
    if (item.to_value === "ALREADY_INTEGRATED") return t("The rule was added to the current product baseline.");
    if (item.from_value === "ALREADY_INTEGRATED" && item.to_value === "NOT_EVALUATED") return t("The rule was removed from the current product baseline; its catalogue record was kept.");
    if (item.to_value === "APPROVED_FOR_PRODUCT") return t("The rule was approved for product evaluation.");
    if (item.to_value === "CANDIDATE") return t("The rule was marked as a product candidate.");
    if (item.to_value === "REJECTED_FOR_PRODUCT") return t("The rule was rejected for the product.");
    return t("The product decision for this rule was updated.");
  };
  return <div className="audit-page">
    <header className="audit-hero">
      <div><span className="eyebrow">{t("TRACEABLE CHANGES")}</span><h1>{t("Audit Log")}</h1><p>{t("Review activity and corrections without user identity.")}</p></div>
      <div className="audit-hero-mark">◷</div>
    </header>
    <section className="panel audit-panel">
      <div className="section-title"><span>01</span><h2>{t("Review and correction history")}</h2></div>
      <p className="review-help">{t("This log records when an action happened and what changed. It does not identify the operator.")}</p>
      <div className="audit-filters">
        <label>{t("Action")}<select value={action} onChange={e => update("action", e.target.value)}><option value="">{t("All actions")}</option><option value="MANUAL_REVIEW">{t("Manual review")}</option><option value="FIELD_CORRECTION">{t("Field correction")}</option><option value="FORCED_MITRE">{locale === "tr" ? "Zorla MITRE" : "Forced MITRE"}</option><option value="PRODUCT_DECISION">{t("Product decision")}</option></select></label>
        <label>{t("SID")}<input value={sid} inputMode="numeric" onChange={e => update("sid", e.target.value.replace(/\D/g, ""))} placeholder="2527019" /></label>
        <label>{t("From date")}<input type="date" value={from} onChange={e => update("date_from", e.target.value)} /></label>
        <label>{t("To date")}<input type="date" value={to} onChange={e => update("date_to", e.target.value)} /></label>
        <button type="button" className="secondary" onClick={clear}>{t("Clear filters")}</button>
      </div>
      {loading ? <div className="empty">{t("Loading audit log…")}</div> : error ? <div className="error">{error}</div> : !items.length ? <div className="empty">{t("No audit events yet.")}</div> : <div className="table-wrap"><table className="audit-table"><thead><tr><th>{t("Time")}</th><th>{t("Rule")}</th><th>{t("Action")}</th><th>{t("Event details")}</th></tr></thead><tbody>{items.map(item => {
        const created = new Date(item.created_at);
        return <tr key={item.event_id}>
          <td className="audit-time"><b>{created.toLocaleDateString(locale === "tr" ? "tr-TR" : "en-US")}</b><span>{created.toLocaleTimeString(locale === "tr" ? "tr-TR" : "en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</span></td>
          <td className="audit-rule"><Link to={`/rules/${item.sid}`}><span>SID</span><b>{item.sid}</b><small>{t("Open rule details")} →</small></Link></td>
          <td><span className={`audit-action ${item.action.toLowerCase()}`}>{formatAction(item.action)}</span></td>
          <td className="audit-event-detail">
            <strong>{describeEvent(item)}</strong>
            {item.field_name && <div className="audit-field"><span>{t("Affected field")}</span><b>{formatField(item.field_name)}</b></div>}
            {(item.from_value || item.to_value) && <div className="audit-change-flow">
              <div><span>{item.from_value ? t("Previous value") : t("Before")}</span><b>{formatValue(item.from_value)}</b></div>
              <i aria-hidden="true">→</i>
              <div className="next"><span>{t("New value")}</span><b>{formatValue(item.to_value)}</b></div>
            </div>}
            {item.detail && <div className="audit-detail-note"><span>{t("Reason / note")}</span><p>{item.detail}</p></div>}
            <div className="audit-event-meta"><span>{t("Event record")} · {item.event_id}</span>{item.classification_id && <span>{t("Classification")} #{item.classification_id}</span>}</div>
          </td>
        </tr>;
      })}</tbody></table></div>}
      <div className="pagination"><button className="secondary" disabled={offset === 0} onClick={() => update("offset", String(Math.max(0, offset - PAGE_SIZE)), false)}>{t("Previous")}</button><span>{total ? `${offset + 1}–${Math.min(offset + PAGE_SIZE, total)} / ${total}` : "0"}</span><button className="secondary" disabled={offset + PAGE_SIZE >= total} onClick={() => update("offset", String(offset + PAGE_SIZE), false)}>{t("Next")}</button></div>
    </section>
  </div>;
}
