import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { DecisionAssessment } from "../components/DecisionAssessment";
import { RuleDecisionCard } from "../components/RuleDecisionCard";
import { StatusBadge } from "../components/StatusBadge";
import {
  classifyRule,
  getNeighbors,
  getReviewHistory,
  getRule,
  saveReview,
  getProductDecision,
  saveProductDecision,
  getProductHistory,
  getForcedMitre,
  forceMitre,
  saveRuleOverrides,
  translateTexts,
  type ProductStatus,
  type ForcedMitreState,
} from "../services/api";
import type { Rule } from "../types";
import { useI18n, valueLabels, type Locale } from "../i18n";

function Value({ children }: { children: React.ReactNode }) {
  const { t } = useI18n();
  return (
    <div className="value">
      {children || <span className="null-value">{t("Not assigned")}</span>}
    </div>
  );
}
function FieldValue({
  classification,
  field,
  children,
  localized,
}: {
  classification: NonNullable<Rule["classification"]>;
  field: string;
  children: React.ReactNode;
  localized?: Record<string, string>;
}) {
  const { t, label } = useI18n();
  const decision = classification.field_decisions?.[field];
  const text =
    decision?.status === "ABSTAINED"
      ? t("Abstained")
      : decision?.status === "NOT_APPLICABLE"
        ? t("Not applicable")
        : decision?.status === "UNAVAILABLE"
          ? t("Unavailable")
          : children;
  const status =
    decision?.status && decision.status !== "ASSIGNED"
      ? label(decision.status.replaceAll("_", " "))
      : "";
  return (
    <Value>
      {text || <span className="null-value">{t("Not assigned")}</span>}{" "}
      {status && (
        <small>
          {status}
          {decision?.reason
            ? ` — ${localized?.[decision.reason] || decision.reason}`
            : ""}
        </small>
      )}
    </Value>
  );
}

function localizedFieldName(field: string, locale: Locale): string {
  if (locale === "en") return field.replaceAll("_", " ");
  const names: Record<string, string> = {
    detected_behavior: "tespit edilen davranış",
    detected_entity: "tespit edilen varlık",
    entity_type: "varlık türü",
    category: "kategori",
    subcategory: "alt kategori",
    mitre_tactic: "MITRE taktiği",
    mitre_technique: "MITRE tekniği",
    mitre_technique_id: "MITRE ID",
    cyber_kill_chain_phase: "öldürme zinciri aşaması",
  };
  return names[field] || field.replaceAll("_", " ");
}

function systemSummary(rule: Rule, locale: Locale): string {
  const c = rule.classification;
  if (!c)
    return locale === "tr"
      ? "Bu kural için başarılı bir sınıflandırma bulunmuyor."
      : "No successful classification is available for this rule.";
  const decisions = c.field_decisions || {};
  const assigned = Object.entries(decisions)
    .filter(([, d]) => d.status === "ASSIGNED")
    .map(([field]) => localizedFieldName(field, locale));
  const abstained = Object.entries(decisions)
    .filter(([, d]) => d.status === "ABSTAINED")
    .map(([field]) => localizedFieldName(field, locale));
  const category =
    locale === "tr" ? valueLabels[c.category || ""] || c.category : c.category;
  const subcategory =
    locale === "tr"
      ? valueLabels[c.subcategory || ""] || c.subcategory
      : c.subcategory;
  const parts =
    locale === "tr"
      ? [
          c.detected_behavior
            ? `Tespit edilen davranış: ${c.detected_behavior}.`
            : `Kural ${category || "sınıflandırılmamış"}${subcategory ? ` / ${subcategory}` : ""} olarak kategorize edildi.`,
        ]
      : [
          c.detected_behavior
            ? `Detected behavior: ${c.detected_behavior}.`
            : `The rule was categorized as ${c.category || "unclassified"}${c.subcategory ? ` / ${c.subcategory}` : ""}.`,
        ];
  if (assigned.length)
    parts.push(
      locale === "tr"
        ? `Atanan alanlar: ${assigned.join(", ")}.`
        : `Assigned: ${assigned.join(", ")}.`,
    );
  if (abstained.length)
    parts.push(
      locale === "tr"
        ? `Çekimser kalınan alanlar: ${abstained.join(", ")}.`
        : `Abstained on: ${abstained.join(", ")}.`,
    );
  parts.push(
    locale === "tr"
      ? `Doğrulayıcı: ${c.validation?.status || "kullanılamıyor"}. Alan atama sayıları tamamlanmayı gösterir, doğruluğu değil.`
      : `Validator: ${c.validation?.status || "unavailable"}. Field assignment counts describe completion, not accuracy.`,
  );
  return parts.join(" ");
}
function polishedSystemSummary(rule: Rule, locale: Locale): string {
  const c = rule.classification;
  if (!c)
    return locale === "tr"
      ? "Bu kural için başarılı bir sınıflandırma bulunmuyor."
      : "No successful classification is available for this rule.";
  const decisions = c.field_decisions || {};
  const assigned = Object.entries(decisions)
    .filter(([, d]) => d.status === "ASSIGNED")
    .map(([field]) => localizedFieldName(field, locale));
  const abstained = Object.entries(decisions)
    .filter(([, d]) => d.status === "ABSTAINED")
    .map(([field]) => localizedFieldName(field, locale));
  const mitreAbstained = Object.entries(decisions).some(
    ([field, decision]) =>
      decision.status === "ABSTAINED" &&
      ["mitre_tactic", "mitre_technique", "mitre_technique_id"].includes(field),
  );
  const status = c.validation?.status || "UNAVAILABLE";
  const category =
    locale === "tr" ? valueLabels[c.category || ""] || c.category : c.category;
  const subcategory =
    locale === "tr"
      ? valueLabels[c.subcategory || ""] || c.subcategory
      : c.subcategory;
  const parts =
    locale === "tr"
      ? [
          status === "PASS"
            ? "Yapısal doğrulama tamamlandı; bu sonuç biçimsel tutarlılığı gösterir, doğruluğu garanti etmez."
            : status === "FAIL"
              ? "Doğrulama sorunları bulundu; bu kural ürün kararı öncesinde incelenmelidir."
              : "Doğrulama durumu mevcut değil; sonuç temkinli yorumlanmalıdır.",
          c.detected_behavior
            ? "Önerilen davranış: " + c.detected_behavior + "."
            : "Kural " +
              (category || "sınıflandırılmamış") +
              (subcategory ? " / " + subcategory : "") +
              " olarak önerildi.",
        ]
      : [
          status === "PASS"
            ? "Structural validation completed; this confirms format and consistency, not factual accuracy."
            : status === "FAIL"
              ? "Validation issues were found; review this rule before making a product decision."
              : "Validation status is unavailable; interpret the result cautiously.",
          c.detected_behavior
            ? "Proposed behavior: " + c.detected_behavior + "."
            : "The rule was proposed as " +
              (c.category || "unclassified") +
              (c.subcategory ? " / " + c.subcategory : "") +
              ".",
        ];
  if (assigned.length)
    parts.push(
      locale === "tr"
        ? assigned.length +
            " alan kanıtla eşleştirildi: " +
            assigned.join(", ") +
            "."
        : assigned.length +
            " fields were assigned from the available evidence: " +
            assigned.join(", ") +
            ".",
    );
  if (abstained.length)
    parts.push(
      locale === "tr"
        ? "Kanıt yetersizliği nedeniyle şu alanlar atanmadı: " +
            abstained.join(", ") +
            "."
        : "These fields were left unassigned because the evidence was insufficient: " +
            abstained.join(", ") +
            ".",
    );
  if (mitreAbstained && !c.final_mitre_mapping)
    parts.push(
      locale === "tr"
        ? "MITRE alanları için yeterli kanıt bulunmadığından doğrulanmış bir final eşleme atanmadı; açıklamadaki teknik adları yalnızca model adayıdır."
        : "No final MITRE mapping was accepted because the evidence was insufficient; technique names in the rationale remain model candidates only.",
    );
  return parts.join(" ");
}

export function RuleDetail() {
  const { label, locale, t } = useI18n();
  const { sid = "" } = useParams();
  const navigate = useNavigate();
  const [rule, setRule] = useState<Rule | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [executionProvider, setExecutionProvider] = useState("");
  const [neighbors, setNeighbors] = useState<{
    previous_sid: number | null;
    next_sid: number | null;
  }>({ previous_sid: null, next_sid: null });
  const [reviewHistory, setReviewHistory] = useState<
    Array<{
      status: string;
      note: string | null;
      reviewer_type: string;
      reviewed_at: string;
    }>
  >([]);
  const [reviewNote, setReviewNote] = useState("");
  const [selectedClassificationId, setSelectedClassificationId] = useState<
    number | null
  >(() => {
    const value = Number(
      new URLSearchParams(window.location.search).get("classification_id"),
    );
    return Number.isSafeInteger(value) && value > 0 ? value : null;
  });
  const [product, setProduct] = useState<{
    status: ProductStatus;
    note: string | null;
    updated_at: string;
  } | null>(null);
  const [productHistory, setProductHistory] = useState<
    Array<{
      from_status: string | null;
      to_status: string;
      note: string | null;
      created_at: string;
    }>
  >([]);
  const [productNote, setProductNote] = useState("");
  const [technicalTab, setTechnicalTab] = useState<"parser" | "agent">("parser");
  const [correctionOpen, setCorrectionOpen] = useState(false);
  const [correctionBusy, setCorrectionBusy] = useState(false);
  const [correctionReason, setCorrectionReason] = useState("");
  const [correctionValues, setCorrectionValues] = useState<Record<string, string>>({});
  const [forcedMitre, setForcedMitre] = useState<ForcedMitreState | null>(null);
  const [forcedMitreOpen, setForcedMitreOpen] = useState(false);
  const [forcedMitreAccepted, setForcedMitreAccepted] = useState(false);
  const [forcedMitreBusy, setForcedMitreBusy] = useState(false);
  const [forcedMitreError, setForcedMitreError] = useState("");
  const [localizedProse, setLocalizedProse] = useState<Record<string, string>>(
    {},
  );
  const load = () =>
    getRule(sid)
      .then((x) => {
        setRule(x);
        setSelectedClassificationId((current) =>
          current && x.classification_options?.some((c) => c.id === current)
            ? current
            : x.classification?.id || null,
        );
      })
      .catch((e) => setError(e.message));
  useEffect(() => {
    void load();
    void getNeighbors(sid)
      .then(setNeighbors)
      .catch(() => undefined);
    void getReviewHistory(sid)
      .then((x) => setReviewHistory(x.items))
      .catch(() => undefined);
    void getProductDecision(sid)
      .then((x) => {
        setProduct(x);
        setProductNote(x.note || "");
      })
      .catch(() => undefined);
    void getProductHistory(sid)
      .then(setProductHistory)
      .catch(() => undefined);
  }, [sid]);
  useEffect(() => {
    if (!selectedClassificationId) {
      setForcedMitre(null);
      return;
    }
    setForcedMitreOpen(false);
    setForcedMitreAccepted(false);
    setForcedMitreError("");
    void getForcedMitre(sid, selectedClassificationId)
      .then(setForcedMitre)
      .catch(() => setForcedMitre(null));
  }, [sid, selectedClassificationId]);
  useEffect(() => {
    const classification =
      rule?.classification_options?.find(
        (item) => item.id === selectedClassificationId,
      ) || rule?.classification;
    if (locale !== "tr" || !classification) {
      setLocalizedProse({});
      return;
    }
    const texts = [
      classification.explanation,
      classification.mapping_reason || "",
      ...classification.evidence,
      ...classification.validation_issues,
      ...(classification.consistency_warnings || []),
      ...Object.values(classification.field_decisions || {}).map(
        (decision) => decision.reason || "",
      ),
    ].filter(Boolean);
    if (!texts.length) return;
    void translateTexts(texts, locale)
      .then((result) =>
        setLocalizedProse(
          Object.fromEntries(
            texts.map((text, index) => [
              text,
              result.translations[index] || text,
            ]),
          ),
        ),
      )
      .catch(() => undefined);
  }, [
    locale,
    rule?.classification?.id,
    rule?.classification_options,
    selectedClassificationId,
  ]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (
        e.target instanceof HTMLInputElement ||
        e.target instanceof HTMLTextAreaElement ||
        e.target instanceof HTMLSelectElement
      )
        return;
      if (e.key.toLowerCase() === "j" && neighbors.next_sid)
        navigate(`/rules/${neighbors.next_sid}`);
      if (e.key.toLowerCase() === "k" && neighbors.previous_sid)
        navigate(`/rules/${neighbors.previous_sid}`);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [neighbors, navigate]);
  const classify = async () => {
    if (!rule) return;
    setBusy(true);
    try {
      const result = await classifyRule(rule.sid, true, executionProvider);
      await load();
      setSelectedClassificationId(result.id);
    } catch (e) {
      setError(e instanceof Error ? e.message : t("Classification failed"));
    } finally {
      setBusy(false);
    }
  };
  const runForcedMitre = async () => {
    if (!selectedClassificationId || !forcedMitreAccepted) return;
    setForcedMitreBusy(true);
    setForcedMitreError("");
    try {
      const mapping = await forceMitre(sid, selectedClassificationId);
      setForcedMitre({ eligible: true, reason: null, mapping });
      setForcedMitreOpen(false);
      setForcedMitreAccepted(false);
    } catch (e) {
      setForcedMitreError(e instanceof Error ? e.message : "Yardımcı model MITRE eşlemesini tamamlayamadı.");
    } finally {
      setForcedMitreBusy(false);
    }
  };
  if (error)
    return (
      <div className="error page-error">
        {error} <Link to="/">{t("Return")}</Link>
      </div>
    );
  if (!rule) return <div className="loading">{t("Loading rule…")}</div>;
  const requestedId = Number(
    new URLSearchParams(window.location.search).get("classification_id"),
  );
  const missingRequested =
    requestedId > 0 &&
    !rule.classification_options?.some((item) => item.id === requestedId);
  const c =
    rule.classification_options?.find(
      (x) => x.id === selectedClassificationId,
    ) || rule.classification;
  const displayRule =
    c && c !== rule.classification ? { ...rule, classification: c } : rule;
  const parsed = {
    action: rule.action,
    protocol: rule.protocol,
    source: rule.source,
    source_port: rule.source_port,
    direction: rule.direction,
    destination: rule.destination,
    destination_port: rule.destination_port,
    classtype: rule.classtype,
    metadata: rule.metadata,
    references: rule.references,
    flow: rule.flow,
    flowbits: rule.flowbits,
    contents: rule.contents,
    pcre: rule.pcre,
    app_layer: rule.app_layer,
  };
  const copy = (text: string) => void navigator.clipboard?.writeText(text);
  const csvCell = (value: unknown) =>
    `"${String(value ?? "").replaceAll('"', '""')}"`;
  const exportRuleCsv = () => {
    const row = [
      ["SID", rule.sid],
      ["REV", rule.rev],
      ["MSG", rule.msg],
      ["SOURCE_FILE", rule.source_file],
      ["RAW_RULE", rule.raw_rule],
      ["PARSED_INPUT_JSON", JSON.stringify(parsed)],
      [
        "MODEL_SIGNAL_SEMANTICS",
        "MODEL_SELF_REPORTED_UNCALIBRATED; not a correctness probability",
      ],
      ["CLASSIFICATION_JSON", JSON.stringify(c || null)],
      ["AGENT_ACTIVITY_JSON", JSON.stringify(c?.agent_activity || null)],
    ];
    const csv =
      "\ufeff" +
      row
        .map(([key, value]) => `${csvCell(key)},${csvCell(value)}`)
        .join("\r\n") +
      "\r\n";
    const url = URL.createObjectURL(
      new Blob([csv], { type: "text/csv;charset=utf-8" }),
    );
    const link = document.createElement("a");
    link.href = url;
    link.download = `suricata-rule-${rule.sid}-rev-${rule.rev}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  };
  const exportRulePdf = () => window.print();
  const review = async (status: string) => {
    try {
      await saveReview(sid, status, reviewNote, c?.id);
      const [fresh, history] = await Promise.all([
        getRule(sid),
        getReviewHistory(sid),
      ]);
      setRule(fresh);
      setReviewHistory(history.items);
      setReviewNote("");
    } catch (e) {
      setError(e instanceof Error ? e.message : t("Review save failed"));
    }
  };
  const openCorrection = () => {
    if (!c) return;
    setCorrectionValues(Object.fromEntries([
      "detected_behavior", "detected_entity", "entity_type", "category", "subcategory",
      "mitre_tactic", "mitre_technique", "mitre_technique_id", "cyber_kill_chain_phase",
    ].map((field) => [field, String((c as unknown as Record<string, unknown>)[field] ?? "")] )));
    setCorrectionOpen(true);
  };
  const saveCorrection = async () => {
    if (!c) return;
    const fields = ["detected_behavior", "detected_entity", "entity_type", "category", "subcategory", "mitre_tactic", "mitre_technique", "mitre_technique_id", "cyber_kill_chain_phase"];
    const corrections = Object.fromEntries(fields.filter((field) => {
      const before = String((c as unknown as Record<string, unknown>)[field] ?? "");
      return (correctionValues[field] || "") !== before;
    }).map((field) => [field, correctionValues[field]?.trim() || null]));
    if (!Object.keys(corrections).length) { setError(t("Change at least one field before saving")); return; }
    if (correctionReason.trim().length < 3) { setError(t("A reason is required and the original model output remains preserved.")); return; }
    setCorrectionBusy(true);
    try {
      await saveRuleOverrides(sid, { classification_id: c.id, corrections, reason: correctionReason.trim() });
      await load();
      setCorrectionOpen(false); setCorrectionReason("");
    } catch (e) { setError(e instanceof Error ? e.message : t("Correction save failed")); }
    finally { setCorrectionBusy(false); }
  };
  const updateProduct = async (status: ProductStatus) => {
    try {
      const value = await saveProductDecision(sid, status, productNote);
      setProduct(value);
      setProductHistory(await getProductHistory(sid));
    } catch (e) {
      setError(
        e instanceof Error ? e.message : t("Product decision save failed"),
      );
    }
  };
  return (
    <>
      {missingRequested && (
        <div className="review-box" role="status">
          {t(
            "The classification requested by this link is not present in the current revision. The current SID revision is shown below; compare it with the REV in the assistant list.",
          )}
        </div>
      )}
      {product?.status === "ALREADY_INTEGRATED" && (
        <div className="product-integrated-notice" role="status">
          <span className="product-integrated-mark">✓</span>
          <div>
            <strong>{t("This rule is currently used in the product")}</strong>
            <p>{t("It is marked as already integrated in the product catalogue.")}</p>
          </div>
        </div>
      )}
      <div className="detail-actions" style={{ marginBottom: 16 }}>
        <Link
          className="compare-detail-action"
          to={`/catalog/compare?sids=${rule.sid}`}
        >
          {t("Compare")}
        </Link>
        <label htmlFor="execution-provider">
          {t("Run classification with")}
        </label>
        <select
          id="execution-provider"
          disabled={busy}
          value={executionProvider}
          onChange={(e) => setExecutionProvider(e.target.value)}
        >
          <option value="">{t("Configured default")}</option>
          <option value="openai">{t("OpenAI · API")}</option>
          <option value="claude">{t("Claude · API")}</option>
          <option value="gemini">{t("Gemini · API")}</option>
          <option value="ollama">{t("Qwen · Local Ollama")}</option>
        </select>
        <small>
          {t(
            "Provider overrides use V2.1 · configured default follows Model Lab settings",
          )}
        </small>
      </div>
      <header className="detail-header reveal">
        <div>
          <Link className="back" to="/">
            {t("← Rule Explorer")}
          </Link>
          <div className="sid-line">
            <span className="detail-kicker">{t("INSPECTION RECORD")}</span>
            <h1>SID {rule.sid}</h1>
            <StatusBadge status={c?.classification_status} />
          </div>
          <p>
            {rule.msg || t("No message")} · rev {rule.rev} ·{" "}
            {rule.source_file || t("unknown source")}
          </p>
        </div>
        <div className="detail-actions">
          {(rule.classification_options?.length || 0) > 1 && (
            <select
              aria-label={t("Classification result")}
              value={selectedClassificationId || ""}
              onChange={(e) =>
                setSelectedClassificationId(Number(e.target.value))
              }
            >
              {rule.classification_options?.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.model_display_name || item.model_name} —{" "}
                  {item.classifier_version}
                </option>
              ))}
            </select>
          )}
          <button
            onClick={() =>
              neighbors.previous_sid &&
              navigate(`/rules/${neighbors.previous_sid}`)
            }
            disabled={!neighbors.previous_sid}
          >
            {t("← Prev")}
          </button>
          <button
            onClick={() =>
              neighbors.next_sid && navigate(`/rules/${neighbors.next_sid}`)
            }
            disabled={!neighbors.next_sid}
          >
            {t("Next →")}
          </button>
          <button onClick={exportRuleCsv}>{t("Export CSV")}</button>
          <button onClick={exportRulePdf}>{t("Export PDF")}</button>
          <button className="primary" disabled={busy} onClick={classify}>
            {busy
              ? t("Classifying…")
              : c
                ? t("Reclassify")
                : t("Classify rule")}
          </button>
        </div>
      </header>
      {locale === "tr" && Object.keys(localizedProse).length > 0 && (
        <article className="panel span-2" style={{ marginBottom: 16 }}>
          <div className="section-title">
            <span>TR</span>
            <h2>{t("Türkçe AI açıklamaları")}</h2>
          </div>
          <div className="evidence">
            {Object.values(localizedProse).map((text, index) => (
              <p key={index}>{text}</p>
            ))}
          </div>
        </article>
      )}
      <RuleDecisionCard rule={displayRule} product={product} />
      <section className="detail-grid">
        <article className="panel flow-panel">
          <div className="section-title">
            <span>01</span>
            <h2>{t("Original Suricata Rule")}</h2>
            <button className="copy-button" onClick={() => copy(rule.raw_rule)}>
              {t("Copy")}
            </button>
          </div>
          <div className="rule-meta">
            <span>SID {rule.sid}</span>
            <span>REV {rule.rev}</span>
            <span>{rule.source_file || t("unknown source")}</span>
          </div>
          <pre className="raw-rule">{rule.raw_rule}</pre>
        </article>
        <article className="panel ai-panel">
          <div className="section-title">
            <span>02</span>
            <h2>{t("AI Classification")}</h2>
            <span className="ai-badge">
              ● {c?.provider || "AI"} · {c?.inference_mode || "INFERENCE"}
            </span>
          </div>
          {forcedMitre?.mapping && (
            <div className="forced-mitre-warning" role="alert">
              <strong>{locale === "tr" ? "Zorla MITRE sınıflandırması" : "Forced MITRE classification"}</strong>
              <p>{locale === "tr" ? "Normal sınıflandırma MITRE eşlemesi üretmedi. Bu sonuç kullanıcı isteğiyle seçili yardımcı model tarafından zorla oluşturulmuştur; yanıltıcı olabilir." : "The normal classification produced no MITRE mapping. This result was forced through the selected helper model at the user's request and may be misleading."}</p>
            </div>
          )}
          {c ? (
            <div className="classification-grid">
              <label>
                {t("Model")}
                <Value>
                  {c.model_display_name || c.model_name}
                  <small>
                    {t("Provider:")} {c.provider || "UNKNOWN"} · {t("Mode:")}{" "}
                    {c.inference_mode || "UNKNOWN"} · {t("Classifier:")}{" "}
                    {c.classifier_version}
                  </small>
                </Value>
              </label>
              <label>
                {t("Behavior")}
                <FieldValue
                  classification={c}
                  field="detected_behavior"
                  localized={localizedProse}
                >
                  {c.detected_behavior}
                </FieldValue>
              </label>
              <label>
                {t("Entity")}
                <FieldValue
                  classification={c}
                  field="detected_entity"
                  localized={localizedProse}
                >
                  {c.detected_entity}
                  <small>{c.entity_type}</small>
                </FieldValue>
              </label>
              <label>
                {t("Category")}
                <FieldValue
                  classification={c}
                  field="category"
                  localized={localizedProse}
                >
                  {label(c.category)}
                  <small>{label(c.subcategory)}</small>
                </FieldValue>
              </label>
              <label>
                {t("MITRE tactic")}
                {forcedMitre?.mapping ? (
                  <Value>{label(forcedMitre.mapping.tactic)}<small>{forcedMitre.mapping.provider.toUpperCase()} · {forcedMitre.mapping.model_name}</small></Value>
                ) : (
                  <FieldValue classification={c} field="mitre_tactic" localized={localizedProse}>{label(c.mitre_tactic)}</FieldValue>
                )}
              </label>
              <label>
                {t("Final MITRE mapping")}
                {forcedMitre?.mapping ? (
                  <Value>
                    <Link className="mitre-inline-link" to={`/catalog/mitre/${forcedMitre.mapping.technique_id}`}>
                      {forcedMitre.mapping.technique_name}
                      <small>{forcedMitre.mapping.technique_id} · {t("Open intelligence ↗")}</small>
                    </Link>
                    <small>{locale === "tr" ? `Zorlanmış sonuç · model sinyali ${(forcedMitre.mapping.confidence * 100).toFixed(0)}%` : `Forced result · model signal ${(forcedMitre.mapping.confidence * 100).toFixed(0)}%`}</small>
                  </Value>
                ) : (
                  <FieldValue classification={c} field="mitre_technique" localized={localizedProse}>
                  {c.mitre_technique_id ? (
                    <Link
                      className="mitre-inline-link"
                      to={`/catalog/mitre/${c.mitre_technique_id}`}
                    >
                      {c.mitre_technique}
                      <small>
                        {c.mitre_technique_id} · {t("Open intelligence ↗")}
                      </small>
                    </Link>
                  ) : (
                    c.mitre_technique
                  )}
                  </FieldValue>
                )}
              </label>
              <label>
                {t("Kill Chain")}
                <FieldValue
                  classification={c}
                  field="cyber_kill_chain_phase"
                  localized={localizedProse}
                >
                  {c.cyber_kill_chain_phase}
                </FieldValue>
              </label>
            </div>
          ) : (
            <div className="empty">
              {t("This rule has not been classified.")}
            </div>
          )}
          {c && (
            <DecisionAssessment classification={c} localized={localizedProse} />
          )}
        </article>
        <div className="flow-connector" aria-hidden="true">
          <span>◈</span>
          <i />
        </div>
        <article className="panel">
          <div className="section-title">
            <span>03</span>
            <h2>{t("MITRE Provenance")}</h2>
            <button
              className="copy-button"
              onClick={() => c && copy(JSON.stringify(c, null, 2))}
            >
              {t("Copy JSON")}
            </button>
          </div>
          {c ? (
            <div className="evidence">
              {forcedMitre?.mapping && <div className="forced-mitre-provenance"><strong>{locale === "tr" ? "Kullanıcı tarafından zorlandı" : "User-forced mapping"}</strong><p>{forcedMitre.mapping.technique_id} — {forcedMitre.mapping.technique_name} · {forcedMitre.mapping.tactic || "—"}</p><p>{forcedMitre.mapping.explanation}</p><small>{locale === "tr" ? "Kanonik ad ve taktik yerel ATT&CK deposunda doğrulandı; eşlemenin davranışsal doğruluğu garanti edilmez." : "Canonical name and tactic were validated locally; behavioral correctness is not guaranteed."}</small></div>}
              <p>
                <strong>
                  {c.mitre_mapping_method?.replaceAll("_", " ") || "UNKNOWN"}
                </strong>
              </p>
              <p>
                {(c.mapping_reason &&
                  (localizedProse[c.mapping_reason] || c.mapping_reason)) ||
                  t("No mapping provenance recorded.")}
              </p>
              <p>
                <strong>{t("Source Metadata")}</strong>
                <br />
                {c.source_mitre_mapping
                  ? `${c.source_mitre_mapping.technique_id}${c.source_mitre_mapping.technique_name ? ` — ${c.source_mitre_mapping.technique_name}` : ""}`
                  : t("No MITRE mapping in rule")}
              </p>
              <p>
                <strong>{t("Final Mapping")}</strong>
                <br />
                {c.final_mitre_mapping
                  ? `${c.final_mitre_mapping.technique_id} — ${c.final_mitre_mapping.technique_name}`
                  : t("No supported mapping")}
              </p>
              <p>
                <strong>{t("MITRE evidence indicator")}</strong>
                <br />
                {c.evidence_strength || "UNKNOWN"}
                <small>
                  {t(
                    "Provenance-based indicator: STRONG for an exact source ID match, MEDIUM for other assigned mappings, NONE for no mapping, UNKNOWN for missing metadata. This is not an overall reliability score.",
                  )}
                </small>
              </p>
              <p>
                <strong>{t("MITRE Retrieval Score")}</strong>
                <br />
                {c.mitre_retrieval_score == null
                  ? t("Not available")
                  : c.mitre_retrieval_score.toFixed(2)}
                <small>{t("Retrieval relevance, not model confidence.")}</small>
              </p>
              {forcedMitre?.eligible && (
                <div className="forced-mitre-action">
                  {!forcedMitreOpen ? (
                    <>
                      <p>{locale === "tr" ? "Normal sınıflandırıcı bu kuralı bir MITRE tekniğine bağlamadı. Yalnızca bu kural için seçili yardımcı modelden uyarılı, en iyi tahmin eşlemesi isteyebilirsiniz." : "The normal classifier did not map this rule to MITRE. You can request a warning-labelled best-effort mapping from the selected helper model for this rule only."}</p>
                      <button type="button" onClick={() => setForcedMitreOpen(true)}>{forcedMitre.mapping ? (locale === "tr" ? "Zorla yeniden sınıflandır (sonuç yanlış olabilir)" : "Force classification again (may be wrong)") : (locale === "tr" ? "Zorla sınıflandır (sonuç yanlış olabilir)" : "Force classification (may be wrong)")}</button>
                    </>
                  ) : (
                    <div className="forced-mitre-confirm">
                      <strong>{locale === "tr" ? "Bu işlem normal sonucu değiştirmez" : "This does not change the normal result"}</strong>
                      <p>{locale === "tr" ? "Seçili yardımcı modele kuralın ayrıştırılmış sinyalleri, normal sınıflandırma özeti ve yerel ATT&CK deposundan öneri adayları gönderilir. Model başka bir kanonik teknik de seçebilir; sonuç yerel depoda doğrulanır fakat davranışsal doğruluğu garanti edilmez." : "The selected helper model receives parsed rule signals, the normal classification summary, and suggestions from the local ATT&CK repository. It may choose another canonical technique; the ID is validated locally, but behavioral correctness is not guaranteed."}</p>
                      <label><input type="checkbox" checked={forcedMitreAccepted} onChange={(event) => setForcedMitreAccepted(event.target.checked)} /> {locale === "tr" ? "Sonucun yanıltıcı olabileceğini anlıyorum." : "I understand that the result may be misleading."}</label>
                      {forcedMitreError && <div className="error">{forcedMitreError}</div>}
                      <div><button type="button" className="primary" disabled={!forcedMitreAccepted || forcedMitreBusy} onClick={() => void runForcedMitre()}>{forcedMitreBusy ? (locale === "tr" ? "Yardımcı model değerlendiriyor…" : "Helper model is evaluating…") : (locale === "tr" ? "Onayla ve çalıştır" : "Confirm and run")}</button><button type="button" disabled={forcedMitreBusy} onClick={() => setForcedMitreOpen(false)}>{t("Cancel")}</button></div>
                    </div>
                  )}
                </div>
              )}
            </div>
          ) : (
            <div className="empty">
              {t("MITRE provenance appears after classification.")}
            </div>
          )}
        </article>
        <article className="panel">
          <div className="section-title">
            <span>03</span>
            <h2>{t("System Decision")}</h2>
          </div>
          {c ? (
            <div className="evidence">
              <p>
                <strong>
                  {c.classification_status === "REVIEW_REQUIRED"
                    ? t("Review required")
                    : c.classification_status === "FAILED"
                      ? t("Classification failed")
                      : c.validation?.status === "PASS"
                        ? t("Classification accepted by validator")
                        : t("Classification decision recorded")}
                </strong>
              </p>
              <p>{polishedSystemSummary(displayRule, locale)}</p>
              {c.explanation && (
                <p>
                  <strong>{t("Model explanation:")}</strong>{" "}
                  {localizedProse[c.explanation] || c.explanation}
                  <small className="decision-note">
                    {locale === "tr"
                      ? "Sağlayıcının gerekçesidir; bağımsız doğrulama değildir."
                      : "Provider rationale only; it is not independent validation."}
                  </small>
                </p>
              )}
              <h3>{t("Decision Evidence")}</h3>
              <ul>
                {c.evidence.map((item, i) => (
                  <li key={i}>{localizedProse[item] || item}</li>
                ))}
              </ul>
              {c.validation_issues.length > 0 && (
                <div className="review-box">
                  <strong>{t("Validation issues")}</strong>
                  <ul>
                    {c.validation_issues.map((x, i) => (
                      <li key={i}>{localizedProse[x] || x}</li>
                    ))}
                  </ul>
                </div>
              )}
              {c.consistency_warnings?.length ? (
                <div className="review-box">
                  <strong>{t("Consistency warnings")}</strong>
                  <ul>
                    {c.consistency_warnings.map((x, i) => (
                      <li key={i}>{localizedProse[x] || x}</li>
                    ))}
                  </ul>
                </div>
              ) : null}
            </div>
          ) : (
            <div className="empty">
              {t("This rule has not been classified.")}
            </div>
          )}
        </article>
        <article className="panel">
          <div className="section-title">
            <span>06</span>
            <h2>{t("Manual Review")}</h2>
          </div>
          <div className="manual-review">
            <p>
              {t("Current status:")}{" "}
              <strong>
                {c?.manual_review?.status
                  ? label(c.manual_review.status)
                  : c
                    ? t("UNREVIEWED")
                    : t("NOT CLASSIFIED")}
              </strong>
            </p>
            <p className="review-help">
              {t(
                "After inspecting the rule, approve it when the classification is correct. Use Correct classification when a field is wrong.",
              )}{" "}
              <strong>{t("Needs Review")}</strong>{" "}
              {t("keeps it open for later verification.")}
            </p>
            {c?.manual_review?.note && <p>{c?.manual_review.note}</p>}
            <textarea
              value={reviewNote}
              onChange={(e) => setReviewNote(e.target.value)}
              placeholder={t("Optional note (required for Reject)")}
              disabled={!c}
            />
            <div className="review-actions">
              <button
                className="approve"
                disabled={!c}
                onClick={() => void review("APPROVED")}
              >
                {t("✓ Mark inspected and approve")}
              </button>
              <button
                className="reject"
                disabled={!c}
                onClick={() => {
                  if (!reviewNote.trim()) {
                    setError(t("Reject requires a note"));
                    return;
                  }
                  void review("REJECTED");
                }}
              >
                {t("Reject")}
              </button>
              <button
                className="needs"
                disabled={!c}
                onClick={() => void review("NEEDS_REVIEW")}
              >
                {t("Needs Review")}
              </button>
              <Link
                className="mitre-review-action"
                to={`/catalog/mitre?review_sid=${rule.sid}${c?.id ? `&classification_id=${c.id}` : ""}`}
              >
                {t("Review MITRE mapping")}
              </Link>
            </div>
            {!c && (
              <p className="review-help">
                {t(
                  "This rule has no successful AI classification yet, so there is nothing to review.",
                )}
              </p>
            )}
            {reviewHistory.length > 0 && (
              <details>
                <summary>
                  {t("Rule Review History")} ({reviewHistory.length})
                </summary>
                <ul>
                  {reviewHistory
                    .slice()
                    .reverse()
                    .map((x, i) => (
                      <li key={i}>
                        <strong>{label(x.status)}</strong> —{" "}
                        {new Date(x.reviewed_at).toLocaleString()}{" "}
                        {x.note && `— ${x.note}`}
                      </li>
                    ))}
                </ul>
              </details>
            )}
            <div className="correction-editor">
              <button type="button" className="secondary" disabled={!c} onClick={() => correctionOpen ? setCorrectionOpen(false) : openCorrection()}>
                {correctionOpen ? t("Cancel") : t("Correct classification")}
              </button>
              {correctionOpen && c && <div className="correction-form">
                <p className="review-help">{t("Edit the displayed classification fields.")} {t("The original model output remains preserved; only the displayed decision is overridden.")}</p>
                <div className="correction-grid">
                  {["detected_behavior", "detected_entity", "entity_type", "category", "subcategory", "mitre_tactic", "mitre_technique", "mitre_technique_id", "cyber_kill_chain_phase"].map((field) => <label key={field}>{t(field.replaceAll("_", " "))}<input value={correctionValues[field] || ""} onChange={(e) => setCorrectionValues({ ...correctionValues, [field]: e.target.value })} /></label>)}
                </div>
                <textarea value={correctionReason} onChange={(e) => setCorrectionReason(e.target.value)} placeholder={t("Reason for edit (required)" )} />
                <div className="correction-actions"><button type="button" className="primary" disabled={correctionBusy} onClick={() => void saveCorrection()}>{correctionBusy ? "…" : t("Save correction")}</button><Link className="secondary" to={`/audit-log?sid=${rule.sid}`}>{t("Open audit log")}</Link></div>
              </div>}
            </div>
          </div>
        </article>
        <article className="panel">
          <div className="section-title">
            <span>07</span>
            <h2>{t("Product Planning")}</h2>
            <span className="ai-badge">{t("RULE-LEVEL DECISION")}</span>
          </div>
          <div className="manual-review">
            <p>
              {t("Product status:")}{" "}
              <strong>
                {product?.status ? label(product.status) : t("NOT_EVALUATED")}
              </strong>
            </p>
            <p className="review-help">
              {t(
                "This is separate from AI classification review: it records whether the rule belongs in the NDR product.",
              )}
            </p>
            <textarea
              value={productNote}
              onChange={(e) => setProductNote(e.target.value)}
              placeholder={t("Product planning note")}
            />
            <div className="review-actions">
              <button
                className="primary"
                onClick={() => void updateProduct("APPROVED_FOR_PRODUCT")}
              >
                {t("Approve for Product")}
              </button>
              <button
                className="reject"
                onClick={() => void updateProduct("REJECTED_FOR_PRODUCT")}
              >
                {t("Reject for Product")}
              </button>
              <button
                className="needs"
                onClick={() => void updateProduct("ALREADY_INTEGRATED")}
              >
                {t("Already Integrated")}
              </button>
            </div>
            {productHistory.length > 0 && (
              <details>
                <summary>
                  {t("Product history")} ({productHistory.length})
                </summary>
                <ul>
                  {productHistory.map((x, i) => (
                    <li key={i}>
                      <strong>
                        {x.from_status ? label(x.from_status) : "NEW"} →{" "}
                        {label(x.to_status)}
                      </strong>{" "}
                      — {new Date(x.created_at).toLocaleString()}{" "}
                      {x.note && `— ${x.note}`}
                    </li>
                  ))}
                </ul>
              </details>
            )}
          </div>
        </article>
        <article className="panel span-2 technical-details-panel">
          <details>
            <summary className="section-title">
              <span>08</span>
              <div>
                <h2>{t("Technical Details")}</h2>
                <p className="review-help">{t("Parser output and agent trace are available for diagnostics.")}</p>
              </div>
            </summary>
            <div className="technical-tabs" role="tablist" aria-label={t("Technical Details")}>
              <button type="button" className={technicalTab === "parser" ? "active" : ""} role="tab" aria-selected={technicalTab === "parser"} onClick={() => setTechnicalTab("parser")}>{t("Parser Output")}</button>
              <button type="button" className={technicalTab === "agent" ? "active" : ""} role="tab" aria-selected={technicalTab === "agent"} disabled={!c} onClick={() => setTechnicalTab("agent")}>{t("Agent Trace")}</button>
            </div>
            {technicalTab === "parser" ? <div className="technical-tab-panel" role="tabpanel">
              <div className="evidence"><p>{t("This is the deterministic parser output extracted from the original Suricata rule. The classifier receives this data plus enrichment context.")}</p></div>
              <pre className="json">{JSON.stringify(parsed, null, 2)}</pre>
            </div> : <div className="technical-tab-panel" role="tabpanel">
              {c ? <><div className="evidence"><p>{t("This is an operational trace of enrichment tools, evidence gates, abstention decisions, MITRE provenance and validator results. It is not the raw model response.")}</p></div><pre className="json">{JSON.stringify(c.agent_activity || {}, null, 2)}</pre></> : <div className="empty">{t("This rule has not been classified.")}</div>}
            </div>}
          </details>
        </article>
      </section>
    </>
  );
}
