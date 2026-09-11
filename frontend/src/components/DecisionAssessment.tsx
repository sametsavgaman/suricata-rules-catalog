import type { Classification } from "../types";
import "./DecisionAssessment.css";
import { useI18n } from "../i18n";

const fields = [
  ["detected_behavior", "Behavior"], ["detected_entity", "Entity"],
  ["entity_type", "Entity type"], ["category", "Category"], ["subcategory", "Subcategory"],
  ["mitre_tactic", "MITRE tactic"], ["mitre_technique", "MITRE technique"],
  ["mitre_technique_id", "MITRE ID"], ["cyber_kill_chain_phase", "Kill Chain"],
] as const;

export function checkLabel(status?: string, translate: (value: string) => string = (value) => value) {
  return translate(({PASS: "Passed", REVIEW: "Review flagged", FAIL: "Failed", NOT_RUN: "Not run"} as Record<string, string>)[status || ""] || "Unavailable");
}

export function rawModelSignal(c: Classification) {
  const score = c.model_confidence ?? c.confidence;
  if (c.classification_status === "FAILED" || typeof score !== "number" || !Number.isFinite(score) || score < 0 || score > 1) return "Unavailable";
  return String(score);
}

export function DecisionAssessment({classification: c, compact = false, localized}: {classification: Classification | null; compact?: boolean; localized?: Record<string, string>}) {
  const { t, label } = useI18n();
  if (!c) return <span className="dim">{t("Not classified")}</span>;
  const failed = c.classification_status === "FAILED";
  const validation = c.validation;
  const semantic = validation?.semantic_verifier?.status;
  const assigned = fields.filter(([key]) => c.field_decisions?.[key]?.status === "ASSIGNED").length;
  const known = fields.filter(([key]) => ["ASSIGNED", "ABSTAINED", "NOT_APPLICABLE"].includes(c.field_decisions?.[key]?.status || "")).length;
  if (compact) return <div className="decision-compact">
    <span>{t("Validator")}: {checkLabel(validation?.status, t)}</span>
    {semantic && semantic !== "NOT_RUN" && <small>{t("Semantic check")}: {checkLabel(semantic, t)}</small>}
    <small>{failed ? t("Classification failed") : known ? `${assigned} ${t("fields assigned")}` : t("Field decisions unavailable")}</small>
  </div>;
  return <section className="decision-assessment" aria-label={t("Decision assessment")}>
    <h3>{t("Decision assessment")}</h3>
    <p>{t("Recorded checks and field decisions explain this result. Passing checks does not establish accuracy or product suitability.")}</p>
    <dl className="decision-checks">
      <div><dt>{t("Validator")}</dt><dd>{checkLabel(validation?.status, t)}</dd></div>
      <div><dt>{t("Semantic check")}</dt><dd>{checkLabel(semantic, t)}</dd></div>
      <div><dt>{t("Human review")}</dt><dd>{c.manual_review?.status ? label(c.manual_review.status) : t("UNREVIEWED")}</dd></div>
    </dl>
    {validation?.reason && <p>{localized?.[validation.reason] || validation.reason}</p>}
    {c.validator_mitre_status === "REVIEW_OVERRIDE" && <p className="review-box">{t("MITRE source mapping was overridden. Inspect the source and final mapping.")}</p>}
    <h4>{t("Field decisions")}</h4>
    <p>{failed ? t("Classification failed; no field assignment is confirmed here.") : known ? `${assigned} ${t("of")} ${fields.length} ${t("fields assigned")}. ${t("Field completion is not a quality score; abstention can be appropriate.")}` : t("Historical field decision metadata is unavailable.")}</p>
    <ul className="decision-fields">{fields.map(([key, label]) => {
      const decision = failed ? undefined : c.field_decisions?.[key];
      const status = decision?.status;
      const text = t(({ASSIGNED: "Assigned", ABSTAINED: "Abstained", NOT_APPLICABLE: "Not applicable", UNAVAILABLE: "Unavailable"} as Record<string, string>)[status || ""] || "Unavailable");
      return <li key={key}><span>{t(label)}</span><strong>{text}</strong>{decision?.reason && <small>{localized?.[decision.reason] || decision.reason}</small>}</li>;
    })}</ul>
    <details className="model-signal-details">
      <summary>{t("Technical details · model self-assessment")}</summary>
      <p><strong>{t("Raw model signal")}: {t(rawModelSignal(c))}</strong></p>
      <p>{t("The model generated this 0–1 value in its structured response. It has not been calibrated against independently reviewed labels and is not a correctness probability. Scores from Gemini and Qwen are not a shared accuracy scale.")}</p>
      <p>{t("This signal belongs to the model response; subsequent evidence gates may change individual fields without recalculating it.")}</p>
    </details>
  </section>;
}
