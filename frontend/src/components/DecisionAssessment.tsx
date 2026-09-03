import type { Classification } from "../types";
import "./DecisionAssessment.css";

const fields = [
  ["detected_behavior", "Behavior"], ["detected_entity", "Entity"],
  ["entity_type", "Entity type"], ["category", "Category"], ["subcategory", "Subcategory"],
  ["mitre_tactic", "MITRE tactic"], ["mitre_technique", "MITRE technique"],
  ["mitre_technique_id", "MITRE ID"], ["cyber_kill_chain_phase", "Kill Chain"],
] as const;

export function checkLabel(status?: string) {
  return ({PASS: "Passed", REVIEW: "Review flagged", FAIL: "Failed", NOT_RUN: "Not run"} as Record<string, string>)[status || ""] || "Unavailable";
}

export function rawModelSignal(c: Classification) {
  const score = c.model_confidence ?? c.confidence;
  if (c.classification_status === "FAILED" || typeof score !== "number" || !Number.isFinite(score) || score < 0 || score > 1) return "Unavailable";
  return String(score);
}

export function DecisionAssessment({classification: c, compact = false}: {classification: Classification | null; compact?: boolean}) {
  if (!c) return <span className="dim">Not classified</span>;
  const failed = c.classification_status === "FAILED";
  const validation = c.validation;
  const semantic = validation?.semantic_verifier?.status;
  const assigned = fields.filter(([key]) => c.field_decisions?.[key]?.status === "ASSIGNED").length;
  const known = fields.filter(([key]) => ["ASSIGNED", "ABSTAINED", "NOT_APPLICABLE"].includes(c.field_decisions?.[key]?.status || "")).length;
  if (compact) return <div className="decision-compact">
    <span>Validator: {checkLabel(validation?.status)}</span>
    {semantic && semantic !== "NOT_RUN" && <small>Semantic check: {checkLabel(semantic)}</small>}
    <small>{failed ? "Classification failed" : known ? `${assigned} fields assigned` : "Field decisions unavailable"}</small>
  </div>;
  return <section className="decision-assessment" aria-label="Decision assessment">
    <h3>Decision assessment</h3>
    <p>Recorded checks and field decisions explain this result. Passing checks does not establish accuracy or product suitability.</p>
    <dl className="decision-checks">
      <div><dt>Validator</dt><dd>{checkLabel(validation?.status)}</dd></div>
      <div><dt>Semantic check</dt><dd>{checkLabel(semantic)}</dd></div>
      <div><dt>Human review</dt><dd>{c.manual_review?.status?.replaceAll("_", " ") || "UNREVIEWED"}</dd></div>
    </dl>
    {validation?.reason && <p>{validation.reason}</p>}
    {c.validator_mitre_status === "REVIEW_OVERRIDE" && <p className="review-box">MITRE source mapping was overridden. Inspect the source and final mapping.</p>}
    <h4>Field decisions</h4>
    <p>{failed ? "Classification failed; no field assignment is confirmed here." : known ? `${assigned} of ${fields.length} fields assigned. Field completion is not a quality score; abstention can be appropriate.` : "Historical field decision metadata is unavailable."}</p>
    <ul className="decision-fields">{fields.map(([key, label]) => {
      const decision = failed ? undefined : c.field_decisions?.[key];
      const status = decision?.status;
      const text = ({ASSIGNED: "Assigned", ABSTAINED: "Abstained", NOT_APPLICABLE: "Not applicable", UNAVAILABLE: "Unavailable"} as Record<string, string>)[status || ""] || "Unavailable";
      return <li key={key}><span>{label}</span><strong>{text}</strong>{decision?.reason && <small>{decision.reason}</small>}</li>;
    })}</ul>
    <details className="model-signal-details">
      <summary>Technical details · model self-assessment</summary>
      <p><strong>Raw model signal: {rawModelSignal(c)}</strong></p>
      <p>The model generated this 0–1 value in its structured response. It has not been calibrated against independently reviewed labels and is not a correctness probability. Scores from Gemini and Qwen are not a shared accuracy scale.</p>
      <p>This signal belongs to the model response; subsequent evidence gates may change individual fields without recalculating it.</p>
    </details>
  </section>;
}
