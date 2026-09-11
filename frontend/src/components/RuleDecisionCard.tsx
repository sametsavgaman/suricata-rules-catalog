import { Link } from "react-router-dom";
import type { Rule } from "../types";
import { AddToRulePack } from "./AddToRulePack";
import { useI18n } from "../i18n";

type ProductState = { status: string; note: string | null } | null;

export function RuleDecisionCard({
  rule,
  product,
}: {
  rule: Rule;
  product: ProductState;
}) {
  const { t, label } = useI18n();
  const c = rule.classification;
  const human = c?.manual_review?.status || "UNREVIEWED";
  const validator = c?.validation?.status || "UNAVAILABLE";
  const ready = Boolean(
    c &&
    c.classification_status === "AUTO_CLASSIFIED" &&
    validator === "PASS" &&
    human === "APPROVED",
  );
  const recommendation = !c
    ? t("Classify before product review")
    : c.classification_status === "FAILED"
      ? t("Classification failed")
      : c.classification_status === "REVIEW_REQUIRED" || validator !== "PASS"
        ? t("Evidence review required")
        : human !== "APPROVED"
          ? t("Candidate for human review")
          : product?.status === "APPROVED_FOR_PRODUCT" ||
              product?.status === "ALREADY_INTEGRATED"
            ? t("Approved catalogue selection")
            : t("Ready for product evaluation");
  const next = !c
    ? t("Run classification and inspect parsed evidence.")
    : validator !== "PASS"
      ? t("Resolve validator warnings before selection.")
      : human !== "APPROVED"
        ? t("Complete Manual Review before deployment consideration.")
        : t("Compare alternatives and add this rule to a reviewed pack.");
  return (
    <section
      className={`rule-decision-card ${ready ? "decision-ready" : ""}`}
      aria-label={t("Rule decision card")}
    >
      <div className="decision-card-head">
        <div>
          <span>{t("RULE DECISION CARD")}</span>
          <h2>{recommendation}</h2>
        </div>
        <b>{ready ? t("REVIEWED") : t("EVALUATE")}</b>
      </div>
      <div className="decision-card-grid">
        <Fact
          label={t("Detection")}
          value={c?.detected_behavior || t("Not classified")}
        />
        <Fact
          label={t("MITRE evidence")}
          value={
            c?.mitre_technique_id
              ? `${c.evidence_strength || "UNKNOWN"} · ${c.mitre_technique_id}`
              : t("No supported mapping")
          }
        />
        <Fact label={t("Validator")} value={label(validator)} />
        <Fact label={t("Human review")} value={label(human)} />
        <Fact
          label={t("Product status")}
          value={label(product?.status || "NOT_EVALUATED")}
        />
        <Fact
          label={t("Detection family")}
          value={
            rule.families?.map((x) => x.name).join(", ") || t("Unassigned")
          }
        />
      </div>
      <div className="decision-next">
        <span>{t("NEXT ACTION")}</span>
        <p>{next}</p>
        <small>
          {t(
            "Readiness uses recorded evidence and review state. Performance and false-positive behavior have not been measured.",
          )}
        </small>
      </div>
      <div className="decision-card-actions">
        <Link to={`/catalog/compare?sids=${rule.sid},`}>
          {t("Compare this rule")}
        </Link>
        <AddToRulePack sid={rule.sid} />
        <Link className="primary" to="/catalog/rule-packs">
          {t("Open pack builder")}
        </Link>
      </div>
    </section>
  );
}
function Fact({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}
