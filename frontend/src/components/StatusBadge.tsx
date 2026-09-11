import type { Status } from "../types";
import { useI18n } from "../i18n";

export function StatusBadge({ status }: { status?: Status }) {
  const { t } = useI18n();
  if (!status) return <span className="badge neutral">{t("Unclassified")}</span>;
  const labels: Record<Status, string> = { AUTO_CLASSIFIED: t("Classified"), REVIEW_REQUIRED: t("Review"), FAILED: t("Failed") };
  return <span className={`badge ${status.toLowerCase()}`}>{labels[status]}</span>;
}
