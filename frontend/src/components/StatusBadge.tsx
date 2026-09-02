import type { Status } from "../types";

export function StatusBadge({ status }: { status?: Status }) {
  if (!status) return <span className="badge neutral">Unclassified</span>;
  const labels: Record<Status, string> = { AUTO_CLASSIFIED: "Classified", REVIEW_REQUIRED: "Review", FAILED: "Failed" };
  return <span className={`badge ${status.toLowerCase()}`}>{labels[status]}</span>;
}

