import { useEffect, useState, type MouseEvent } from "react";
import { useI18n } from "../i18n";
import { COMPARE_SELECTION_EVENT, loadCompareSelection, toggleCompareSid } from "../services/compareSelection";

export function CompareSelectButton({ sid, compact = false }: { sid: number; compact?: boolean }) {
  const { t } = useI18n();
  const [selected, setSelected] = useState(false);
  const [message, setMessage] = useState("");

  useEffect(() => {
    const sync = () => setSelected(loadCompareSelection().includes(sid));
    sync();
    window.addEventListener(COMPARE_SELECTION_EVENT, sync);
    return () => window.removeEventListener(COMPARE_SELECTION_EVENT, sync);
  }, [sid]);

  const select = (event: MouseEvent<HTMLButtonElement>) => {
    event.preventDefault();
    event.stopPropagation();
    const result = toggleCompareSid(sid);
    setSelected(result.sids.includes(sid));
    setMessage(result.full ? t("Up to four rules can be compared.") : result.removed ? t("Removed from comparison") : t("Added to comparison"));
    window.setTimeout(() => setMessage(""), 1800);
  };

  return (
    <span className={`compare-select ${compact ? "compact" : ""}`}>
      <button type="button" className={`compare-select-button ${selected ? "selected" : ""}`} onClick={select}>
        {selected ? `✓ ${t("Selected")}` : t("Compare")}
      </button>
      {message && <small role="status">{message}</small>}
    </span>
  );
}
