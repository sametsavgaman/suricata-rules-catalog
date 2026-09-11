import { useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useI18n } from "../i18n";
import {
  COMPARE_SELECTION_EVENT,
  clearCompareSelection,
  loadCompareSelection,
  removeCompareSid,
  setCompareSelection,
} from "../services/compareSelection";

export function CompareTray() {
  const { t } = useI18n();
  const navigate = useNavigate();
  const location = useLocation();
  const [sids, setSids] = useState<number[]>(() => loadCompareSelection());

  useEffect(() => {
    const refresh = () => setSids(loadCompareSelection());
    window.addEventListener(COMPARE_SELECTION_EVENT, refresh);
    return () => window.removeEventListener(COMPARE_SELECTION_EVENT, refresh);
  }, []);

  // Keep legacy compare links inside the same persistent basket flow.
  useEffect(() => {
    const captureCompareLink = (event: MouseEvent) => {
      if (!(event.target instanceof Element)) return;
      const link = event.target.closest<HTMLAnchorElement>('a[href*="/catalog/compare?sids="]');
      if (!link) return;
      const url = new URL(link.href, window.location.origin);
      const values = (url.searchParams.get("sids") || "")
        .split(",")
        .map((value) => Number(value))
        .filter((value) => Number.isSafeInteger(value) && value > 0);
      if (!values.length) return;
      event.preventDefault();
      event.stopPropagation();
      setCompareSelection(values);
      navigate(`/catalog/compare?sids=${values.join(",")}${values.length >= 2 ? "&auto=1" : ""}`);
    };
    document.addEventListener("click", captureCompareLink, true);
    return () => document.removeEventListener("click", captureCompareLink, true);
  }, [navigate]);

  if (location.pathname === "/" || !sids.length) return null;

  const compareNow = () => {
    navigate(`/catalog/compare?sids=${sids.join(",")}${sids.length >= 2 ? "&auto=1" : ""}`);
  };

  return (
    <div className="compare-tray" aria-label={t("Comparison tray")}>
      <div className="compare-tray-summary">
        <span className="section-kicker">{t("COMPARISON TRAY")}</span>
        <div className="compare-tray-summary-head">
          <strong>{t("Selected rules")}</strong>
          <button type="button" className="compare-tray-clear" onClick={() => clearCompareSelection()}>
            {t("Clear all")}
          </button>
        </div>
        <div className="compare-tray-list">
          {sids.map((sid) => (
            <button
              type="button"
              className="compare-tray-chip"
              key={sid}
              onClick={() => removeCompareSid(sid)}
              title={t("Remove from comparison")}
            >
              SID {sid} ×
            </button>
          ))}
        </div>
      </div>
      <button
        type="button"
        className="compare-tray-trigger"
        onClick={compareNow}
        aria-label={`${t("Compare now")} (${sids.length})`}
        title={t("Compare now")}
      >
        <span aria-hidden="true">🛒</span>
        <b>{sids.length}</b>
      </button>
    </div>
  );
}
