import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { getRules } from "../services/api";
import type { Rule } from "../types";
import { useI18n } from "../i18n";

type Props = {
  value: string;
  selectedRule: Rule | null;
  onChange: (value: string) => void;
  onSelect: (rule: Rule) => void;
};

const PAGE_SIZE = 5;

export function ModelRulePicker({ value, selectedRule, onChange, onSelect }: Props) {
  const { t, label } = useI18n();
  const [items, setItems] = useState<Rule[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const requestId = useRef(0);

  const search = async (pageNumber = 0, term = value.trim()) => {
    if (!term) {
      requestId.current += 1;
      setItems([]);
      setTotal(0);
      setPage(0);
      setLoading(false);
      setError("");
      return;
    }
    const request = ++requestId.current;
    setLoading(true);
    setError("");
    try {
      const params = new URLSearchParams({
        search: term,
        sort: "recent",
        offset: String(pageNumber * PAGE_SIZE),
        limit: String(PAGE_SIZE),
      });
      const response = await getRules(params);
      if (request !== requestId.current) return;
      setItems(response.items);
      setTotal(response.total);
      setPage(pageNumber);
    } catch (cause) {
      if (request === requestId.current) setError(cause instanceof Error ? cause.message : t("Rule search failed"));
    } finally {
      if (request === requestId.current) setLoading(false);
    }
  };

  useEffect(() => {
    const timer = window.setTimeout(() => void search(0), 280);
    return () => window.clearTimeout(timer);
  }, [value]);

  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div className="model-rule-picker">
      <div className="model-form rule-picker">
        <label>
          {t("Search SID or category")}
          <input
            value={value}
            onChange={(event) => onChange(event.target.value)}
            onKeyDown={(event) => { if (event.key === "Enter") void search(0); }}
            placeholder={t("2060513, AnyDesk or Malware…")}
          />
        </label>
        <button type="button" onClick={() => void search(0)} disabled={loading || !value.trim()}>{t("Find Rule")}</button>
      </div>
      {value.trim() && <section className="model-rule-suggestions" aria-live="polite">
        <div className="model-rule-suggestions-heading">
          <strong>{t("Suggested rules")}</strong>
          <span>{loading ? t("Searching…") : `${total.toLocaleString()} ${t("matches")}`}</span>
        </div>
        {error && <div className="error">{error}</div>}
        {!loading && !error && !items.length && <div className="empty">{t("No rules match this search.")}</div>}
        <div className="model-rule-suggestions-list">
          {items.map((item) => (
            <button
              className={`model-rule-suggestion ${selectedRule?.sid === item.sid ? "selected" : ""}`}
              type="button"
              key={`${item.sid}-${item.rev}`}
              onClick={() => onSelect(item)}
            >
              <span className="model-rule-suggestion-id">SID {item.sid} · REV {item.rev}</span>
              <strong>{item.msg || t("No message")}</strong>
              <small>{item.classification?.category ? label(item.classification.category) : t("Unclassified")} · {item.classification?.mitre_technique_id || t("MITRE unmapped")}</small>
              {selectedRule?.sid === item.sid && <em>✓ {t("Selected")}</em>}
            </button>
          ))}
        </div>
        {total > PAGE_SIZE && <div className="model-rule-suggestions-pagination">
          <button type="button" disabled={page <= 0 || loading} onClick={() => void search(page - 1)}>{t("← Previous")}</button>
          <span>{page + 1} / {pages}</span>
          <button type="button" disabled={page + 1 >= pages || loading} onClick={() => void search(page + 1)}>{t("Next →")}</button>
        </div>}
      </section>}
      {selectedRule && <p className="model-rule-selected-note">{t("Selected rule")}: SID {selectedRule.sid} · {selectedRule.msg || t("No message")}</p>}
    </div>
  );
}
