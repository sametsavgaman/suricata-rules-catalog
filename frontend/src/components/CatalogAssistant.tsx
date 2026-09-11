import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import "./CatalogAssistant.css";
import { useI18n } from "../i18n";

type Filters = Record<string, string | null>;
export type CatalogAnswer = {
  status: "RESULTS" | "CLARIFY" | "OUT_OF_SCOPE" | "EXPLANATION";
  answer: string; filters: Filters; total: number | null; offset: number; limit: number;
  planner_model: string | null; planner_provider: "gemini" | "claude" | "openai" | null; source: string; resource: "RULES" | "FAMILIES";
  items: Array<{sid: number; rev: number; classification_id: number | null; message: string | null;
    category: string | null; subcategory: string | null; entity: string | null; mitre_id: string | null;
    mitre_tactic: string | null; provider: string | null; model: string | null; product_status: string}>;
  families: Array<{id:number;slug:string;name:string;family_type:string;rule_count:number;mitre_count:number;
    protocols:string[];categories:string[];mitre_ids:string[];entity_types:string[];product_status:Record<string,number>}>;
};
const examples = ["List the AnyDesk rules", "How many AnyDesk rules are there?", "Show detection families related to T1219", "Show families related to DNS tunneling"];
const examplesTr = ["AnyDesk kurallarını listele", "Kaç tane AnyDesk kuralı var?", "T1219 ile ilişkili detection ailelerini göster", "DNS tünellemesiyle ilişkili aileleri göster"];
const labels: Record<string, string> = {family_name:"Detection family",category:"Category", subcategory:"Subcategory", detected_entity:"Entity", mitre_tactic:"Tactic", mitre_technique_id:"MITRE", protocol:"Protocol", provider:"Model provider", product_status:"Product status", entity_status:"Entity status", mitre_status:"MITRE status", search:"Keyword"};

async function callAssistant(path: string, body: unknown, signal: AbortSignal): Promise<CatalogAnswer> {
  const response = await fetch(`${import.meta.env.VITE_API_URL || "/api"}/catalog/assistant/${path}`, {
    method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(body), signal,
  });
  const value = await response.json().catch(() => null);
  if (!response.ok) throw new Error(typeof value?.detail === "string" ? value.detail : "The assistant could not respond. Please try again.");
  return value;
}

export function AssistantResults({result}: {result: CatalogAnswer}) {
  const { t, label } = useI18n();
  const filters = Object.entries(result.filters).filter(([, value]) => value !== null);
  return <div className="ca-response">
    <div className="ca-response-heading"><span className="ca-eyebrow">{result.source === "PLATFORM_GUIDE" ? t("PLATFORM GUIDE") : t("CATALOG RESPONSE")}</span>{result.total !== null && <span className="ca-count">{result.total.toLocaleString("tr-TR")} {t("records")}</span>}</div>
    <p className="ca-answer">{result.answer}</p>
    {result.status === "RESULTS" && <><div className="ca-filter-list" aria-label={t("Applied filters")}>{filters.length ? filters.map(([key, value]) => <span key={key}>{t(labels[key] || key)}: <b>{value}</b></span>) : <span>{t("All catalog records")}</span>}</div><p className="ca-caption">{t("Filters are combined with AND semantics. Counts are not suitability or accuracy scores.")}</p></>}
    {result.items.length > 0 && <div className="ca-table-wrap"><table className="ca-table"><caption className="ca-sr-only">{t("Catalog search results")}</caption><thead><tr><th scope="col">{t("Rule / source")}</th><th scope="col">{t("Classification")}</th><th scope="col">{t("MITRE / Entity")}</th><th scope="col">{t("Product status")}</th><th scope="col">{t("Action")}</th></tr></thead><tbody>{result.items.map(item => <tr key={`${item.sid}:${item.rev}:${item.classification_id ?? "none"}`}>
      <td><Link to={`/rules/${item.sid}${item.classification_id ? `?classification_id=${item.classification_id}` : ""}`}>SID {item.sid} <span aria-hidden="true">↗</span></Link><small>REV {item.rev} · {item.classification_id ? `${item.provider || t("Source unavailable")} · ${item.model || t("Model unavailable")}` : t("Not classified yet")}</small><p>{item.message || t("No message available")}</p></td>
      <td>{item.category ? label(item.category) : t("Unassigned")}<small>{item.subcategory ? label(item.subcategory) : "—"}</small></td>
      <td><span className="ca-technique">{item.mitre_id || t("MITRE unassigned")}</span><small>{item.mitre_tactic || "—"}</small><small>{item.entity || t("Entity unassigned")}</small></td>
      <td><span className="ca-product">{label(item.product_status.replaceAll("_", " "))}</span></td>
      <td className="ca-rule-action"><Link className="ca-open-rule" to={`/rules/${item.sid}${item.classification_id ? `?classification_id=${item.classification_id}` : ""}`}>{t("Open rule")} <span aria-hidden="true">↗</span></Link></td>
    </tr>)}</tbody></table></div>}
    {result.families?.length > 0 && <div className="ca-family-results">{result.families.map(family=><Link to={`/catalog/families/${family.slug}`} key={family.id}><div><span>{family.family_type}</span><h3>{family.name}</h3><p>{family.categories.slice(0,2).join(" · ")||"Classification pending"}</p></div><div><b>{family.rule_count}</b><small>rules</small><em>{family.protocols.slice(0,3).join(" · ")||"—"}</em></div></Link>)}</div>}
    {result.status === "RESULTS" && result.total === 0 && <div className="ca-empty">{t("No records match these conditions. Try a broader category or fewer filters.")}</div>}
    {result.planner_model && <p className="ca-caption">{t("Interpreted by")}: {result.planner_provider?.toUpperCase()} · {result.planner_model} · {t("Result source")}: {t("local catalog")}</p>}
  </div>;
}

export function CatalogAssistant() {
  const { locale, t } = useI18n();
  const visibleExamples = locale === "tr" ? examplesTr : examples;
  const [url] = useSearchParams();
  const [question, setQuestion] = useState(() => url.get("ask_family") ? `List the rules in the ${url.get("ask_family")} family` : "");
  const [result, setResult] = useState<CatalogAnswer | null>(null);
  const [submitted, setSubmitted] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const controller = useRef<AbortController | null>(null);
  const input = useRef<HTMLTextAreaElement>(null);
  useEffect(() => () => controller.current?.abort(), []);

  const ask = async () => {
    if (busy || question.trim().length < 3) return;
    const current = new AbortController(); controller.current = current;
    setBusy(true); setError(""); setResult(null); setSubmitted(question.trim());
    try { const response = await callAssistant("ask", {question:question.trim()}, current.signal); if (!current.signal.aborted) setResult(response); }
    catch (e) { if (!current.signal.aborted) setError(e instanceof Error ? e.message : "Connection error"); }
    finally { if (!current.signal.aborted) setBusy(false); }
  };
  const page = async (offset: number) => {
    if (!result || busy) return;
    const current = new AbortController(); controller.current = current;
    setBusy(true); setError("");
    try { const response = await callAssistant("search", {filters:result.filters, resource:result.resource, offset, limit:result.limit}, current.signal); if (!current.signal.aborted) setResult({...response, planner_model:result.planner_model, planner_provider:result.planner_provider}); }
    catch (e) { if (!current.signal.aborted) setError(e instanceof Error ? e.message : "Connection error"); }
    finally { if (!current.signal.aborted) setBusy(false); }
  };
  const clear = () => {controller.current?.abort(); setBusy(false); setResult(null); setError(""); setQuestion(""); setSubmitted(""); input.current?.focus();};

  return <section id="catalog-assistant" className="catalog-assistant" aria-labelledby="catalog-assistant-title">
    <div className="ca-intro"><div className="ca-mark" aria-hidden="true"><svg viewBox="0 0 60 60" fill="none"><path d="M30 51V29M30 36C10 36 10 16 10 16s20 0 20 20Zm0-7C50 29 50 9 50 9S30 9 30 29Z" stroke="currentColor" strokeWidth="1.5"/><circle cx="30" cy="51" r="3" fill="currentColor"/><path d="M14 20 26 32M46 13 34 25" stroke="currentColor" opacity=".5"/></svg></div><div><div className="ca-eyebrow">{t("Catalog Intelligence")}</div><h2 id="catalog-assistant-title">{t("Let’s find the right rule together.")}</h2><p>{t("Ask about a category, behavior, or MITRE technique to retrieve relevant catalog records and their sources.")}</p></div><span className="ca-mode"><i/> {t("Helper-model search")}</span></div>
    <form className="ca-form" onSubmit={e => {e.preventDefault(); void ask();}}>
      <label htmlFor="catalog-question">{t("Ask the catalog")}</label>
      <textarea id="catalog-question" aria-describedby="ca-privacy" ref={input} value={question} maxLength={1000} minLength={3} required rows={2} placeholder={t("Example: List rules in the C2 category that use DNS…")} onChange={e => setQuestion(e.target.value)} onKeyDown={e => {if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {e.preventDefault(); void ask();}}}/>
      <div className="ca-form-footer"><span id="ca-privacy">{t("Only your question is sent to the selected helper model. Each question is independent.")}</span><span className="ca-char-count">{question.length}/1000</span><button type="submit" disabled={busy || question.trim().length < 3}>{busy ? t("Processing…") : t("Search catalog")}<span aria-hidden="true">↗</span></button></div>
    </form>
    <div className="ca-suggestions" aria-label={locale === "tr" ? "Örnek sorular" : "Example questions"}>{visibleExamples.map(example => <button type="button" disabled={busy} key={example} onClick={() => {setQuestion(example); input.current?.focus();}}>{example}<span aria-hidden="true">↗</span></button>)}</div>
    {(submitted || result) && <div className="ca-session"><span>{t("Last question")}: {submitted}</span><button type="button" onClick={clear}>{t("Clear")}</button></div>}
    {error && <div className="ca-error" role="alert">{error} <Link to="/models">{t("Model Lab")}</Link></div>}
    <div aria-live="polite" aria-busy={busy}>{busy && <div className="ca-loading" role="status"><span/> {result ? t("Loading records…") : t("Interpreting your question and searching the catalog…")}</div>}{result && <AssistantResults result={result}/>}</div>
    {result?.status === "RESULTS" && (result.total || 0) > 0 && <div className="ca-pagination"><button type="button" disabled={busy || result.offset === 0} onClick={() => void page(Math.max(0, result.offset - result.limit))}>{t("← Previous")}</button><span>{result.offset + 1}–{Math.min(result.offset + (result.resource === "FAMILIES" ? result.families.length : result.items.length), result.total || 0)} / {result.total?.toLocaleString("tr-TR")}</span><button type="button" disabled={busy || result.offset + result.limit >= (result.total || 0)} onClick={() => void page(result.offset + result.limit)}>{t("Next →")}</button></div>}
    <details className="ca-how"><summary>{t("How does this assistant work?")}</summary><p>{t("The selected helper model converts your question into a constrained filter plan. The backend validates that plan and searches the catalog. Records, approvals, and model results are never changed. Review the signature and its behavior in your own network before making product decisions. Changing pages does not trigger another model call.")}</p></details>
  </section>;
}
