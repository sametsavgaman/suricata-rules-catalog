import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { getCatalogCandidates, type ProductStatus } from "../services/api";
import type { Rule } from "../types";

const STATUSES: ProductStatus[] = ["NOT_EVALUATED", "CANDIDATE", "SHORTLISTED", "APPROVED_FOR_PRODUCT", "ALREADY_INTEGRATED", "REJECTED_FOR_PRODUCT"];

export function Candidates() {
  const [params] = useSearchParams();
  const [status, setStatus] = useState<ProductStatus>((params.get("status") as ProductStatus) || "NOT_EVALUATED");
  const [rules, setRules] = useState<Rule[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  useEffect(() => { setLoading(true); void getCatalogCandidates(status).then(x => { setRules(x.items); setTotal(x.total); }).finally(() => setLoading(false)); }, [status]);
  return <><header className="catalog-hero"><div className="section-kicker">PRODUCT PLANNING</div><h1>Candidate Workspace</h1><p>Product decisions are independent from classification review. Newly classified rules appear under NOT EVALUATED until you choose a product status.</p></header><div className="status-tabs">{STATUSES.map(x => <button className={status === x ? "active" : ""} onClick={() => setStatus(x)} key={x}>{x.replaceAll("_", " ")}</button>)}</div><section className="panel"><div className="panel-heading"><div><h2>{status.replaceAll("_", " ")}</h2><p className="result-count"><strong>{total}</strong> rule bulundu</p></div><Link className="export-button" to="/catalog/rules">Browse catalog</Link></div>{loading ? <div className="loading">Loading product queue…</div> : <div className="candidate-list">{rules.map(rule => <Link to={`/rules/${rule.sid}`} className="candidate-row" key={rule.id}><span className="mono">{rule.sid}<small>rev {rule.rev}</small></span><span><strong>{rule.msg || "No message"}</strong><small>{rule.source_file || "unknown source"} · {rule.protocol}</small></span><span>{rule.classification?.category || "Unclassified"}<small>{rule.classification?.subcategory || "—"}</small></span><span>{rule.classification?.detected_entity || "No entity"}</span></Link>)}{!rules.length && <div className="empty">No rules in this product queue yet.</div>}</div>}</section></>;
}
