import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { StatusBadge } from "../components/StatusBadge";
import { classifyRule, getNeighbors, getReviewHistory, getRule, saveReview } from "../services/api";
import type { Rule } from "../types";

function Value({ children }: { children: React.ReactNode }) { return <div className="value">{children || <span className="null-value">Not assigned</span>}</div>; }
function FieldValue({ classification, field, children }: { classification: NonNullable<Rule["classification"]>; field: string; children: React.ReactNode }) {
  const decision = classification.field_decisions?.[field];
  const text = decision?.status === "ABSTAINED" ? "Abstained" : decision?.status === "NOT_APPLICABLE" ? "Not applicable" : decision?.status === "UNAVAILABLE" ? "Unavailable" : children;
  return <Value>{text || <span className="null-value">Not assigned</span>} {decision?.status && decision.status !== "ASSIGNED" && <small>{decision.status.replaceAll("_", " ")}{decision.reason ? ` — ${decision.reason}` : ""}</small>}</Value>;
}

function systemSummary(rule: Rule): string {
  const c = rule.classification;
  if (!c) return "No successful classification is available for this rule.";
  const decisions = c.field_decisions || {};
  const assigned = Object.entries(decisions).filter(([, d]) => d.status === "ASSIGNED").map(([field]) => field.replaceAll("_", " "));
  const abstained = Object.entries(decisions).filter(([, d]) => d.status === "ABSTAINED").map(([field]) => field.replaceAll("_", " "));
  const parts = [c.detected_behavior ? `Detected behavior: ${c.detected_behavior}.` : `The rule was categorized as ${c.category || "unclassified"}${c.subcategory ? ` / ${c.subcategory}` : ""}.`];
  if (assigned.length) parts.push(`Assigned: ${assigned.join(", ")}.`);
  if (abstained.length) parts.push(`Abstained on: ${abstained.join(", ")}.`);
  parts.push(`Model self-confidence is ${Math.round((c.model_confidence ?? c.confidence) * 100)}% (uncalibrated); ${c.field_coverage ? `${c.field_coverage.assigned} of ${c.field_coverage.total} fields are assigned` : "field coverage is unavailable"}; validator status is ${c.validation?.status || "data unavailable"}.`);
  return parts.join(" ");
}

export function RuleDetail() {
  const { sid = "" } = useParams();
  const navigate = useNavigate();
  const [rule, setRule] = useState<Rule | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [executionProvider, setExecutionProvider] = useState("");
  const [neighbors, setNeighbors] = useState<{previous_sid:number|null;next_sid:number|null}>({previous_sid:null,next_sid:null});
  const [reviewHistory, setReviewHistory] = useState<Array<{status:string;note:string|null;reviewer_type:string;reviewed_at:string}>>([]);
  const [reviewNote, setReviewNote] = useState("");
  const [selectedClassificationId, setSelectedClassificationId] = useState<number | null>(null);
  const load = () => getRule(sid).then(x => { setRule(x); setSelectedClassificationId(current => current && x.classification_options?.some(c => c.id === current) ? current : x.classification?.id || null); }).catch(e => setError(e.message));
  useEffect(() => { void load(); void getNeighbors(sid).then(setNeighbors).catch(() => undefined); void getReviewHistory(sid).then(x=>setReviewHistory(x.items)).catch(() => undefined); }, [sid]);
  useEffect(() => { const onKey = (e: KeyboardEvent) => { if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement || e.target instanceof HTMLSelectElement) return; if (e.key.toLowerCase()==="j" && neighbors.next_sid) navigate(`/rules/${neighbors.next_sid}`); if (e.key.toLowerCase()==="k" && neighbors.previous_sid) navigate(`/rules/${neighbors.previous_sid}`); }; window.addEventListener("keydown", onKey); return () => window.removeEventListener("keydown", onKey); }, [neighbors, navigate]);
  const classify = async () => { if (!rule) return; setBusy(true); try { const result = await classifyRule(rule.sid, true, executionProvider); await load(); setSelectedClassificationId(result.id); } catch(e) { setError(e instanceof Error ? e.message : "Classification failed"); } finally { setBusy(false); } };
  if (error) return <div className="error page-error">{error} <Link to="/">Return</Link></div>;
  if (!rule) return <div className="loading">Loading rule…</div>;
  const c = rule.classification_options?.find(x => x.id === selectedClassificationId) || rule.classification;
  const displayRule = c && c !== rule.classification ? {...rule, classification: c} : rule;
  const parsed = {
    action: rule.action, protocol: rule.protocol, source: rule.source, source_port: rule.source_port,
    direction: rule.direction, destination: rule.destination, destination_port: rule.destination_port,
    classtype: rule.classtype, metadata: rule.metadata, references: rule.references, flow: rule.flow,
    flowbits: rule.flowbits, contents: rule.contents, pcre: rule.pcre, app_layer: rule.app_layer,
  };
  const copy = (text: string) => void navigator.clipboard?.writeText(text);
  const review = async (status:string) => { try { await saveReview(sid,status,reviewNote,c?.id); const [fresh,history] = await Promise.all([getRule(sid),getReviewHistory(sid)]); setRule(fresh); setReviewHistory(history.items); setReviewNote(""); } catch(e) { setError(e instanceof Error ? e.message : "Review save failed"); } };
  return <>
    <div className="detail-actions" style={{marginBottom:16}}>
      <label htmlFor="execution-provider">Run classification with</label>
      <select id="execution-provider" disabled={busy} value={executionProvider} onChange={e=>setExecutionProvider(e.target.value)}>
        <option value="">Configured default</option><option value="gemini">Gemini · API</option><option value="ollama">Qwen · Local Ollama</option>
      </select>
      <small>Gemini / Qwen choices use V2.1 · configured default follows server settings</small>
    </div>
    <header className="detail-header reveal"><div><Link className="back" to="/">← Rule Explorer</Link><div className="sid-line"><span className="detail-kicker">INSPECTION RECORD</span><h1>SID {rule.sid}</h1><StatusBadge status={c?.classification_status}/></div><p>{rule.msg || "No message"} · rev {rule.rev} · {rule.source_file || "unknown source"}</p></div><div className="detail-actions">{(rule.classification_options?.length || 0) > 1 && <select aria-label="Classification result" value={selectedClassificationId || ""} onChange={e => setSelectedClassificationId(Number(e.target.value))}>{rule.classification_options?.map(item=><option key={item.id} value={item.id}>{item.model_display_name || item.model_name} — {item.classifier_version}</option>)}</select>}<button onClick={() => neighbors.previous_sid && navigate(`/rules/${neighbors.previous_sid}`)} disabled={!neighbors.previous_sid}>← Prev</button><button onClick={() => neighbors.next_sid && navigate(`/rules/${neighbors.next_sid}`)} disabled={!neighbors.next_sid}>Next →</button><button className="primary" disabled={busy} onClick={classify}>{busy ? "Classifying…" : c ? "Reclassify" : "Classify rule"}</button></div></header>
    <section className="detail-grid">
      <article className="panel flow-panel"><div className="section-title"><span>01</span><h2>Original Suricata Rule</h2><button className="copy-button" onClick={() => copy(rule.raw_rule)}>Copy</button></div><div className="rule-meta"><span>SID {rule.sid}</span><span>REV {rule.rev}</span><span>{rule.source_file || "unknown source"}</span></div><pre className="raw-rule">{rule.raw_rule}</pre></article>
      <article className="panel ai-panel"><div className="section-title"><span>02</span><h2>AI Classification</h2><span className="ai-badge">● {c?.provider || "AI"} · {c?.inference_mode || "INFERENCE"}</span></div>{c ? <div className="classification-grid">
        <label>Model<Value>{c.model_display_name || c.model_name}<small>Provider: {c.provider || "UNKNOWN"} · Mode: {c.inference_mode || "UNKNOWN"} · Classifier: {c.classifier_version}</small></Value></label>
        <label>Behavior<FieldValue classification={c} field="detected_behavior">{c.detected_behavior}</FieldValue></label><label>Entity<FieldValue classification={c} field="detected_entity">{c.detected_entity}<small>{c.entity_type}</small></FieldValue></label>
        <label>Category<FieldValue classification={c} field="category">{c.category}<small>{c.subcategory}</small></FieldValue></label><label>MITRE tactic<FieldValue classification={c} field="mitre_tactic">{c.mitre_tactic}</FieldValue></label>
        <label>Final MITRE mapping<FieldValue classification={c} field="mitre_technique">{c.mitre_technique}<small>{c.mitre_technique_id}</small></FieldValue></label><label>Kill Chain<FieldValue classification={c} field="cyber_kill_chain_phase">{c.cyber_kill_chain_phase}</FieldValue></label>
        <label>Model Confidence (uncalibrated)<Value><span className="confidence large">{Math.round((c.model_confidence ?? c.confidence)*100)}%</span><span className="confidence-track"><i style={{width:`${Math.round((c.model_confidence ?? c.confidence)*100)}%`}}/></span><small>Self-reported overall model assessment; not a calibrated accuracy probability.</small><small>Band: {c.confidence_band || "UNKNOWN"} (raw score; coverage does not change it)</small><small>{c.confidence_band_definition || "Threshold definition unavailable"}</small></Value></label><label>Decision Coverage<Value>{c.field_coverage ? `${c.field_coverage.assigned} / ${c.field_coverage.total} fields assigned` : "Unavailable"}<small>Coverage is separate from model confidence.</small></Value></label>
        <label>MITRE Evidence Strength<Value>{c.evidence_strength || "UNKNOWN"}<small>Validator: {c.validation?.status || "Data unavailable"}</small></Value></label>
      </div> : <div className="empty">This rule has not been classified.</div>}</article>
      <div className="flow-connector" aria-hidden="true"><span>◈</span><i/></div><article className="panel"><div className="section-title"><span>03</span><h2>MITRE Provenance</h2><button className="copy-button" onClick={() => c && copy(JSON.stringify(c, null, 2))}>Copy JSON</button></div>{c ? <div className="evidence"><p><strong>{c.mitre_mapping_method?.replaceAll("_", " ") || "UNKNOWN"}</strong></p><p>{c.mapping_reason || "No mapping provenance recorded."}</p><p><strong>Source Metadata</strong><br/>{c.source_mitre_mapping ? `${c.source_mitre_mapping.technique_id}${c.source_mitre_mapping.technique_name ? ` — ${c.source_mitre_mapping.technique_name}` : ""}` : "No MITRE mapping in rule"}</p><p><strong>Final Mapping</strong><br/>{c.final_mitre_mapping ? `${c.final_mitre_mapping.technique_id} — ${c.final_mitre_mapping.technique_name}` : "No supported mapping"}</p><p><strong>MITRE Retrieval Score</strong><br/>{c.mitre_retrieval_score == null ? "Not available" : c.mitre_retrieval_score.toFixed(2)}<small>Retrieval relevance, not model confidence.</small></p></div> : <div className="empty">MITRE provenance appears after classification.</div>}</article>
      <article className="panel"><div className="section-title"><span>03</span><h2>System Decision</h2></div>{c ? <div className="evidence"><p><strong>{c.classification_status === "REVIEW_REQUIRED" ? "Review required" : c.classification_status === "FAILED" ? "Classification failed" : c.validation?.status === "PASS" ? "Classification accepted by validator" : "Classification decision recorded"}</strong></p><p>{systemSummary(displayRule)}</p>{c.explanation && <p><strong>Model explanation:</strong> {c.explanation}</p>}<h3>Decision Evidence</h3><ul>{c.evidence.map((item, i)=><li key={i}>{item}</li>)}</ul>{c.validation_issues.length > 0 && <div className="review-box"><strong>Validation issues</strong><ul>{c.validation_issues.map((x,i)=><li key={i}>{x}</li>)}</ul></div>}{c.consistency_warnings?.length ? <div className="review-box"><strong>Consistency warnings</strong><ul>{c.consistency_warnings.map((x,i)=><li key={i}>{x}</li>)}</ul></div> : null}</div> : <div className="empty">This rule has not been classified.</div>}</article>
      <article className="panel"><div className="section-title"><span>06</span><h2>Manual Review</h2></div><div className="manual-review"><p>Current status: <strong>{c?.manual_review?.status || "UNREVIEWED"}</strong></p><p className="review-help">Manual review is complete when you approve or reject this classification. <strong>Needs Review</strong> keeps it open for later verification.</p>{c?.manual_review?.note && <p>{c?.manual_review.note}</p>}<textarea value={reviewNote} onChange={e=>setReviewNote(e.target.value)} placeholder="Optional note (required for Reject)"/><div className="review-actions"><button className="approve" onClick={()=>void review("APPROVED")}>✓ Mark Reviewed / Approve</button><button className="reject" onClick={()=>{if(!reviewNote.trim()){setError("Reject requires a note");return;} void review("REJECTED")}}>Reject</button><button className="needs" onClick={()=>void review("NEEDS_REVIEW")}>Needs Review</button></div>{reviewHistory.length>0 && <details><summary>Rule Review History ({reviewHistory.length})</summary><ul>{reviewHistory.slice().reverse().map((x,i)=><li key={i}><strong>{x.status}</strong> — {new Date(x.reviewed_at).toLocaleString()} {x.note && `— ${x.note}`}</li>)}</ul></details>}</div></article>
      <article className="panel span-2"><div className="section-title"><span>04</span><h2>Parsed Input</h2></div><pre className="json">{JSON.stringify(parsed, null, 2)}</pre></article>
      {c && <article className="panel span-2"><details><summary className="section-title"><span>05</span><h2>Agent Activity (evidence only)</h2></summary><div className="evidence"><pre className="json">{JSON.stringify(c.agent_activity || {}, null, 2)}</pre></div></details></article>}
    </section>
  </>;
}
