import type { Classification, Rule, Stats } from "../types";

const API = import.meta.env.VITE_API_URL || "/api";

const GET_CACHE_TTL = 30_000;
const getCache = new Map<string, { expiresAt: number; value: unknown }>();
const inFlight = new Map<string, Promise<unknown>>();

export function clearApiCache() { getCache.clear(); }

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const method = (init?.method || "GET").toUpperCase();
  const key = `${method}:${path}`;
  if (method === "GET") {
    const cached = getCache.get(key);
    if (cached && cached.expiresAt > Date.now()) return cached.value as T;
    const pending = inFlight.get(key);
    if (pending) return pending as Promise<T>;
  }
  const operation = (async () => {
    const response = await fetch(`${API}${path}`, init);
    if (!response.ok) throw new Error((await response.json().catch(() => null))?.detail || response.statusText);
    const value = await response.json() as T;
    if (method === "GET") getCache.set(key, { expiresAt: Date.now() + GET_CACHE_TTL, value });
    else clearApiCache();
    return value;
  })();
  if (method !== "GET") return operation;
  inFlight.set(key, operation);
  try { return await operation; }
  finally { inFlight.delete(key); }
}

export function getStats() { return request<Stats>("/stats"); }
export function getCatalogStats() { return request<{total_rules:number;classified_rules:number;mitre_mapped:number;classification_records:number;product_status:Record<string,number>}>("/catalog/stats"); }
export function getCatalogFacets() { return request<{categories:Array<{value:string;count:number}>;subcategories:Array<{value:string;count:number}>;entities:Array<{value:string;count:number}>;mitre_tactics:Array<{value:string;count:number}>;mitre_techniques:Array<{value:string;count:number}>;protocols:Array<{value:string;count:number}>}>("/catalog/facets"); }
export function getCatalogCandidates(status?: string) { return request<{items:Rule[];total:number}>(`/catalog/candidates${status ? `?status=${encodeURIComponent(status)}` : ""}`); }
export type DetectionFamily = {id:number;slug:string;name:string;family_type:string;rule_count:number;mitre_count:number;protocols:string[];categories:string[];mitre_ids:string[];entity_types:string[];product_status:Record<string,number>};
export type DetectionFamilyList = {items:DetectionFamily[];total:number;offset:number;limit:number;page:number;total_pages:number};
export type MitreTechnique = {technique_id:string;name:string;tactics:string[];parent_id:string|null;is_subtechnique:boolean;rule_count:number;family_count:number;parent?:{technique_id:string;name:string}|null};
export type DetectionFamilyDetail = {family:DetectionFamily;provenance:Record<string,number>;mitre:{mapped_rule_count:number;unmapped_rule_count:number;techniques:MitreTechnique[]};rules:Array<Rule & {family_assignment:{provenance:string;evidence:Record<string,unknown>;algorithm_version:string;source_classification_id:number|null}}> ;total:number;offset:number;limit:number;page:number;total_pages:number};
export function getFamilyStats() { return request<{families:number;assigned_rules:number;evaluated_rules:number;unassigned_rules:number;pending_evaluation_rules:number;assignment_coverage:number}>("/families/stats"); }
export function getFamilies(params: URLSearchParams) { return request<DetectionFamilyList>(`/families?${params}`); }
export function getFamily(slug: string, offset=0, limit=50) { return request<DetectionFamilyDetail>(`/families/${encodeURIComponent(slug)}?offset=${offset}&limit=${limit}`); }
export type MitreOverview = {summary:{total_rules:number;mapped_rules:number;unmapped_rules:number;techniques_represented:number;subtechniques_represented:number;tactics_represented:number;families_with_mappings:number};tactics:Array<{name:string;technique_count:number;rule_count:number}>;data_source:string;coverage_scope:"SURICATA_CATALOG"};
export type MitreCoverage = {scope:"SURICATA_CATALOG_MAPPING_COVERAGE";disclaimer:string;summary:{repository_techniques:number;represented_techniques:number;gap_techniques:number;coverage_percent:number;mapped_rules:number;unmapped_rules:number};tactics:Array<{name:string;total_techniques:number;represented_techniques:number;gap_techniques:number;rule_count:number;coverage_percent:number}>;gaps:Array<{technique_id:string;name:string;tactics:string[];parent_id:string|null;is_subtechnique:boolean}>;data_source:string};
export type MitreTechniqueList = {items:MitreTechnique[];total:number;offset:number;limit:number;page:number;total_pages:number};
export type MitreTechniqueDetail = {technique:MitreTechnique&{description:string;source:string};parent:MitreTechnique|null;subtechniques:MitreTechnique[];related_families:Array<{id:number;slug:string;name:string;family_type:string;rule_count:number}>;categories:Array<{value:string;count:number}>;protocols:Array<{value:string;count:number}>;product_status:Record<string,number>;mapping_sources:Record<string,number>};
export type MitreTechniqueRules = {items:Array<Rule&{family:{slug:string;name:string}|null;mitre_mapping_sources:string[]}>;total:number;offset:number;limit:number;page:number;total_pages:number};
export function getMitreOverview(){return request<MitreOverview>("/mitre");}
export function getMitreCoverage(){return request<MitreCoverage>("/mitre/coverage");}
export function getMitreTechniques(params:URLSearchParams){return request<MitreTechniqueList>(`/mitre/techniques?${params}`);}
export function getMitreTechnique(techniqueId:string){return request<MitreTechniqueDetail>(`/mitre/techniques/${encodeURIComponent(techniqueId)}`);}
export function getMitreTechniqueRules(techniqueId:string,offset=0,limit=50){return request<MitreTechniqueRules>(`/mitre/techniques/${encodeURIComponent(techniqueId)}/rules?offset=${offset}&limit=${limit}`);}
export async function exportCatalogCsv(params: URLSearchParams) { const response = await fetch(`${API}/catalog/export.csv?${params}`); if (!response.ok) throw new Error("Export failed"); return response.blob(); }
export function getRule(sid: string) { return request<Rule>(`/rules/${sid}`); }
export type ForcedMitreMapping = {id:number;classification_id:number;technique_id:string;technique_name:string;tactic:string|null;confidence:number;evidence:Array<Record<string,unknown>>;explanation:string;provider:"gemini"|"claude"|"openai";model_name:string;created_at:string;forced:true;warning:string};
export type ForcedMitreState = {eligible:boolean;reason:string|null;mapping:ForcedMitreMapping|null};
export function getForcedMitre(sid:string,classificationId:number){return request<ForcedMitreState>(`/rules/${sid}/forced-mitre?classification_id=${classificationId}`);}
export function forceMitre(sid:string,classificationId:number){return request<ForcedMitreMapping>(`/rules/${sid}/forced-mitre`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({classification_id:classificationId,acknowledge_risk:true})});}
export function getNeighbors(sid: string) { return request<{previous_sid:number|null; next_sid:number|null}>(`/rules/${sid}/neighbors`); }
export function getReview(sid: string) { return request<{status:string;note:string|null;reviewer_type:string;reviewed_at:string}>(`/rules/${sid}/review`); }
export function getReviewHistory(sid: string) { return request<{items:Array<{status:string;note:string|null;reviewer_type:string;reviewed_at:string}>}>(`/rules/${sid}/review/history`); }
export type ProductStatus = "NOT_EVALUATED" | "CANDIDATE" | "APPROVED_FOR_PRODUCT" | "REJECTED_FOR_PRODUCT" | "ALREADY_INTEGRATED";
export function getProductDecision(sid: string) { return request<{status:ProductStatus;note:string|null;updated_at:string}>(`/rules/${sid}/product`); }
export function saveProductDecision(sid: string, status: ProductStatus, note?: string) { return request<{status:ProductStatus;note:string|null;updated_at:string}>(`/rules/${sid}/product`, {method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify({status,note:note || null})}); }
export function getProductHistory(sid: string) { return request<Array<{from_status:string|null;to_status:string;note:string|null;created_at:string}>>(`/rules/${sid}/product/history`); }
export function saveReview(sid: string, status: string, note?: string, classification_id?: number | null) { return request<{status:string;note:string|null;reviewer_type:string;reviewed_at:string}>(`/rules/${sid}/review`, {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({status,note:note||null,classification_id:classification_id||null})}); }
export function classifyRule(sid: number, force = false, executionProvider = "") { return request<Classification>(`/rules/${sid}/classify?force=${force}${executionProvider ? `&execution_provider=${encodeURIComponent(executionProvider)}` : ""}`, { method: "POST" }); }
export function getRules(params: URLSearchParams) { return request<{items: Rule[]; total: number; offset:number; limit:number; page:number; total_pages:number}>(`/rules?${params}`); }
export function getRuleOverrides(sid: string) { return request<{items:any[]}>(`/rules/${sid}/overrides`); }
export function saveRuleOverrides(sid: string, payload: any) { return request<{items:any[]}>(`/rules/${sid}/overrides`, {method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)}); }
export type AuditLogItem = {event_id:string;sid:number;action:string;classification_id:number|null;field_name:string|null;from_value:string|null;to_value:string|null;detail:string|null;created_at:string};
export function getAuditLogs(params: URLSearchParams) { return request<{items:AuditLogItem[];total:number;offset:number;limit:number}>(`/audit-log?${params}`); }
export function getClassificationFilters() { return request<{models:string[]; providers:string[]; classifier_versions:string[]; inference_modes:string[]; runs:string[]}>("/rules/filters"); }
export function importRules(files: FileList) {
  const body = new FormData();
  Array.from(files).forEach(file => body.append("files", file));
  return request<{imported: number; skipped: number; failed: number}>("/rules/import", { method: "POST", body });
}
export type ExistingRulesetPreview = {
  files:Array<{filename:string;discovered:number;exact_matches:number;new_catalog_rules:number;revision_updates:number;reusable_classifications:number;gemini_candidates:number;duplicates:number;errors:string[]}>;
  discovered:number;exact_matches:number;new_catalog_rules:number;revision_updates:number;reusable_classifications:number;gemini_candidates:number;duplicates:number;failed:number;
};
export type ExistingRulesetImport = {
  files:Array<{filename:string;discovered:number;matched_existing:number;imported:number;marked_existing:number;already_marked:number;duplicates:number;errors:string[]}>;
  discovered:number;matched_existing:number;imported:number;marked_existing:number;already_marked:number;duplicates:number;failed:number;
  reused_classifications:number;queued_for_gemini:number;classification_batch_id:string|null;
};
export type ProductRulesetBatch = {
  batch_id:string;filenames:string[];status:"PENDING"|"RUNNING"|"COMPLETED"|"PARTIAL_FAILED"|"FAILED";
  provider:string;model_name:string|null;classifier_version:string;discovered:number;reused_classifications:number;
  queued:number;processed:number;auto_classified:number;review_required:number;failed:number;
  error_message:string|null;created_at:string;completed_at:string|null;
};
function rulesetForm(files: File[]) {
  const body = new FormData();
  files.forEach((file) => body.append("files", file));
  return body;
}
export function previewExistingRuleset(files: File[]) {
  return request<ExistingRulesetPreview>("/rules/existing/preview", {method:"POST", body:rulesetForm(files)});
}
export function importExistingRuleset(files: File[]) {
  return request<ExistingRulesetImport>("/rules/existing/import", {method:"POST", body:rulesetForm(files)});
}
export function getProductRulesetBatch(batchId: string) {
  return request<ProductRulesetBatch>(`/rules/existing/batches/${encodeURIComponent(batchId)}?fresh=${Date.now()}`);
}
export function retryProductRulesetBatch(batchId: string) {
  return request<ProductRulesetBatch>(`/rules/existing/batches/${encodeURIComponent(batchId)}/retry`, {method:"POST"});
}
export function getModelConfig() { return request<any>("/model-lab/config"); }
export function updateModelConfig(payload: any) { return request<any>("/model-lab/config", {method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)}); }
export function testModel(provider: "openai"|"gemini"|"claude"|"ollama") { return request<any>(`/model-lab/test/${provider}`, {method:"POST"}); }
export type ProviderHealth = { ok: boolean; provider?: string; model?: string; latency_ms?: number; error?: string };
let modelStatusCache: { value: {providers: Record<string, ProviderHealth>; checked_at: number}; at: number } | null = null;
let modelStatusRequest: Promise<{providers: Record<string, ProviderHealth>; checked_at: number}> | null = null;
export function getModelStatus(force = false) {
  const now = Date.now();
  if (!force && modelStatusCache && now - modelStatusCache.at < 60_000) return Promise.resolve(modelStatusCache.value);
  if (!force && modelStatusRequest) return modelStatusRequest;
  modelStatusRequest = request<{providers: Record<string, ProviderHealth>; checked_at: number}>("/model-lab/status")
    .then(value => { modelStatusCache = { value, at: Date.now() }; return value; })
    .finally(() => { modelStatusRequest = null; });
  return modelStatusRequest;
}
export function getOllamaModels() { return request<{models:string[];error?:string}>("/model-lab/ollama/models"); }
export function compareModels(payload: {sid:number;rev?:number;models:string[]}) { return request<any>("/model-lab/compare", {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)}); }
export function saveComparisonReview(sid:number,payload:any) { return request<any>(`/model-lab/${sid}/review`, {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)}); }
export function translateTexts(texts: string[], locale: string) { return request<{translations:string[]}>("/catalog/assistant/translate", {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({texts, locale})}); }
export type ScenarioRule = { sid:number; rev:number; classification_id:number|null; message:string|null; category:string|null; subcategory:string|null; entity:string|null; mitre_id:string|null; mitre_tactic:string|null; provider:string|null; model:string|null; product_status:string; match_type:"MITRE"|"KEYWORD"|"PROTOCOL"; step_index:number; why:string };
export type ScenarioStepResult = { index:number; title:string; technique_id:string|null; technique_name:string|null; tactics:string[]; keywords:string[]; status:"COVERED"|"PARTIAL"|"GAP"; confidence:number; matched_rule_count:number; evidence:string[]; rules:ScenarioRule[] };
export type ScenarioAnalysis = { status:"COVERED"|"PARTIAL"|"GAP"; summary:string; steps:ScenarioStepResult[]; recommendations:ScenarioRule[]; assumptions:string[]; signals_extracted:number; planner_model:string; source:string };
export type ScenarioProvider = "gemini" | "claude" | "openai";
export function analyzeScenario(question:string, provider:ScenarioProvider = "gemini", signal?: AbortSignal) { return request<ScenarioAnalysis>("/catalog/assistant/scenario", {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({question, provider}),signal}); }

/** Warm only read-only, lightweight catalogue data after the first screen paints. */
export function warmAppCache() {
  const rulesParams = new URLSearchParams({ limit: "50", offset: "0", sort: "sid_desc" });
  const familyParams = new URLSearchParams({ limit: "24", offset: "0" });
  const mitreParams = new URLSearchParams({ limit: "50", offset: "0", kind: "all" });
  return Promise.allSettled([
    getStats(), getCatalogStats(), getCatalogFacets(), getClassificationFilters(),
    getFamilyStats(), getFamilies(familyParams), getMitreOverview(), getMitreTechniques(mitreParams),
    getRules(rulesParams), getModelConfig(),
  ]);
}
