import type { Classification, Rule, Stats } from "../types";

const API = import.meta.env.VITE_API_URL || "/api";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API}${path}`, init);
  if (!response.ok) throw new Error((await response.json().catch(() => null))?.detail || response.statusText);
  return response.json();
}

export function getStats() { return request<Stats>("/stats"); }
export function getRule(sid: string) { return request<Rule>(`/rules/${sid}`); }
export function getNeighbors(sid: string) { return request<{previous_sid:number|null; next_sid:number|null}>(`/rules/${sid}/neighbors`); }
export function getReview(sid: string) { return request<{status:string;note:string|null;reviewer_type:string;reviewed_at:string}>(`/rules/${sid}/review`); }
export function getReviewHistory(sid: string) { return request<{items:Array<{status:string;note:string|null;reviewer_type:string;reviewed_at:string}>}>(`/rules/${sid}/review/history`); }
export function saveReview(sid: string, status: string, note?: string, classification_id?: number | null) { return request<{status:string;note:string|null;reviewer_type:string;reviewed_at:string}>(`/rules/${sid}/review`, {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({status,note:note||null,classification_id:classification_id||null})}); }
export function classifyRule(sid: number, force = false, executionProvider = "") { return request<Classification>(`/rules/${sid}/classify?force=${force}${executionProvider ? `&execution_provider=${encodeURIComponent(executionProvider)}` : ""}`, { method: "POST" }); }
export function getRules(params: URLSearchParams) { return request<{items: Rule[]; total: number; offset:number; limit:number; page:number; total_pages:number}>(`/rules?${params}`); }
export function getClassificationFilters() { return request<{models:string[]; providers:string[]; classifier_versions:string[]; inference_modes:string[]; runs:string[]}>("/rules/filters"); }
export function importRules(files: FileList) {
  const body = new FormData();
  Array.from(files).forEach(file => body.append("files", file));
  return request<{imported: number; skipped: number; failed: number}>("/rules/import", { method: "POST", body });
}
export function getModelConfig() { return request<any>("/model-lab/config"); }
export function updateModelConfig(payload: any) { return request<any>("/model-lab/config", {method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)}); }
export function testModel(provider: "gemini"|"ollama") { return request<any>(`/model-lab/test/${provider}`, {method:"POST"}); }
export function getOllamaModels() { return request<{models:string[];error?:string}>("/model-lab/ollama/models"); }
export function compareModels(payload: {sid:number;rev?:number;models:string[]}) { return request<any>("/model-lab/compare", {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)}); }
export function saveComparisonReview(sid:number,payload:any) { return request<any>(`/model-lab/${sid}/review`, {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)}); }
