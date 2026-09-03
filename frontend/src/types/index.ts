export type Status = "AUTO_CLASSIFIED" | "REVIEW_REQUIRED" | "FAILED";

export interface Classification {
  manual_review?: {status:string;note:string|null;reviewer_type:string;reviewed_at:string} | null;
  id: number;
  detected_behavior: string | null;
  detected_entity: string | null;
  entity_type: string | null;
  category: string | null;
  subcategory: string | null;
  mitre_tactic: string | null;
  mitre_technique: string | null;
  mitre_technique_id: string | null;
  cyber_kill_chain_phase: string | null;
  confidence: number;
  evidence: string[];
  explanation: string;
  model_name: string;
  model_display_name?: string | null;
  provider?: string | null;
  inference_mode?: string | null;
  run_id?: string | null;
  classification_run_id?: number | null;
  inference_duration_ms?: number | null;
  classifier_version: string;
  agent_activity: Record<string, unknown>;
  inspection_batch?: string | null;
  source_mitre_mapping?: { technique_id: string; technique_name?: string; tactic?: string; source?: string } | null;
  final_mitre_mapping?: { technique_id: string; technique_name?: string; tactic?: string } | null;
  mitre_mapping_method?: string | null;
  mapping_reason?: string | null;
  mitre_retrieval_score?: number | null;
  evidence_strength?: string | null;
  model_confidence?: number | null;
  validator_mitre_status?: string | null;
  classification_status: Status;
  validation_issues: string[];
  created_at: string;
  field_decisions?: Record<string, {status:string; value: unknown; reason:string|null}>;
  abstained_fields?: string[];
  validation?: {status:string; reason?:string; checks?:string[]; source?:string; deterministic_validator?: {status:string}; semantic_verifier?: {status:string}} | null;
  consistency_warnings?: string[];
  confidence_semantics?: string;
  confidence_band?: string;
  confidence_band_definition?: string;
  field_coverage?: {assigned:number; total:number; ratio:number};
}

export interface Rule {
  id: number; sid: number; rev: number; raw_rule: string; msg: string | null;
  action: string; protocol: string; source: string; source_port: string; direction: string;
  destination: string; destination_port: string; classtype: string | null; metadata: string[];
  references: string[]; flow: string[]; flowbits: string[]; contents: string[]; pcre: string[];
  app_layer: Array<Record<string, string | null>>; source_file: string | null; created_at: string;
  classification: Classification | null; manual_review?: {status:string; note:string|null; reviewer_type:string; reviewed_at:string} | null;
  classification_options?: Classification[];
  product_decision?: {status:string; note:string|null; updated_at:string} | null;
}

export interface Stats {
  total_rules: number; classified_rules: number; review_required: number; failed: number;
  category_distribution: Record<string, number>; top_detected_entities: Array<{name: string; count: number}>;
  top_mitre_techniques: Array<{id: string; name: string; count: number}>; average_confidence: number;
  manual_review?: Record<string, number>;
}
