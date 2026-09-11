import { useDeferredValue, useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { AddToRulePack } from "../components/AddToRulePack";
import { StatusBadge } from "../components/StatusBadge";
import {
  clearApiCache,
  getCatalogStats,
  getProductRulesetBatch,
  getRules,
  importExistingRuleset,
  previewExistingRuleset,
  retryProductRulesetBatch,
  saveProductDecision,
  type ExistingRulesetImport,
  type ExistingRulesetPreview,
  type ProductRulesetBatch,
} from "../services/api";
import type { Rule } from "../types";
import { useI18n } from "../i18n";

const PAGE_SIZE = 40;
const MAX_RULESET_FILES = 10;
const MAX_RULESET_FILE_BYTES = 25 * 1024 * 1024;
const MAX_RULESET_TOTAL_BYTES = 50 * 1024 * 1024;

export function ExistingRules() {
  const { t, label } = useI18n();
  const navigate = useNavigate();
  const fileInput = useRef<HTMLInputElement>(null);
  const [rules, setRules] = useState<Rule[]>([]);
  const [total, setTotal] = useState(0);
  const [workspaceTotal, setWorkspaceTotal] = useState(0);
  const [search, setSearch] = useState("");
  const deferredSearch = useDeferredValue(search);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [preview, setPreview] = useState<ExistingRulesetPreview | null>(null);
  const [importResult, setImportResult] = useState<ExistingRulesetImport | null>(null);
  const [uploading, setUploading] = useState<"preview" | "import" | "">("");
  const [uploadError, setUploadError] = useState("");
  const [geminiConsent, setGeminiConsent] = useState(false);
  const [batch, setBatch] = useState<ProductRulesetBatch | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const [removeTarget, setRemoveTarget] = useState<Rule | null>(null);
  const [removing, setRemoving] = useState(false);
  const [removeMessage, setRemoveMessage] = useState("");
  const [removeError, setRemoveError] = useState("");

  const params = useMemo(() => {
    const value = new URLSearchParams({
      product_status: "ALREADY_INTEGRATED",
      limit: String(PAGE_SIZE),
      offset: String((page - 1) * PAGE_SIZE),
      sort: "sid_desc",
    });
    if (deferredSearch.trim()) value.set("search", deferredSearch.trim());
    return value;
  }, [page, deferredSearch]);

  useEffect(() => {
    setLoading(true);
    Promise.all([getRules(params), getCatalogStats()])
      .then(([result, stats]) => {
        setRules(result.items);
        setTotal(result.total);
        setWorkspaceTotal(stats.product_status.ALREADY_INTEGRATED || 0);
        setError("");
      })
      .catch((cause) => setError(cause instanceof Error ? cause.message : "Existing rules could not be loaded"))
      .finally(() => setLoading(false));
  }, [params, refreshKey]);

  useEffect(() => setPage(1), [search]);

  useEffect(() => {
    if (!removeTarget) return;
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !removing) setRemoveTarget(null);
    };
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [removeTarget, removing]);

  useEffect(() => {
    if (!batch || !["PENDING", "RUNNING"].includes(batch.status)) return;
    const timer = window.setTimeout(() => {
      getProductRulesetBatch(batch.batch_id)
        .then((next) => {
          setBatch(next);
          if (!["PENDING", "RUNNING"].includes(next.status)) {
            clearApiCache();
            setRefreshKey((value) => value + 1);
          }
        })
        .catch(() => undefined);
    }, 1400);
    return () => window.clearTimeout(timer);
  }, [batch]);

  async function inspectFiles(files: File[]) {
    if (!files.length) return;
    if (fileInput.current) fileInput.current.value = "";
    const invalidExtension = files.find((file) => !file.name.toLowerCase().endsWith(".rules"));
    const oversized = files.find((file) => file.size > MAX_RULESET_FILE_BYTES);
    const totalBytes = files.reduce((sum, file) => sum + file.size, 0);
    const clientError = files.length > MAX_RULESET_FILES
      ? t("Select no more than 10 .rules files at once.")
      : invalidExtension
        ? t("Only UTF-8 .rules files are accepted. ZIP, JSON, PDF, executable and generic text files are rejected.")
        : oversized
          ? t("Each ruleset file must be 25 MB or smaller.")
          : totalBytes > MAX_RULESET_TOTAL_BYTES
            ? t("The combined upload must be 50 MB or smaller.")
            : "";
    if (clientError) {
      setSelectedFiles([]);
      setPreview(null);
      setImportResult(null);
      setUploadError(clientError);
      return;
    }
    setSelectedFiles(files);
    setPreview(null);
    setImportResult(null);
    setBatch(null);
    setGeminiConsent(false);
    setUploadError("");
    setUploading("preview");
    try {
      setPreview(await previewExistingRuleset(files));
    } catch (cause) {
      setUploadError(cause instanceof Error ? cause.message : t("Ruleset could not be inspected."));
    } finally {
      setUploading("");
    }
  }

  async function applyRuleset() {
    if (!selectedFiles.length) return;
    setUploadError("");
    setUploading("import");
    try {
      const result = await importExistingRuleset(selectedFiles);
      setImportResult(result);
      setPreview(null);
      if (result.classification_batch_id) {
        getProductRulesetBatch(result.classification_batch_id)
          .then(setBatch)
          .catch(() => setUploadError(t("Baseline was imported, but classification progress could not be loaded.")));
      }
      setRefreshKey((value) => value + 1);
    } catch (cause) {
      setUploadError(cause instanceof Error ? cause.message : t("Ruleset could not be imported."));
    } finally {
      setUploading("");
    }
  }

  async function retryBatch() {
    if (!batch) return;
    setUploadError("");
    try {
      setBatch(await retryProductRulesetBatch(batch.batch_id));
    } catch (cause) {
      setUploadError(cause instanceof Error ? cause.message : t("Gemini classification could not be retried."));
    }
  }

  async function removeFromProduct() {
    if (!removeTarget) return;
    setRemoving(true);
    setRemoveMessage("");
    setRemoveError("");
    try {
      await saveProductDecision(
        String(removeTarget.sid),
        "NOT_EVALUATED",
        "Removed from the current product baseline on the Existing Rules page.",
      );
      setRemoveTarget(null);
      setPage(1);
      clearApiCache();
      setRefreshKey((value) => value + 1);
      setRemoveMessage(t("Rule removed from the product baseline. Its catalogue record and classification were kept."));
    } catch (cause) {
      setRemoveError(cause instanceof Error ? cause.message : t("Rule could not be removed from the product baseline."));
    } finally {
      setRemoving(false);
    }
  }

  const mapped = rules.filter((rule) => Boolean(rule.classification?.mitre_technique_id)).length;
  const classified = rules.filter((rule) => Boolean(rule.classification)).length;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const selectedNames = selectedFiles.map((file) => file.name).join(", ");
  const previewErrors = preview?.files.flatMap((file) => file.errors.map((message) => `${file.filename}: ${message}`)) || [];
  const importErrors = importResult?.files.flatMap((file) => file.errors.map((message) => `${file.filename}: ${message}`)) || [];

  return <div className="existing-rules-page">
    <header className="existing-rules-hero">
      <div className="section-kicker">{t("PRODUCT BASELINE · NDR CATALOGUE")}</div>
      <h1>{t("Map your product ruleset.")}</h1>
      <p>{t("Upload the Suricata rules currently deployed in your cybersecurity product. Existing catalogue classifications are reused; only new or unclassified rules are sent to Gemini.")}</p>
      <div className="existing-rule-stamp" aria-hidden="true"><span>BASELINE</span><b>SID · REV</b></div>
    </header>

    <section className="existing-rules-workbench" aria-label={t("Product ruleset workspace")}>
      <article className="ruleset-import-card">
        <div className="workbench-heading">
          <span className="workbench-index">01</span>
          <div><div className="section-kicker">{t("IMPORT PRODUCT BASELINE")}</div><h2>{t("Upload your current ruleset")}</h2></div>
        </div>
        <div className="ruleset-format-guide">
          <div className="ruleset-format-title"><strong>{t("Accepted ruleset format")}</strong><span>{t("Validated before any database write")}</span></div>
          <div className="ruleset-format-grid">
            <div><b>.rules · UTF-8</b><span>{t("Plain-text Suricata rules only. Up to 10 files, 25 MB each and 50 MB combined.")}</span></div>
            <div><b>SID · REV</b><span>{t("Every active rule needs a numeric SID. REV is recommended and defaults to 1 when omitted.")}</span></div>
            <div><b>HEADER → OPTIONS</b><span>{t("Use the standard seven-field Suricata header followed by a parenthesized option block.")}</span></div>
          </div>
          <pre><code>{'alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Example TLS detection"; flow:established,to_server; sid:9000001; rev:1;)'}</code></pre>
          <details><summary>{t("Formatting and safety notes")}</summary><ul><li>{t("One rule per line is simplest; multiline rules are accepted when the final option block ends with ).")}</li><li>{t("Blank lines and lines beginning with # are ignored.")}</li><li>{t("ZIP archives, JSON, PDF, executables, binary data and renamed non-rule files are rejected.")}</li><li>{t("The server also limits each file to 100,000 rules and each individual rule to 64 KB.")}</li><li>{t("Preview parses and validates the files without changing the catalogue. Import becomes available only when valid rules are found.")}</li></ul></details>
        </div>
        <label
          className={`ruleset-dropzone ${uploading ? "busy" : ""}`}
          onDragOver={(event) => event.preventDefault()}
          onDrop={(event) => { event.preventDefault(); void inspectFiles(Array.from(event.dataTransfer.files)); }}
        >
          <input ref={fileInput} type="file" accept=".rules" multiple
            onChange={(event) => void inspectFiles(Array.from(event.target.files || []))} />
          <span className="dropzone-mark" aria-hidden="true">⇧</span>
          <strong>{uploading === "preview" ? t("Parsing ruleset…") : t("Drop .rules files here")}</strong>
          <small>{t("or choose files · up to 25 MB each")}</small>
        </label>

        {selectedNames && <div className="selected-ruleset"><span>{t("Selected")}</span><b title={selectedNames}>{selectedNames}</b><button type="button" onClick={() => fileInput.current?.click()}>{t("Choose different files")}</button></div>}
        {uploadError && <div className="ruleset-message error">{uploadError}</div>}

        {preview && <div className="ruleset-preview" aria-live="polite">
          <div className="preview-title"><strong>{t("Ready to establish baseline")}</strong><span>{preview.discovered.toLocaleString()} {t("rules parsed")}</span></div>
          <div className="preview-grid">
            <div><b>{preview.exact_matches.toLocaleString()}</b><span>{t("Exact catalogue match")}</span></div>
            <div><b>{preview.new_catalog_rules.toLocaleString()}</b><span>{t("New catalogue record")}</span></div>
            <div><b>{preview.revision_updates.toLocaleString()}</b><span>{t("Same SID, new revision")}</span></div>
            <div className={preview.failed ? "warning" : ""}><b>{preview.failed.toLocaleString()}</b><span>{t("Parse error")}</span></div>
          </div>
          <div className="classification-plan">
            <div><b>{preview.reusable_classifications.toLocaleString()}</b><span>{t("Existing Qwen classifications will be reused")}</span></div>
            <div className="gemini"><b>{preview.gemini_candidates.toLocaleString()}</b><span>{t("New or unclassified rules will use Gemini")}</span></div>
          </div>
          {previewErrors.length > 0 && <div className="ruleset-validation-errors" role="alert"><strong>{t("Rejected content")}</strong><ul>{previewErrors.slice(0, 12).map((message, index) => <li key={`${index}:${message}`}>{message}</li>)}</ul>{previewErrors.length > 12 && <small>{previewErrors.length - 12} {t("additional validation errors were hidden")}</small>}</div>}
          <p>{t("New rules and revisions will be added to the catalogue. Every successfully parsed rule will be marked Already Integrated with its source filename.")}</p>
          {preview.gemini_candidates > 0 && <label className="gemini-consent">
            <input type="checkbox" checked={geminiConsent} onChange={(event) => setGeminiConsent(event.target.checked)} />
            <span>{t("I understand that parsed fields from these new rules will be sent to the configured Gemini API for classification. Existing Qwen results will not be changed.")}</span>
          </label>}
          <button className="primary establish-baseline" type="button" disabled={uploading === "import" || preview.exact_matches + preview.new_catalog_rules === 0 || (preview.gemini_candidates > 0 && !geminiConsent)}
            onClick={() => void applyRuleset()}>{uploading === "import" ? t("Establishing baseline…") : preview.gemini_candidates > 0 ? t("Import & classify new rules") : t("Import & reuse classifications")}</button>
        </div>}

        {importResult && <div className="ruleset-message success" aria-live="polite">
          <strong>{t("Product baseline updated")}</strong>
          <span>{importResult.marked_existing.toLocaleString()} {t("rules marked existing")} · {importResult.reused_classifications.toLocaleString()} {t("Qwen results reused")} · {importResult.queued_for_gemini.toLocaleString()} {t("queued for Gemini")}</span>
          {importErrors.length > 0 && <small>{importErrors.length} {t("items were rejected safely; inspect the files and preview again.")}</small>}
        </div>}

        {batch && <div className={`gemini-batch ${batch.status.toLowerCase()}`} aria-live="polite">
          <div className="gemini-batch-heading"><div><span>{t("GEMINI IMPORT CLASSIFICATION")}</span><strong>{t(batch.status === "COMPLETED" ? "Classification completed" : batch.status === "RUNNING" ? "Classifying new rules…" : batch.status === "PENDING" ? "Waiting to classify…" : "Classification needs attention")}</strong></div><b>{batch.processed}/{batch.queued}</b></div>
          <div className="gemini-progress"><i style={{width: `${batch.queued ? Math.round(batch.processed / batch.queued * 100) : 100}%`}} /></div>
          <div className="gemini-batch-counts"><span><b>{batch.auto_classified}</b>{t("Auto-classified")}</span><span><b>{batch.review_required}</b>{t("Needs review")}</span><span><b>{batch.failed}</b>{t("Failed")}</span></div>
          {batch.error_message && <p>{t(batch.error_message)}</p>}
          {["FAILED", "PARTIAL_FAILED"].includes(batch.status) && <div className="gemini-batch-actions"><button type="button" onClick={() => void retryBatch()}>{t("Retry Gemini classification")}</button>{batch.error_message?.includes("NOT_CONFIGURED") && <Link to="/models">{t("Configure Gemini in Model Lab")}</Link>}</div>}
        </div>}
      </article>

      <article className="existing-search-card">
        <div className="workbench-heading">
          <span className="workbench-index">02</span>
          <div><div className="section-kicker">{t("SEARCH PRODUCT COVERAGE")}</div><h2>{t("Find an existing detection")}</h2></div>
        </div>
        <label className="existing-search-field">
          <span className="search-glyph" aria-hidden="true">⌕</span>
          <span className="search-label">{t("Search the product baseline")}</span>
          <input aria-label={t("Search existing rules")} placeholder={t("Enter SID, rule message, entity or MITRE technique…")}
            value={search} onChange={(event) => setSearch(event.target.value)} />
          {search && <button type="button" aria-label={t("Clear search")} onClick={() => setSearch("")}>×</button>}
        </label>
        <div className="search-scope"><span>SID</span><span>{t("Message")}</span><span>{t("Entity")}</span><span>MITRE</span><span>{t("Family")}</span></div>
        <p>{search ? <>{t("Showing product rules matching")} <strong>“{search}”</strong></> : t("Search only within rules confirmed as present in the product.")}</p>
      </article>
    </section>

    <section className="existing-rules-metrics" aria-label={t("Existing rule summary")}>
      <div><b>{workspaceTotal.toLocaleString()}</b><span>{t("Integrated in product")}</span></div>
      <div><b>{total.toLocaleString()}</b><span>{t("Matching current filter")}</span></div>
      <div><b>{classified.toLocaleString()}</b><span>{t("With classification")}</span></div>
      <div><b>{mapped.toLocaleString()}</b><span>{t("MITRE mapped on page")}</span></div>
    </section>

    <section className="panel existing-rules-board">
      <div className="panel-heading">
        <div><div className="section-kicker">{t("INTEGRATED CONTENT REGISTER")}</div><h2>{t("Current NDR rule set")}</h2><p className="result-count"><strong>{total.toLocaleString()}</strong> {t("integrated records")} · {t("page")} {page} / {pages}</p></div>
        {search && <button className="clear-existing-search" type="button" onClick={() => setSearch("")}>{t("Clear search")}</button>}
      </div>
      {removeMessage && <div className="existing-remove-message" role="status">{removeMessage}</div>}
      {error && <div className="error">{error}</div>}
      {loading ? <div className="loading">{t("Loading existing rules…")}</div> : rules.length ? <div className="existing-rule-list">{rules.map((rule) => {
        const classification = rule.classification;
        return <article className="existing-rule-row" key={rule.id} role="link" tabIndex={0}
          aria-label={`${t("Open rule details")} ${rule.sid}`}
          onClick={() => navigate(`/rules/${rule.sid}`)}
          onKeyDown={(event) => { if (event.key === "Enter" && event.target === event.currentTarget) navigate(`/rules/${rule.sid}`); }}>
          <div className="existing-rule-id"><span>SID</span><b>{rule.sid}</b><small>rev {rule.rev}</small></div>
          <div className="existing-rule-main"><strong>{rule.msg || t("Untitled rule")}</strong><small>{rule.protocol} · {rule.source_file || t("unknown source")}</small><div className="existing-rule-tags">{rule.families?.slice(0, 3).map((family) => <em key={family.slug}>{family.name}</em>)}{classification?.mitre_technique_id && <em className="mitre">{classification.mitre_technique_id}</em>}</div></div>
          <div className="existing-rule-decision"><span>{classification?.category ? label(classification.category) : t("Unclassified")}</span><small>{classification?.detected_entity || t("No entity assigned")}</small></div>
          <div className="existing-rule-status"><StatusBadge status={classification?.classification_status} /><small>{t("ALREADY INTEGRATED")}</small></div>
          <div className="existing-rule-actions" onClick={(event) => event.stopPropagation()} onKeyDown={(event) => event.stopPropagation()}>
            <AddToRulePack sid={rule.sid} compact />
            <button className="remove-product-rule" type="button" onClick={() => { setRemoveMessage(""); setRemoveError(""); setRemoveTarget(rule); }}>{t("Remove from product")}</button>
          </div>
        </article>;
      })}</div> : <div className="existing-empty"><b>{workspaceTotal ? t("No integrated rules match the current search.") : t("No rules are marked as existing yet.")}</b><span>{workspaceTotal ? t("Try a broader search or clear the filter.") : t("Upload the product ruleset above, or mark a rule as Already Integrated from its decision panel.")}</span>{!workspaceTotal && <Link to="/catalog/rules">{t("Open Rules to review product decisions →")}</Link>}</div>}
      <div className="pagination"><button disabled={page <= 1} onClick={() => setPage((value) => value - 1)}>{t("← Previous")}</button><span>{t("page")} {page} / {pages}</span><button disabled={page >= pages} onClick={() => setPage((value) => value + 1)}>{t("Next →")}</button></div>
    </section>

    {removeTarget && <div className="existing-remove-overlay" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !removing) setRemoveTarget(null); }}>
      <section className="existing-remove-dialog" role="alertdialog" aria-modal="true" aria-labelledby="remove-rule-title" aria-describedby="remove-rule-description">
        <div className="section-kicker">{t("PRODUCT BASELINE CHANGE")}</div>
        <h2 id="remove-rule-title">{t("Remove this rule from the product?")}</h2>
        <p id="remove-rule-description">{t("This removes the rule from the current NDR baseline. Its catalogue record, classification and history will be kept.")}</p>
        <div className="remove-rule-summary"><span>SID</span><b>{removeTarget.sid}</b><small>{removeTarget.msg || t("Untitled rule")}</small></div>
        {removeError && <div className="ruleset-message error" role="alert">{removeError}</div>}
        <div className="existing-remove-actions">
          <button type="button" autoFocus disabled={removing} onClick={() => setRemoveTarget(null)}>{t("Cancel")}</button>
          <button className="confirm-remove" type="button" disabled={removing} onClick={() => void removeFromProduct()}>{removing ? t("Removing…") : t("Remove from product")}</button>
        </div>
      </section>
    </div>}
  </div>;
}
