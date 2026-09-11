import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { AddToRulePack } from "../components/AddToRulePack";
import {
  analyzeScenario,
  getModelConfig,
  getModelStatus,
  translateTexts,
  type ProviderHealth,
  type ScenarioAnalysis,
  type ScenarioProvider,
  type ScenarioStepResult,
} from "../services/api";
import { useI18n } from "../i18n";

const complexExample = "During a red team exercise, initial access was gained by exploiting an internet-facing web server. The attacker executed PowerShell, used compromised credentials to move laterally over RDP to an internal server, staged sensitive financial files in an archive, and exfiltrated the archive in fragments through DNS TXT queries. The NDR product produced no alert at any stage. Identify the network-observable behaviors, likely MITRE ATT&CK techniques, relevant Suricata rules in the local catalogue, and any coverage gaps.";
const exampleTranslations: Record<string, string> = {
  [complexExample]:
    "Bir red team çalışmasında internete açık web sunucusundaki zafiyet kullanılarak ilk erişim sağlandı. Saldırgan PowerShell ile kod çalıştırdı, ele geçirilen kimlik bilgileriyle RDP üzerinden iç ağdaki bir sunucuya yatay hareket etti, hassas finans dosyalarını arşivledi ve arşivi DNS TXT sorgularına bölerek dışarı aktardı. NDR ürünü bu zincirin hiçbir adımında alarm üretmedi. Ağ üzerinden gözlemlenebilecek davranışları, olası MITRE ATT&CK tekniklerini, yerel katalogdaki ilgili Suricata kurallarını ve kapsama boşluklarını çıkar.",
};

function statusLabel(status: ScenarioStepResult["status"]) {
  return status === "COVERED"
    ? "COVERED"
    : status === "PARTIAL"
      ? "PARTIAL"
      : "GAP";
}

export function ScenarioCoverage() {
  const { t, locale, label } = useI18n();
  const [prompt, setPrompt] = useState("");
  const [result, setResult] = useState<ScenarioAnalysis | null>(null);
  const [busy, setBusy] = useState(false);
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  const [error, setError] = useState("");
  const [provider, setProvider] = useState<ScenarioProvider>("gemini");
  const [modelConfig, setModelConfig] = useState<
    Record<string, { api_key_configured?: boolean; model?: string }>
  >({});
  const [providerHealth, setProviderHealth] = useState<Record<string, ProviderHealth>>({});
  const [healthBusy, setHealthBusy] = useState(true);
  const [localizedProse, setLocalizedProse] = useState<Record<string, string>>(
    {},
  );
  const promptInput = useRef<HTMLTextAreaElement>(null);
  const resultAnchor = useRef<HTMLDivElement>(null);
  const activeAnalysis = useRef<AbortController | null>(null);
  useEffect(() => {
    let active = true;
    setHealthBusy(true);

    // Configuration supplies model labels only. A configured key/model is not
    // proof that the provider is reachable, so keep every provider in
    // “Checking” until the authoritative live probe completes.
    const refreshLiveStatus = () => {
      void getModelStatus(true)
        .then((status) => {
          if (active) {
            setProviderHealth(status.providers || {});
            setHealthBusy(false);
          }
        })
        .catch(() => {
          if (active) {
            setProviderHealth({});
            setHealthBusy(false);
          }
        });
    };
    void getModelConfig()
      .then((config) => {
        if (!active) return;
        setModelConfig(config);
        setProviderHealth({});
        refreshLiveStatus();
      })
      .catch(() => {
        if (active) {
          setProviderHealth({});
          setHealthBusy(true);
        }
        refreshLiveStatus();
      });
    return () => {
      active = false;
    };
  }, []);
  useEffect(() => {
    if (locale !== "tr" || !result) {
      setLocalizedProse({});
      return;
    }
    const texts = [
      result.summary,
      ...result.assumptions,
      ...result.steps.flatMap((step) => [step.title, ...step.evidence]),
      ...result.recommendations.flatMap((item) => [
        item.message || "",
        item.why,
      ]),
    ].filter(Boolean);
    if (!texts.length) return;
    void translateTexts([...new Set(texts)], locale)
      .then((response) =>
        setLocalizedProse(
          Object.fromEntries(
            [...new Set(texts)].map((text, index) => [
              text,
              response.translations[index] || text,
            ]),
          ),
        ),
      )
      .catch(() => undefined);
  }, [locale, result]);
  useEffect(() => {
    if (!busy) return;
    setElapsedSeconds(0);
    const timer = window.setInterval(() => setElapsedSeconds((value) => value + 1), 1000);
    return () => window.clearInterval(timer);
  }, [busy]);
  useEffect(() => () => activeAnalysis.current?.abort(), []);
  const available = (name: ScenarioProvider) => providerHealth[name]?.ok === true;
  const providerState = (name: ScenarioProvider) =>
    healthBusy ? t("Checking…") : available(name) ? t("Active") : t("Unavailable");
  const analyze = async (value = prompt) => {
    const question = value.trim();
    if (question.length < 10 || activeAnalysis.current) return;
    const controller = new AbortController();
    activeAnalysis.current = controller;
    // Provider planning plus the bounded local evidence pass can take longer
    // on a large SQLite catalogue. Keep the request alive long enough for a
    // valid result instead of presenting a misleading timeout error.
    const timeout = window.setTimeout(() => controller.abort(), 180_000);
    setBusy(true);
    setError("");
    setResult(null);
    try {
      const nextResult = await analyzeScenario(question, provider, controller.signal);
      setResult(nextResult);
      window.requestAnimationFrame(() => resultAnchor.current?.scrollIntoView({ behavior: "smooth", block: "start" }));
    } catch (e) {
      setError(e instanceof DOMException && e.name === "AbortError"
        ? t("The analysis took too long. Please try again with a slightly shorter scenario.")
        : e instanceof Error ? e.message : t("Scenario analysis failed"));
    } finally {
      window.clearTimeout(timeout);
      if (activeAnalysis.current === controller) {
        activeAnalysis.current = null;
        setBusy(false);
      }
    }
  };

  const prose = (text: string | null | undefined) =>
    text ? localizedProse[text] || text : "";
  const exampleLabel = (text: string) =>
    locale === "tr" ? exampleTranslations[text] || text : text;

  return (
    <div className="scenario-page">
      <header className="scenario-howto">
        <div className="scenario-howto-intro">
          <div className="section-kicker">{t("DETECTION READINESS")}</div>
          <h1>{t("How to use this page")}</h1>
          <p>{t("Describe the missed attack as a timeline: entry point, tools, protocols, lateral movement and exfiltration. The analysis turns those observations into a locally verified rule shortlist.")}</p>
          <div className="scenario-howto-steps">
            <span><b>01</b>{t("Paste the customer or red team scenario")}</span>
            <span><b>02</b>{t("Choose the configured analysis provider")}</span>
            <span><b>03</b>{t("Review the attack path and matching rules below")}</span>
          </div>
        </div>
        <aside className="scenario-example-card">
          <div><span>{t("COMPLEX EXAMPLE")}</span><small>{t("Ready to paste")}</small></div>
          <p>{exampleLabel(complexExample)}</p>
          <button type="button" onClick={() => { setPrompt(exampleLabel(complexExample)); window.requestAnimationFrame(() => promptInput.current?.focus()); }}>{t("Use this example")}</button>
        </aside>
      </header>
      <section className="scenario-intake panel">
        <div className="section-title">
          <span>01</span>
          <h2>{t("Customer scenario")}</h2>
          <span className="scenario-note">
            {provider.toUpperCase()} {t("plan")} · {t("local evidence")}
          </span>
        </div>
        <textarea
          ref={promptInput}
          value={prompt}
          onChange={(e) => setPrompt(e.target.value)}
          placeholder={t(
            "Example: The pentest used RDP lateral movement, PowerShell, DNS tunneling and data exfiltration, but the product did not alert.",
          )}
          rows={5}
        />
        <div className="scenario-provider-picker">
          <span>{t("Analysis provider")}</span>
          {(["gemini", "claude", "openai"] as ScenarioProvider[]).map(
            (name) => (
              <button
                type="button"
                key={name}
                className={`${provider === name ? "active" : ""} ${available(name) ? "available" : "unavailable"}`}
                disabled={busy || !available(name)}
                onClick={() => setProvider(name)}
              >
                <b>
                  {name === "openai"
                    ? "Codex / OpenAI"
                    : name[0].toUpperCase() + name.slice(1)}
                </b>
                <small>
                  {providerState(name)} · {modelConfig[name]?.model || t("Configure in Model Lab")}
                </small>
              </button>
            ),
          )}
        </div>
        <div className="scenario-actions">
          <button
            type="button"
            className="primary"
            // A transient live-health timeout must not make the primary
            // action unusable. The API performs the authoritative provider
            // configuration check and returns a clear error when needed.
            disabled={busy || prompt.trim().length < 10}
            onClick={() => void analyze()}
          >
            {busy ? t("Analyzing scenario…") : t("Assess detection readiness")}
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => {
              setPrompt("");
              setResult(null);
              setError("");
            }}
          >
            {t("Clear")}
          </button>
        </div>
        {busy && <div className="scenario-analysis-progress" role="status" aria-live="polite"><i /><div><b>{t("Detection readiness analysis is running…")}</b><span>{t("Complex scenarios can take up to a minute while the attack path and local catalogue evidence are verified.")} · {elapsedSeconds} sn</span></div></div>}
      </section>
      {error && <div className="error">{error}</div>}
      {result && (
        <div ref={resultAnchor} className="scenario-results">
          <section className="scenario-results-guide">
            <span>{t("ANALYSIS COMPLETE")}</span>
            <div><h2>{t("Continue with the verified rule candidates below")}</h2><p>{t("The scenario was separated into observable attack steps. You can inspect the matching catalogue rules below, open a rule's detail page, or add it to a rule pack for review.")}</p></div>
          </section>
          <section className="scenario-overview">
            <article className="panel scenario-summary">
              <span className="scenario-label">{t("ASSESSMENT")}</span>
              <h2>{t(`${result.status} detection readiness`)}</h2>
              <p>{prose(result.summary)}</p>
              <div className="scenario-stats">
                <div>
                  <b>{result.recommendations.length}</b>
                  <span>{t("verified candidates")}</span>
                </div>
                <div>
                  <b>{result.signals_extracted}</b>
                  <span>{t("signals extracted")}</span>
                </div>
                <div>
                  <b
                    className={`scenario-status-${result.status.toLowerCase()}`}
                  >
                    {t(result.status)}
                  </b>
                  <span>{t("coverage status")}</span>
                </div>
              </div>
              {result.assumptions.length > 0 && (
                <div className="scenario-assumptions">
                  <b>{t("Assumptions")}</b>
                  {result.assumptions.map((x, i) => (
                    <span key={`${x}-${i}`}>{prose(x)}</span>
                  ))}
                </div>
              )}
            </article>
            <article className="panel scenario-steps">
              <span className="scenario-label">{t("ATTACK PATH")}</span>
              <h2>{t("Verified behavioral checkpoints")}</h2>
              {result.steps.map((step) => (
                <div key={step.index}>
                  <i>{String(step.index).padStart(2, "0")}</i>
                  <span>
                    {prose(step.title)}
                    {step.technique_id && (
                      <small>
                        {step.technique_id} · {step.technique_name}
                      </small>
                    )}
                  </span>
                  <b className={`scenario-status-${step.status.toLowerCase()}`}>
                    {t(statusLabel(step.status))}
                  </b>
                </div>
              ))}
            </article>
          </section>
          <section className="panel scenario-coverage-matrix">
            <div className="panel-heading">
              <div>
                <span className="scenario-label">{t("COVERAGE MATRIX")}</span>
                <h2>{t("What the local catalogue can support")}</h2>
                <p>
                  {t(
                    "Coverage is computed from verified local mappings and evidence, not from Gemini claims.",
                  )}
                </p>
              </div>
            </div>
            {result.steps.map((step) => (
              <div className="scenario-matrix-row" key={step.index}>
                <div>
                  <b>{String(step.index).padStart(2, "0")}</b>
                  <span>{prose(step.title)}</span>
                </div>
                <strong
                  className={`scenario-status-${step.status.toLowerCase()}`}
                >
                  {t(statusLabel(step.status))}
                </strong>
                <small>
                  {step.evidence.map((item) => prose(item)).join(" ")}
                </small>
              </div>
            ))}
          </section>
          <section className="panel scenario-rules">
            <div className="panel-heading">
              <div>
                <span className="scenario-label">{t("RECOMMENDED RULES")}</span>
                <h2>{t("Rules to investigate and add to a pack")}</h2>
                <p>
                  {t(
                    "Every recommendation includes the local evidence used for its match.",
                  )}
                </p>
              </div>
              <strong>{result.recommendations.length}</strong>
            </div>
            {result.recommendations.length ? (
              result.recommendations.map((item) => (
                <div className="scenario-rule" key={`${item.sid}-${item.rev}`}>
                  <div>
                    <b>
                      SID {item.sid} · {item.match_type}
                    </b>
                    <span>{prose(item.message) || t("Untitled rule")}</span>
                    <small>
                      {prose(item.why)} ·{" "}
                      {item.mitre_id || t("MITRE unassigned")} ·{" "}
                      {item.category ? label(item.category) : t("Unclassified")}
                    </small>
                  </div>
                  <div className="scenario-rule-actions"><Link to={`/rules/${item.sid}`}>{t("Open rule")}</Link><AddToRulePack sid={item.sid} compact /></div>
                </div>
              ))
            ) : (
              <div className="empty">
                {t(
                  "No verified local candidates were found. Review the GAP rows and refine the scenario.",
                )}
              </div>
            )}
          </section>
        </div>
      )}
    </div>
  );
}
