import { BrowserRouter, Route, Routes, useLocation } from "react-router-dom";
import { useEffect } from "react";
import { Dashboard } from "./pages/Dashboard";
import { RuleDetail } from "./pages/RuleDetail";
import { ModelLab } from "./pages/ModelLab";
import { CatalogOverview } from "./pages/CatalogOverview";
import { MitreCatalog } from "./pages/MitreCatalog";
import { MitreTechniqueDetail } from "./pages/MitreTechniqueDetail";
import { Documentation } from "./pages/Documentation";
import { DetectionFamilies } from "./pages/DetectionFamilies";
import { FamilyDetail } from "./pages/FamilyDetail";
import { MitreCoverage } from "./pages/MitreCoverage";
import { CompareRules } from "./pages/CompareRules";
import { RulePackBuilder } from "./pages/RulePackBuilder";
import { ScenarioCoverage } from "./pages/ScenarioCoverage";
import { LanguageSwitcher, useI18n } from "./i18n";
import { ExistingRules } from "./pages/ExistingRules";
import { Welcome } from "./pages/Welcome";
import { warmAppCache } from "./services/api";
import { AuditLog } from "./pages/AuditLog";
function AppFrame() {
  const { t } = useI18n();
  const { pathname } = useLocation();
  useEffect(() => {
    const timer = window.setTimeout(() => {
      void warmAppCache();
    }, 0);
    return () => window.clearTimeout(timer);
  }, []);
  const rulesRoute =
    pathname === "/rules" ||
    pathname.startsWith("/rules/") ||
    pathname === "/catalog/rules" ||
    pathname.startsWith("/catalog/rules/");
  const welcomeRoute = pathname === "/";
  const isActive = (section: string) => {
    if (section === "catalog") return pathname === "/catalog";
    if (section === "rules")
      return (
        pathname === "/rules" ||
        pathname.startsWith("/rules/") ||
        pathname === "/catalog/rules" ||
        pathname.startsWith("/catalog/rules/")
      );
    if (section === "/catalog/mitre")
      return (
        pathname === "/catalog/mitre" ||
        pathname.startsWith("/catalog/mitre/") ||
        pathname === "/catalog/coverage"
      );
    return pathname === section || pathname.startsWith(section + "/");
  };
  return (
    <main
      className={`shell ${rulesRoute ? "rules-route" : "catalogue-route"} ${welcomeRoute ? "welcome-shell" : ""}`}
    >
      {!welcomeRoute && (
        <nav className="app-nav">
          <a
            className={isActive("catalog") ? "active" : undefined}
            href="/catalog"
          >
            {t("Detection Catalog")}
          </a>
          <a
            className={isActive("/catalog/families") ? "active" : undefined}
            href="/catalog/families"
          >
            {t("Families")}
          </a>
          <a
            className={isActive("rules") ? "active" : undefined}
            href="/catalog/rules"
          >
            {t("Rules")}
          </a>
          <a
            className={isActive("/catalog/mitre") ? "active" : undefined}
            href="/catalog/mitre"
          >
            {t("MITRE Intelligence")}
          </a>
          <a
            className={isActive("/catalog/existing") ? "active" : undefined}
            href="/catalog/existing"
          >
            {t("Existing Rules")}
          </a>
          <a
            className={isActive("/catalog/scenarios") ? "active" : undefined}
            href="/catalog/scenarios"
          >
            {t("Detection Readiness")}
          </a>
          <a
            className={isActive("/catalog/compare") ? "active" : undefined}
            href="/catalog/compare"
          >
            {t("Compare")}
          </a>
          <a
            className={isActive("/catalog/rule-packs") ? "active" : undefined}
            href="/catalog/rule-packs"
          >
            {t("Rule Packs")}
          </a>
          <a
            className={isActive("/models") ? "active" : undefined}
            href="/models"
          >
            {t("Model Lab")}
          </a>
          <a className={isActive("/docs") ? "active" : undefined} href="/docs">
            {t("Docs")}
          </a>
          <a className={isActive("/audit-log") ? "active" : undefined} href="/audit-log">
            {t("Audit Log")}
          </a>
          <LanguageSwitcher />
        </nav>
      )}
      <Routes>
        <Route path="/" element={<Welcome />} />
        <Route path="/catalog" element={<CatalogOverview />} />
        <Route path="/rules" element={<Dashboard />} />
        <Route path="/catalog/rules" element={<Dashboard />} />
        <Route path="/catalog/families" element={<DetectionFamilies />} />
        <Route path="/catalog/families/:slug" element={<FamilyDetail />} />
        <Route path="/catalog/mitre" element={<MitreCatalog />} />
        <Route path="/catalog/coverage" element={<MitreCoverage />} />
        <Route path="/catalog/compare" element={<CompareRules />} />
        <Route path="/catalog/scenarios" element={<ScenarioCoverage />} />
        <Route path="/catalog/rule-packs" element={<RulePackBuilder />} />
        <Route path="/catalog/existing" element={<ExistingRules />} />
        <Route
          path="/catalog/mitre/:techniqueId"
          element={<MitreTechniqueDetail />}
        />
        <Route path="/rules/:sid" element={<RuleDetail />} />
        <Route path="/catalog/rules/:sid" element={<RuleDetail />} />
        <Route path="/models" element={<ModelLab />} />
        <Route path="/docs" element={<Documentation />} />
        <Route path="/audit-log" element={<AuditLog />} />
      </Routes>
    </main>
  );
}
export default function App() {
  return (
    <BrowserRouter>
      <AppFrame />
    </BrowserRouter>
  );
}
