import { BrowserRouter, Route, Routes } from "react-router-dom";
import { Dashboard } from "./pages/Dashboard";
import { RuleDetail } from "./pages/RuleDetail";
import { ModelLab } from "./pages/ModelLab";
import { CatalogOverview } from "./pages/CatalogOverview";
import { Candidates } from "./pages/Candidates";
import { MitreCatalog } from "./pages/MitreCatalog";
import { Documentation } from "./pages/Documentation";

export default function App() {
  return <BrowserRouter><main className="shell"><nav className="app-nav"><a href="/catalog">Detection Catalog</a><a href="/catalog/rules">Rules</a><a href="/catalog/candidates?status=CANDIDATE">Candidates</a><a href="/catalog/mitre">MITRE</a><a href="/models">Model Lab</a><a href="/docs">Docs</a></nav><Routes><Route path="/" element={<CatalogOverview/>}/><Route path="/catalog" element={<CatalogOverview/>}/><Route path="/rules" element={<Dashboard/>}/><Route path="/catalog/rules" element={<Dashboard/>}/><Route path="/catalog/candidates" element={<Candidates/>}/><Route path="/catalog/mitre" element={<MitreCatalog/>}/><Route path="/rules/:sid" element={<RuleDetail/>}/><Route path="/catalog/rules/:sid" element={<RuleDetail/>}/><Route path="/models" element={<ModelLab/>}/><Route path="/docs" element={<Documentation/>}/></Routes></main></BrowserRouter>;
}
