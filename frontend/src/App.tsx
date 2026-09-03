import { BrowserRouter, Route, Routes } from "react-router-dom";
import { Dashboard } from "./pages/Dashboard";
import { RuleDetail } from "./pages/RuleDetail";
import { ModelLab } from "./pages/ModelLab";

export default function App() {
  return <BrowserRouter><main className="shell"><nav className="app-nav"><a href="/">Rule Explorer</a><a href="/models">Model Lab</a></nav><Routes><Route path="/" element={<Dashboard/>}/><Route path="/rules" element={<Dashboard/>}/><Route path="/rules/:sid" element={<RuleDetail/>}/><Route path="/models" element={<ModelLab/>}/></Routes></main></BrowserRouter>;
}
