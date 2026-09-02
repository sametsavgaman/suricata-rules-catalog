import { BrowserRouter, Route, Routes } from "react-router-dom";
import { Dashboard } from "./pages/Dashboard";
import { RuleDetail } from "./pages/RuleDetail";

export default function App() {
  return <BrowserRouter><main className="shell"><Routes><Route path="/" element={<Dashboard/>}/><Route path="/rules" element={<Dashboard/>}/><Route path="/rules/:sid" element={<RuleDetail/>}/></Routes></main></BrowserRouter>;
}
