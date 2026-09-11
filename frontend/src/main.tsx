import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import "./styles.css";
import "./docs.css";
import "./catalog-visuals.css";
import "./heritage-theme.css";
import "./compare-theme.css";
import "./welcome.css";
import "./button-theme.css";
import "./audit-theme.css";
import { I18nProvider } from "./i18n";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <I18nProvider>
      <App />
    </I18nProvider>
  </StrictMode>,
);
