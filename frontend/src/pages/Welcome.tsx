import { useNavigate } from "react-router-dom";
import { useI18n } from "../i18n";

function CatalogMark() {
  return (
    <svg
      className="welcome-mark"
      viewBox="0 0 180 180"
      role="img"
      aria-label="Surricatalog"
    >
      <defs>
        <linearGradient id="welcome-gold" x1="0" x2="1">
          <stop offset="0" stopColor="#d6bd79" />
          <stop offset="1" stopColor="#70e0ad" />
        </linearGradient>
        <filter id="welcome-glow">
          <feGaussianBlur stdDeviation="3" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>
      <circle className="welcome-orbit orbit-one" cx="90" cy="90" r="76" />
      <circle className="welcome-orbit orbit-two" cx="90" cy="90" r="62" />
      <path
        d="M90 18 145 39v47c0 38-23 62-55 76C58 148 35 124 35 86V39Z"
        fill="#10241f"
        stroke="url(#welcome-gold)"
        strokeWidth="3"
      />
      <path
        d="M55 89c10-18 23-27 35-27s25 9 35 27c-10 18-23 27-35 27S65 107 55 89Z"
        fill="#0a1517"
        stroke="#70e0ad"
        strokeWidth="2"
      />
      <circle
        cx="90"
        cy="89"
        r="13"
        fill="#d6bd79"
        filter="url(#welcome-glow)"
      />
      <circle cx="90" cy="89" r="6" fill="#0b1718" />
      <path
        d="M90 48v14M90 116v15M49 89h14M117 89h14"
        stroke="#d6bd79"
        strokeWidth="2"
        strokeLinecap="round"
        opacity=".8"
      />
      <path
        d="m71 133 19 10 19-10"
        fill="none"
        stroke="#70e0ad"
        strokeWidth="2"
        opacity=".8"
      />
    </svg>
  );
}

export function Welcome() {
  const navigate = useNavigate();
  const { locale } = useI18n();
  const isTurkish = locale === "tr";

  return (
    <div className="welcome-page">
      <div className="welcome-grain" aria-hidden="true" />
      <div className="welcome-orbit-lines" aria-hidden="true">
        <i />
        <i />
        <i />
      </div>
      <header className="welcome-header">
        <span className="welcome-status">
          <i /> {isTurkish ? "GÜVENLİ ÇALIŞMA ALANI" : "SECURE WORKSPACE"}
        </span>
        <span className="welcome-version">FIELD EDITION · 01</span>
      </header>
      <main className="welcome-main">
        <div className="welcome-brand">
          <CatalogMark />
          <div className="welcome-wordmark">
            <span className="welcome-eyebrow">
              {isTurkish
                ? "SURICATA TESPİT İSTİHBARATI"
                : "SURICATA DETECTION INTELLIGENCE"}
            </span>
            <h1>Surricatalog</h1>
            <p>for cybersecurity</p>
          </div>
        </div>
        <div className="welcome-rule" aria-hidden="true">
          <span />
          <b>✦</b>
          <span />
        </div>
        <p className="welcome-intro">
          {isTurkish
            ? "Suricata kurallarını, MITRE bağlamını ve ürün kararlarını tek bir mühendislik çalışma alanında keşfedin."
            : "Explore Suricata rules, MITRE context and product decisions in one considered engineering workspace."}
        </p>
        <button className="welcome-enter" onClick={() => navigate("/catalog")}>
          <span>
            {isTurkish ? "Detection Catalog'a gir" : "Enter Detection Catalog"}
          </span>
          <b>↗</b>
        </button>
        <p className="welcome-note">
          {isTurkish
            ? "Kimlik bilgisi gerekmez · Çalışma alanı yerel katalogla açılır"
            : "No credentials required · Opens your local detection catalogue"}
        </p>
      </main>
      <footer className="welcome-footer">
        <span>
          FASTAPI <b>×</b> SQLITE <b>×</b> REACT
        </span>
        <span>
          {isTurkish ? "KURAL · KANIT · KARAR" : "RULE · EVIDENCE · DECISION"}
        </span>
      </footer>
    </div>
  );
}
