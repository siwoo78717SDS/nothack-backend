import React, { useEffect, useMemo, useState } from "react";

const WDQS_ENDPOINT = "https://query.wikidata.org/sparql";
const FACTS_CACHE_KEY = "historyFacts1000_cache_react_v1";
const CACHE_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;

function formatWikidataDate(iso) {
  const m = String(iso).match(/^(-?\d{1,6})-(\d{2})-(\d{2})/);
  if (!m) return String(iso);

  const year = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3]);

  const monthNames = [
    "January","February","March","April","May","June",
    "July","August","September","October","November","December"
  ];
  const mm = monthNames[month - 1] || `Month ${month}`;

  if (year <= 0) return `${mm} ${day}, ${1 - year} BCE`;
  return `${mm} ${day}, ${year}`;
}

function toFactLine(row) {
  const dateIso = row?.date?.value || "";
  const label = row?.eventLabel?.value || "Unknown event";
  const desc = row?.eventDescription?.value || "";
  const dateText = dateIso ? formatWikidataDate(dateIso) : "Unknown date";
  return desc ? `On ${dateText}, ${label} — ${desc}.` : `On ${dateText}, ${label}.`;
}

async function fetchFacts1000() {
  const sparql = `
PREFIX wd: <http://www.wikidata.org/entity/>
PREFIX wdt: <http://www.wikidata.org/prop/direct/>
PREFIX wikibase: <http://wikiba.se/ontology#>
PREFIX bd: <http://www.bigdata.com/rdf#>
PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>

SELECT ?eventLabel ?eventDescription ?date WHERE {
  {
    SELECT ?event ?date WHERE {
      ?event wdt:P31/wdt:P279* wd:Q1190554 .
      OPTIONAL { ?event wdt:P585 ?date . }
      OPTIONAL { ?event wdt:P580 ?date . }
      FILTER(BOUND(?date) && DATATYPE(?date) = xsd:dateTime)
    }
    ORDER BY DESC(?date)
    LIMIT 1000
  }
  SERVICE wikibase:label { bd:serviceParam wikibase:language "en". }
}
`;
  const url = `${WDQS_ENDPOINT}?format=json&query=${encodeURIComponent(sparql)}`;
  const res = await fetch(url, { headers: { Accept: "application/sparql-results+json" } });
  if (!res.ok) throw new Error(`Wikidata request failed: ${res.status} ${res.statusText}`);

  const json = await res.json();
  const bindings = json?.results?.bindings || [];
  return bindings.map(toFactLine).filter(Boolean).slice(0, 1000);
}

function HistoryFactsDoc({ onBack }) {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [facts, setFacts] = useState([]);

  async function load({ forceRefresh = false } = {}) {
    setLoading(true);
    setError("");

    try {
      if (!forceRefresh) {
        const raw = localStorage.getItem(FACTS_CACHE_KEY);
        if (raw) {
          const cached = JSON.parse(raw);
          const okAge = Date.now() - (cached?.savedAt || 0) < CACHE_MAX_AGE_MS;
          if (okAge && Array.isArray(cached?.facts) && cached.facts.length) {
            setFacts(cached.facts);
            setLoading(false);
            return;
          }
        }
      }

      const fresh = await fetchFacts1000();
      setFacts(fresh);
      localStorage.setItem(FACTS_CACHE_KEY, JSON.stringify({ savedAt: Date.now(), facts: fresh }));
    } catch (e) {
      setError(String(e?.message || e));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  const text = useMemo(
    () => facts.map((f, i) => `${i + 1}. ${f}`).join("\n"),
    [facts]
  );

  const btnStyle = {
    padding: "6px 10px",
    background: "#f6f6f6",
    border: "1px solid #d8d8d8",
    color: "#111",
    cursor: "pointer",
    fontFamily: "inherit",
    marginRight: "8px"
  };

  return (
    <div style={{ minHeight: "100vh", background: "#fff", padding: "24px 12px" }}>
      <div
        style={{
          width: "min(900px, 100%)",
          margin: "0 auto",
          border: "1px solid #e6e6e6",
          padding: "34px 40px",
          fontFamily: '"Times New Roman", Times, serif',
          color: "#000",
          background: "#fff"
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", gap: 12, flexWrap: "wrap", alignItems: "flex-start" }}>
          <div>
            <h1 style={{ margin: 0, fontSize: 28, fontWeight: 700 }}>History Facts</h1>
            <div style={{ marginTop: 6, color: "#444", fontSize: 14 }}>
              {loading ? "Loading 1000 facts…" : `${facts.length} facts`}
            </div>
          </div>

          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <button onClick={onBack} style={btnStyle}>Back</button>
            <button onClick={() => load({ forceRefresh: true })} style={btnStyle}>Refresh</button>
            <button onClick={() => window.print()} style={btnStyle}>Print</button>
          </div>
        </div>

        <hr style={{ margin: "16px 0", border: "none", borderTop: "1px solid #e6e6e6" }} />

        {loading && <div style={{ fontSize: 16, color: "#222" }}>Searching and loading facts…</div>}

        {!loading && error && (
          <div style={{ border: "1px solid #ffb3b3", background: "#fff5f5", padding: 12 }}>
            <b>Could not load facts</b>
            <div style={{ whiteSpace: "pre-wrap", marginTop: 6, fontSize: 14 }}>{error}</div>
          </div>
        )}

        {!loading && !error && (
          <pre style={{ margin: 0, fontSize: 16, lineHeight: 1.45, whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
            {text}
          </pre>
        )}
      </div>
    </div>
  );
}

export default function HomePage() {
  const [view, setView] = useState("hack");
  const [lines, setLines] = useState([]);

  useEffect(() => {
    const handler = (e) => {
      const tag = (e.target?.tagName || "").toLowerCase();
      const typing = tag === "input" || tag === "textarea" || e.target?.isContentEditable;
      if (typing) return;

      const isH = e.key === "H" || e.key === "h" || e.code === "KeyH";
      if (e.shiftKey && isH) {
        e.preventDefault();
        setView("facts");
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  const handleStart = () => {
    const now = new Date();
    const tz = Intl.DateTimeFormat().resolvedOptions().timeZone || "unknown";
    const boot = [
      "[BOOT] Initializing simulation…",
      `[TIME] ${now.toISOString()}`,
      `[ZONE] ${tz}`,
      "[OK] Local demo mode enabled (no real access).",
      "[SCAN] Simulating system checks…",
      "[OK] UI online.",
      "[TIP] Press Shift+H for History Facts (1000)."
    ];
    setLines(boot);
  };

  const handleClear = () => setLines([]);

  const handleHelp = () => {
    setLines(prev => [...prev, "[HELP] Shift+H opens the History Facts document page."]);
  };

  const btnStyle = {
    cursor: "pointer",
    background: "transparent",
    color: "#39ff14",
    border: "1px solid rgba(57,255,20,.28)",
    padding: "10px 12px",
    fontFamily: "inherit",
    fontSize: "14px",
    marginRight: "8px"
  };

  if (view === "facts") return <HistoryFactsDoc onBack={() => setView("hack")} />;

  return (
    <div style={{ minHeight: "100vh", background: "#000", color: "#39ff14", padding: 18 }}>
      <div style={{ maxWidth: 1000, margin: "0 auto" }}>
        <div style={{ fontSize: 26, margin: "10px 0", textShadow: "0 0 16px rgba(57,255,20,.20)" }}>
          Cyber Terminal Simulator
        </div>
        <div style={{ color: "rgba(57,255,20,.75)", marginBottom: 16, lineHeight: 1.4 }}>
          This is a harmless terminal animation (no real hacking). Press <b>Shift + H</b> to open the "History Facts" document (1000 facts).
        </div>

        <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 14 }}>
          <button onClick={handleStart} style={btnStyle}>Start</button>
          <button onClick={handleClear} style={btnStyle}>Clear</button>
          <button onClick={handleHelp} style={btnStyle}>Help</button>
        </div>

        <div
          style={{
            border: "1px solid rgba(57,255,20,.28)",
            background: "rgba(0,0,0,.35)",
            padding: 12,
            height: 340,
            overflow: "auto",
            whiteSpace: "pre-wrap",
            lineHeight: 1.35,
            fontFamily: "inherit",
            fontSize: "14px"
          }}
        >
          {lines.length > 0 ? lines.join("\n") : ""}
        </div>

        <div style={{ marginTop: 10, fontSize: 12, color: "rgba(57,255,20,.7)" }}>
          Tip: Shift+H works anywhere (as long as you're not typing in an input).
        </div>
      </div>
    </div>
  );
}
