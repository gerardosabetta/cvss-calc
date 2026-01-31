import { useState, useMemo } from "react";

type MetricKey = "AV" | "AC" | "PR" | "UI" | "S" | "C" | "I" | "A";

interface MetricOption {
  label: string;
  abbrev: string;
  value: number | null;
}

interface MetricGroup {
  key: MetricKey;
  name: string;
  options: MetricOption[];
}

const metrics: MetricGroup[] = [
  {
    key: "AV",
    name: "Attack Vector",
    options: [
      { label: "Network", abbrev: "N", value: 0.85 },
      { label: "Adjacent", abbrev: "A", value: 0.62 },
      { label: "Local", abbrev: "L", value: 0.55 },
      { label: "Physical", abbrev: "P", value: 0.2 },
    ],
  },
  {
    key: "AC",
    name: "Attack Complexity",
    options: [
      { label: "Low", abbrev: "L", value: 0.77 },
      { label: "High", abbrev: "H", value: 0.44 },
    ],
  },
  {
    key: "PR",
    name: "Privileges Required",
    options: [
      { label: "None", abbrev: "N", value: 0.85 },
      { label: "Low", abbrev: "L", value: 0.62 },
      { label: "High", abbrev: "H", value: 0.27 },
    ],
  },
  {
    key: "UI",
    name: "User Interaction",
    options: [
      { label: "None", abbrev: "N", value: 0.85 },
      { label: "Required", abbrev: "R", value: 0.62 },
    ],
  },
  {
    key: "S",
    name: "Scope",
    options: [
      { label: "Unchanged", abbrev: "U", value: 0 },
      { label: "Changed", abbrev: "C", value: 1 },
    ],
  },
  {
    key: "C",
    name: "Confidentiality",
    options: [
      { label: "None", abbrev: "N", value: 0.0 },
      { label: "Low", abbrev: "L", value: 0.22 },
      { label: "High", abbrev: "H", value: 0.56 },
    ],
  },
  {
    key: "I",
    name: "Integrity",
    options: [
      { label: "None", abbrev: "N", value: 0.0 },
      { label: "Low", abbrev: "L", value: 0.22 },
      { label: "High", abbrev: "H", value: 0.56 },
    ],
  },
  {
    key: "A",
    name: "Availability",
    options: [
      { label: "None", abbrev: "N", value: 0.0 },
      { label: "Low", abbrev: "L", value: 0.22 },
      { label: "High", abbrev: "H", value: 0.56 },
    ],
  },
];

const PR_CHANGED: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };
const PR_UNCHANGED: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };

function roundUp(val: number): number {
  const r = Math.round(val * 100000);
  return r % 10 === 0 ? r / 100000 : (Math.floor(r / 10) + 1) / 10000;
}

function calcScore(sel: Record<MetricKey, string | null>) {
  for (const m of metrics) if (sel[m.key] === null) return null;

  const sc = sel.S === "C";
  const pr = sc ? PR_CHANGED[sel.PR!] : PR_UNCHANGED[sel.PR!];
  const v = (k: MetricKey) =>
    metrics.find((m) => m.key === k)!.options.find((o) => o.abbrev === sel[k])!
      .value!;

  const iss = 1 - (1 - v("C")) * (1 - v("I")) * (1 - v("A"));
  const impact = sc
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;

  const vec = `CVSS:3.1/${metrics
    .map((m) => `${m.key}:${sel[m.key]}`)
    .join("/")}`;
  if (impact <= 0) return { score: 0, severity: "None", vec };

  const expl = 8.22 * v("AV") * v("AC") * pr * v("UI");
  let score = roundUp(
    Math.min(sc ? 1.08 * (impact + expl) : impact + expl, 10)
  );
  score = Math.round(score * 10) / 10;

  const severity =
    score === 0
      ? "None"
      : score <= 3.9
      ? "Low"
      : score <= 6.9
      ? "Medium"
      : score <= 8.9
      ? "High"
      : "Critical";

  return { score, severity, vec };
}

function sevColor(s: string) {
  return s === "None"
    ? "#53b1a0"
    : s === "Low"
    ? "#f5c542"
    : s === "Medium"
    ? "#f59b42"
    : s === "High"
    ? "#e85d3a"
    : s === "Critical"
    ? "#cc2936"
    : "#8892a0";
}

function MetricButton({
  opt,
  isSelected,
  onSelect,
}: {
  opt: MetricOption;
  isSelected: boolean;
  onSelect: () => void;
}) {
  const [hovered, setHovered] = useState(false);

  return (
    <button
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      onClick={onSelect}
      style={{
        padding: "7px 16px",
        fontSize: 13,
        fontWeight: 500,
        borderRadius: 8,
        border: isSelected
          ? "1px solid #7f5af0"
          : "1px solid rgba(255,255,255,0.1)",
        background: isSelected
          ? "linear-gradient(135deg, rgba(127,90,240,0.25), rgba(44,181,232,0.15))"
          : hovered
          ? "rgba(255,255,255,0.08)"
          : "rgba(255,255,255,0.04)",
        color: isSelected ? "#c4b5fd" : "#a0a8b8",
        cursor: "pointer",
        transition: "all 0.2s ease",
        outline: "none",
        boxShadow: isSelected ? "0 0 12px rgba(127,90,240,0.2)" : "none",
      }}
    >
      {opt.label}
    </button>
  );
}

function Section({
  title,
  items,
  selected,
  onSelect,
}: {
  title: string;
  items: MetricGroup[];
  selected: Record<MetricKey, string | null>;
  onSelect: (key: MetricKey, abbrev: string) => void;
}) {
  return (
    <div
      style={{
        background: "rgba(255,255,255,0.03)",
        borderRadius: 14,
        border: "1px solid rgba(255,255,255,0.06)",
        padding: "24px 28px",
        marginBottom: 16,
        backdropFilter: "blur(12px)",
      }}
    >
      <div
        style={{
          fontSize: 12,
          fontWeight: 600,
          textTransform: "uppercase",
          color: "#7f5af0",
          letterSpacing: "1px",
          marginBottom: 20,
        }}
      >
        {title}
      </div>
      {items.map((m) => (
        <div
          key={m.key}
          style={{
            display: "flex",
            alignItems: "center",
            marginBottom: 14,
            gap: 16,
          }}
        >
          <span
            style={{
              width: 160,
              fontSize: 14,
              fontWeight: 500,
              color: "#c0c8d8",
              flexShrink: 0,
            }}
          >
            {m.name}
          </span>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            {m.options.map((opt) => (
              <MetricButton
                key={opt.abbrev}
                opt={opt}
                isSelected={selected[m.key] === opt.abbrev}
                onSelect={() => onSelect(m.key, opt.abbrev)}
              />
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

function App() {
  const [selected, setSelected] = useState<Record<MetricKey, string | null>>({
    AV: null,
    AC: null,
    PR: null,
    UI: null,
    S: null,
    C: null,
    I: null,
    A: null,
  });
  const [resetHovered, setResetHovered] = useState(false);

  const result = useMemo(() => calcScore(selected), [selected]);
  const allSelected = metrics.every((m) => selected[m.key] !== null);
  const color = result ? sevColor(result.severity) : "#8892a0";
  const vector = `CVSS:3.1/${metrics
    .map((m) => `${m.key}:${selected[m.key] ?? "X"}`)
    .join("/")}`;

  const handleSelect = (key: MetricKey, abbrev: string) =>
    setSelected((p) => ({ ...p, [key]: p[key] === abbrev ? null : abbrev }));

  const handleReset = () =>
    setSelected({
      AV: null,
      AC: null,
      PR: null,
      UI: null,
      S: null,
      C: null,
      I: null,
      A: null,
    });

  return (
    <div
      style={{
        minHeight: "100vh",
        background:
          "linear-gradient(135deg, #0f0c29 0%, #1a1a3e 50%, #24243e 100%)",
        fontFamily:
          "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
        color: "#e0e0e0",
        display: "flex",
        justifyContent: "center",
        alignItems: "flex-start",
        padding: "40px 20px",
      }}
    >
      <div style={{ maxWidth: 720, width: "100%" }}>
        <div style={{ textAlign: "center", marginBottom: 36 }}>
          <h1
            style={{
              fontSize: 32,
              fontWeight: 700,
              margin: 0,
              background: "linear-gradient(90deg, #7f5af0, #2cb5e8)",
              WebkitBackgroundClip: "text",
              WebkitTextFillColor: "transparent",
              letterSpacing: "-0.5px",
            }}
          >
            CVSS 3.1 Calculator
          </h1>
          <p
            style={{
              fontSize: 14,
              color: "#8892a0",
              marginTop: 6,
              fontWeight: 400,
            }}
          >
            Common Vulnerability Scoring System v3.1
          </p>
        </div>

        <div
          style={{
            background: "rgba(255,255,255,0.04)",
            borderRadius: 16,
            border: "1px solid rgba(255,255,255,0.08)",
            padding: "28px 32px",
            marginBottom: 28,
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            backdropFilter: "blur(12px)",
            gap: 24,
          }}
        >
          <div
            style={{
              width: 96,
              height: 96,
              borderRadius: "50%",
              border: `3px solid ${color}`,
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              justifyContent: "center",
              flexShrink: 0,
              background: `radial-gradient(circle, ${color}15 0%, transparent 70%)`,
              transition: "all 0.3s ease",
            }}
          >
            <span
              style={{
                fontSize: 32,
                fontWeight: 700,
                color: color,
                lineHeight: 1,
                transition: "color 0.3s ease",
              }}
            >
              {allSelected && result ? result.score.toFixed(1) : "—"}
            </span>
            <span
              style={{
                fontSize: 11,
                fontWeight: 600,
                textTransform: "uppercase",
                color: color,
                marginTop: 4,
                letterSpacing: "0.5px",
                transition: "color 0.3s ease",
              }}
            >
              {allSelected && result ? result.severity : "N/A"}
            </span>
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div
              style={{
                fontSize: 11,
                fontWeight: 600,
                textTransform: "uppercase",
                color: "#8892a0",
                letterSpacing: "0.5px",
                marginBottom: 6,
              }}
            >
              Vector String
            </div>
            <div
              style={{
                fontSize: 13,
                fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
                color: "#b0b8c8",
                wordBreak: "break-all",
                lineHeight: 1.6,
                background: "rgba(0,0,0,0.2)",
                padding: "10px 14px",
                borderRadius: 8,
                border: "1px solid rgba(255,255,255,0.06)",
              }}
            >
              {vector}
            </div>
          </div>
        </div>

        <Section
          title="Exploitability Metrics"
          items={metrics.slice(0, 4)}
          selected={selected}
          onSelect={handleSelect}
        />
        <Section
          title="Scope"
          items={metrics.slice(4, 5)}
          selected={selected}
          onSelect={handleSelect}
        />
        <Section
          title="Impact Metrics"
          items={metrics.slice(5, 8)}
          selected={selected}
          onSelect={handleSelect}
        />

        <button
          onMouseEnter={() => setResetHovered(true)}
          onMouseLeave={() => setResetHovered(false)}
          onClick={handleReset}
          style={{
            display: "block",
            margin: "24px auto 0",
            padding: "10px 28px",
            fontSize: 13,
            fontWeight: 600,
            color: resetHovered ? "#e0e0e0" : "#8892a0",
            background: "rgba(255,255,255,0.05)",
            border: resetHovered
              ? "1px solid rgba(255,255,255,0.2)"
              : "1px solid rgba(255,255,255,0.1)",
            borderRadius: 8,
            cursor: "pointer",
            transition: "all 0.2s ease",
          }}
        >
          Reset All
        </button>
      </div>
    </div>
  );
}

export default App;
