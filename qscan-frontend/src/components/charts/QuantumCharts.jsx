import React from "react";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
  PieChart, Pie, Cell, ResponsiveContainer,
  AreaChart, Area, ReferenceLine, Label,
} from "recharts";
import { motion } from "framer-motion";
import "./quantum_charts.css";


/* ─────────────────────────────────────────────────────────
   1. CRQC Algorithm Vulnerability Timeline
   Shows WHEN each algorithm becomes breakable by quantum.
   Highlights the algorithms YOUR asset actually uses.
   ───────────────────────────────────────────────────────── */

const CRQC_DATA = [
  { algorithm: "RSA-2048", yearsToBreak: 7, safe: false },
  { algorithm: "RSA-4096", yearsToBreak: 8, safe: false },
  { algorithm: "DH", yearsToBreak: 7, safe: false },
  { algorithm: "DHE", yearsToBreak: 7, safe: false },
  { algorithm: "ECDHE", yearsToBreak: 9, safe: false },
  { algorithm: "ECDSA", yearsToBreak: 9, safe: false },
  { algorithm: "X25519", yearsToBreak: 9, safe: false },
  { algorithm: "ML-KEM", yearsToBreak: 50, safe: true },
  { algorithm: "ML-DSA", yearsToBreak: 50, safe: true },
  { algorithm: "SLH-DSA", yearsToBreak: 50, safe: true },
];

export function CRQCTimelineChart({ detectedAlgorithms = [] }) {
  const currentYear = new Date().getFullYear();
  const detected = detectedAlgorithms.map(a => a.toUpperCase());

  const data = CRQC_DATA.map(item => ({
    ...item,
    breakYear: currentYear + item.yearsToBreak,
    isDetected: detected.some(d =>
      item.algorithm.toUpperCase().includes(d) || d.includes(item.algorithm.toUpperCase())
    ),
    displayYears: Math.min(item.yearsToBreak, 25),
  }));

  const CustomTooltip = ({ active, payload }) => {
    if (!active || !payload?.length) return null;
    const d = payload[0].payload;
    return (
      <div className="chart-tooltip">
        <p className="tooltip-title">{d.algorithm}</p>
        <p>Vulnerable in: <strong>{d.safe ? "Not vulnerable" : `${d.yearsToBreak} years (${d.breakYear})`}</strong></p>
        <p>Status: <strong style={{ color: d.safe ? "#0ffd" : d.isDetected ? "#ff3b5c" : "#ffa726" }}>
          {d.safe ? "Quantum Safe" : d.isDetected ? "⚠ IN USE — Vulnerable" : "Vulnerable"}
        </strong></p>
      </div>
    );
  };

  return (
    <motion.div
      className="chart-card"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.6, delay: 0.1 }}
    >
      <h4>CRQC Algorithm Vulnerability Timeline</h4>
      <p className="chart-subtitle">
        Years until a Cryptographically Relevant Quantum Computer can break each algorithm
        <br /><small>Source: NIST IR 8547 • Red = Detected in your infrastructure</small>
      </p>
      <ResponsiveContainer width="100%" height={320}>
        <BarChart data={data} margin={{ top: 10, right: 30, left: 0, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
          <XAxis
            dataKey="algorithm"
            tick={{ fill: "#94a3b8", fontSize: 11 }}
            angle={-35}
            textAnchor="end"
            height={60}
          />
          <YAxis
            tick={{ fill: "#94a3b8", fontSize: 12 }}
            label={{ value: "Years to CRQC", angle: -90, position: "insideLeft", fill: "#94a3b8" }}
            domain={[0, 28]}
          />
          <Tooltip content={<CustomTooltip />} />
          <ReferenceLine y={10} stroke="#ff3b5c" strokeDasharray="5 5">
            <Label value="Mosca Danger Zone (X+Y=10)" position="top" fill="#ff3b5c" fontSize={11} />
          </ReferenceLine>
          <Bar dataKey="displayYears" radius={[4, 4, 0, 0]}>
            {data.map((entry, i) => (
              <Cell
                key={i}
                fill={
                  entry.safe ? "#0ffda1"
                    : entry.isDetected ? "#ff3b5c"
                    : "#ffa726"
                }
                opacity={entry.isDetected ? 1 : 0.6}
                stroke={entry.isDetected ? "#ff3b5c" : "none"}
                strokeWidth={entry.isDetected ? 2 : 0}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </motion.div>
  );
}


/* ─────────────────────────────────────────────────────────
   2. Crypto Posture Radar
   Scores the asset across 6 security dimensions.
   ───────────────────────────────────────────────────────── */

function computeRadarData(cbom) {
  const assets = cbom?.crypto_assets || [];
  if (assets.length === 0) return [];

  let tlsScore = 0, kexScore = 0, fsScore = 0;
  let cipherScore = 0, certScore = 0, pqcScore = 0;

  for (const asset of assets) {
    const tls = asset?.tls_configuration?.protocol_version || asset?.tls_version || "";
    const cipher = asset?.tls_configuration?.negotiated_cipher || asset?.cipher_suite || "";
    const pqc = asset?.pqcClassification?.status || asset?.quantum_assessment?.pqc_status;
    const fs = asset?.cipher_analysis?.forward_secrecy;
    const daysExpiry = asset?.certificate_info?.validity?.days_until_expiry ?? asset?.formattedCert?.daysUntilExpiry;
    const bits = asset?.tls_configuration?.cipher_strength_bits;

    // TLS Version (0-100)
    if (tls.includes("1.3")) tlsScore += 100;
    else if (tls.includes("1.2")) tlsScore += 60;
    else if (tls.includes("1.1")) tlsScore += 20;
    else tlsScore += 10;

    // Key Exchange (0-100)
    if (pqc === "PQC_READY") kexScore += 100;
    else if (pqc === "HYBRID_PQC") kexScore += 75;
    else kexScore += 25;

    // Forward Secrecy (0-100)
    fsScore += fs ? 100 : 0;

    // Cipher Strength (0-100)
    if (bits >= 256) cipherScore += 100;
    else if (bits >= 128) cipherScore += 60;
    else cipherScore += 20;

    // Certificate Health (0-100)
    if (daysExpiry > 180) certScore += 100;
    else if (daysExpiry > 90) certScore += 70;
    else if (daysExpiry > 30) certScore += 40;
    else certScore += 10;

    // PQC Readiness (0-100)
    if (pqc === "PQC_READY") pqcScore += 100;
    else if (pqc === "HYBRID_PQC") pqcScore += 60;
    else if (pqc === "MIGRATION_NEEDED") pqcScore += 20;
    else pqcScore += 5;
  }

  const n = assets.length;
  return [
    { dimension: "TLS Version", score: Math.round(tlsScore / n), fullMark: 100 },
    { dimension: "Key Exchange", score: Math.round(kexScore / n), fullMark: 100 },
    { dimension: "Forward Secrecy", score: Math.round(fsScore / n), fullMark: 100 },
    { dimension: "Cipher Strength", score: Math.round(cipherScore / n), fullMark: 100 },
    { dimension: "Certificate Health", score: Math.round(certScore / n), fullMark: 100 },
    { dimension: "PQC Readiness", score: Math.round(pqcScore / n), fullMark: 100 },
  ];
}

export function CryptoPostureRadar({ cbom }) {
  const data = computeRadarData(cbom);
  if (data.length === 0) return null;

  const avgScore = Math.round(data.reduce((s, d) => s + d.score, 0) / data.length);
  const posture = avgScore >= 70 ? "Strong" : avgScore >= 40 ? "Moderate" : "Weak";
  const postureColor = avgScore >= 70 ? "#0ffda1" : avgScore >= 40 ? "#ffa726" : "#ff3b5c";

  return (
    <motion.div
      className="chart-card"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.6, delay: 0.2 }}
    >
      <h4>Cryptographic Posture Analysis</h4>
      <p className="chart-subtitle">
        Multi-dimensional security assessment •
        Overall: <span style={{ color: postureColor, fontWeight: "bold" }}>{posture} ({avgScore}/100)</span>
      </p>
      <ResponsiveContainer width="100%" height={350}>
        <RadarChart cx="50%" cy="50%" outerRadius="70%" data={data}>
          <PolarGrid stroke="rgba(255,255,255,0.1)" />
          <PolarAngleAxis
            dataKey="dimension"
            tick={{ fill: "#94a3b8", fontSize: 11 }}
          />
          <PolarRadiusAxis
            angle={30}
            domain={[0, 100]}
            tick={{ fill: "#94a3b8", fontSize: 10 }}
          />
          <Radar
            name="Your Posture"
            dataKey="score"
            stroke="#0ffda1"
            fill="#0ffda1"
            fillOpacity={0.2}
            strokeWidth={2}
          />
          <Radar
            name="Ideal (PQC Ready)"
            dataKey="fullMark"
            stroke="#3b82f6"
            fill="none"
            strokeDasharray="5 5"
            strokeWidth={1}
          />
          <Legend wrapperStyle={{ color: "#94a3b8", fontSize: 12 }} />
          <Tooltip
            contentStyle={{
              background: "rgba(5,11,24,0.95)",
              border: "1px solid rgba(15,253,209,0.3)",
              borderRadius: "8px",
              color: "#e2e8f0",
            }}
          />
        </RadarChart>
      </ResponsiveContainer>
    </motion.div>
  );
}


/* ─────────────────────────────────────────────────────────
   3. Mosca Breach Timeline Visualization
   Shows data capture, shelf-life, and CRQC arrival on a
   timeline — makes the breach window intuitive.
   ───────────────────────────────────────────────────────── */

export function MoscaTimelineChart({ hndlData }) {
  if (!hndlData || hndlData.urgency === "NONE") return null;

  const currentYear = hndlData.current_year || new Date().getFullYear();
  const X = hndlData.migration_years_x || 3;
  const Y = hndlData.data_life_years_y || 7;
  const Z = hndlData.crqc_timeline_years || 10;

  // Build timeline from currentYear-1 to currentYear+max(X+Y, Z)+2
  const startYear = currentYear - 1;
  const endYear = currentYear + Math.max(X + Y, Z) + 2;

  const data = [];
  for (let year = startYear; year <= endYear; year++) {
    const elapsed = year - currentYear;

    data.push({
      year,
      migrationWindow: (elapsed >= 0 && elapsed <= X) ? 80 : 0,
      dataAtRisk: (elapsed >= 0 && elapsed <= Y) ? 60 : 0,
      crqcArrival: (elapsed >= Z) ? 100 : 0,
      breachZone: (elapsed >= 0 && (X + Y) > Z && elapsed >= Z) ? 100 : 0,
    });
  }

  return (
    <motion.div
      className="chart-card"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.6, delay: 0.3 }}
    >
      <h4>Mosca Inequality — Breach Window Visualization</h4>
      <p className="chart-subtitle">
        Overlapping timelines: Migration window (X={X}yr), Data shelf-life (Y={Y}yr),
        CRQC arrival (Z={Z}yr) • {hndlData.algorithm_assessed} cryptography
      </p>
      <ResponsiveContainer width="100%" height={280}>
        <AreaChart data={data} margin={{ top: 10, right: 30, left: 0, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
          <XAxis
            dataKey="year"
            tick={{ fill: "#94a3b8", fontSize: 12 }}
          />
          <YAxis hide />
          <Tooltip
            contentStyle={{
              background: "rgba(5,11,24,0.95)",
              border: "1px solid rgba(15,253,209,0.3)",
              borderRadius: "8px",
              color: "#e2e8f0",
            }}
            formatter={(value, name) => {
              if (value === 0) return ["—", name];
              const labels = {
                migrationWindow: "Migration Window Active",
                dataAtRisk: "Data Still Confidential",
                crqcArrival: "CRQC Can Break Crypto",
                breachZone: "⚠ BREACH ZONE",
              };
              return ["Active", labels[name] || name];
            }}
          />
          <Area
            type="stepAfter"
            dataKey="migrationWindow"
            name="Migration Window (X)"
            stackId="1"
            stroke="#3b82f6"
            fill="#3b82f6"
            fillOpacity={0.3}
          />
          <Area
            type="stepAfter"
            dataKey="dataAtRisk"
            name="Data Shelf-Life (Y)"
            stackId="2"
            stroke="#ffa726"
            fill="#ffa726"
            fillOpacity={0.25}
          />
          <Area
            type="stepAfter"
            dataKey="crqcArrival"
            name="CRQC Capability (Z)"
            stackId="3"
            stroke="#ff3b5c"
            fill="#ff3b5c"
            fillOpacity={0.15}
          />
          {hndlData.mosca_breach && (
            <Area
              type="stepAfter"
              dataKey="breachZone"
              name="Breach Window"
              stackId="4"
              stroke="#ff3b5c"
              fill="#ff3b5c"
              fillOpacity={0.4}
            />
          )}
          <ReferenceLine x={currentYear} stroke="#0ffda1" strokeDasharray="3 3">
            <Label value="Today" position="top" fill="#0ffda1" fontSize={12} />
          </ReferenceLine>
          <Legend wrapperStyle={{ color: "#94a3b8", fontSize: 11 }} />
        </AreaChart>
      </ResponsiveContainer>
    </motion.div>
  );
}


/* ─────────────────────────────────────────────────────────
   4. Vulnerability Component Breakdown
   Donut chart: quantum-safe vs vulnerable across assets.
   ───────────────────────────────────────────────────────── */

export function VulnerabilityBreakdown({ cbom }) {
  const assets = cbom?.crypto_assets || [];
  if (assets.length === 0) return null;

  let safeCount = 0;
  let vulnCount = 0;
  let partialCount = 0;

  for (const asset of assets) {
    const safe = asset?.cipher_analysis?.quantum_safe_components?.length || 0;
    const vuln = asset?.cipher_analysis?.quantum_vulnerable_components?.length || 0;
    safeCount += safe;
    vulnCount += vuln;

    const pqc = asset?.pqcClassification?.status || asset?.quantum_assessment?.pqc_status;
    if (pqc === "HYBRID_PQC") partialCount++;
  }

  const data = [
    { name: "Quantum Vulnerable", value: vulnCount, color: "#ff3b5c" },
    { name: "Quantum Safe", value: safeCount, color: "#0ffda1" },
  ];

  if (partialCount > 0) {
    data.push({ name: "Hybrid PQC", value: partialCount, color: "#ffa726" });
  }

  const total = safeCount + vulnCount + partialCount;
  const vulnPct = total > 0 ? Math.round((vulnCount / total) * 100) : 0;

  return (
    <motion.div
      className="chart-card"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.6, delay: 0.4 }}
    >
      <h4>Quantum Vulnerability Breakdown</h4>
      <p className="chart-subtitle">
        Cryptographic components across {assets.length} asset{assets.length > 1 ? "s" : ""} •
        <span style={{ color: "#ff3b5c", fontWeight: "bold" }}> {vulnPct}% vulnerable</span>
      </p>
      <ResponsiveContainer width="100%" height={280}>
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={70}
            outerRadius={100}
            paddingAngle={3}
            dataKey="value"
            label={({ name, value }) => `${name}: ${value}`}
          >
            {data.map((entry, i) => (
              <Cell key={i} fill={entry.color} stroke="none" />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              background: "rgba(5,11,24,0.95)",
              border: "1px solid rgba(15,253,209,0.3)",
              borderRadius: "8px",
              color: "#e2e8f0",
            }}
          />
          <Legend wrapperStyle={{ color: "#94a3b8", fontSize: 12 }} />
        </PieChart>
      </ResponsiveContainer>
    </motion.div>
  );
}
