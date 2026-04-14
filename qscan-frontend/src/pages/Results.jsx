import React, { useState, useEffect } from "react";
import { useParams } from "react-router-dom";
import { useScanResults } from "../hooks/useScan";
import { motion } from "framer-motion";
import {
  SkeletonCard,
  EmptyState,
  RiskBadge,
  TLSVersionBadge,
  PQCStatusPill,
} from "../components/common/badges";

import HNDLRiskPanel from "../components/HNDL/HNDLRiskPanel";

import {
  CRQCTimelineChart,
  CryptoPostureRadar,
  MoscaTimelineChart,
  VulnerabilityBreakdown,
} from "../components/charts/QuantumCharts";
import "../components/charts/quantum_charts.css";

import { generatePDFReport, downloadCBOM } from "../utils/reportGenerator";
import { scanApi } from "../api/scanApi";

import { calculateQuantumReadinessScore } from "../utils/pqcClassifier";

import "./pages.css";

function Results() {
  const { scanId } = useParams();

  /* ML branch added scanResults */
  const { cbom, scanResults, vpnResults, loading, error } = useScanResults(scanId);

  // Track HNDL data for charts + PDF
  const [hndlData, setHndlData] = useState(null);

  useEffect(() => {
    if (scanId && cbom) {
      scanApi.getHNDLRisk(scanId).then(res => {
        setHndlData(res.data.hndl_risk);
      }).catch(() => {});
    }
  }, [scanId, cbom]);

  if (loading) {
    return (
      <div className="container" style={{ padding: "3rem 0" }}>
        <h2>Loading Results...</h2>
        <div className="grid grid-3">
          {[1, 2, 3, 4, 5].map((i) => (
            <SkeletonCard key={i} />
          ))}
        </div>
      </div>
    );
  }

  if (error || !cbom) {
    return (
      <div className="container" style={{ padding: "3rem 0" }}>
        <EmptyState
          icon="❌"
          title="Failed to Load Results"
          message={error || "Results not found"}
        />
      </div>
    );
  }

  const asset = cbom.crypto_assets?.[0];

  const readinessScore = calculateQuantumReadinessScore(cbom);

  const readinessLabel =
    readinessScore >= 80
      ? "Quantum Ready"
      : readinessScore >= 50
      ? "Partial PQC"
      : "Not Ready";

  const readinessColor =
    readinessScore >= 80
      ? "var(--accent-safe)"
      : readinessScore >= 50
      ? "orange"
      : "red";

  return (
    <div style={{ minHeight: "100vh" }}>
      <div className="container" style={{ padding: "3rem 0" }}>
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>

          <div className="dashboard-header">
            <h2>{cbom.metadata?.organization_domain}</h2>
            <p style={{ color: "var(--text-muted)" }}>
              Scan ID: {scanId}
            </p>
          </div>

          {/* Report Actions */}
          <div className="report-actions">
            <button
              className="btn-report btn-report-pdf"
              onClick={() => generatePDFReport(cbom, scanId, hndlData)}
            >
              📄 Download PDF Report
            </button>
            <button
              className="btn-report btn-report-cbom"
              onClick={() => downloadCBOM(cbom)}
            >
              📋 Download CBOM (JSON)
            </button>
          </div>

          <div
            className="card"
            style={{
              marginBottom: "2rem",
              textAlign: "center",
            }}
          >
            <h3>Quantum Readiness Score</h3>

            <div
              style={{
                fontSize: "3rem",
                fontWeight: "bold",
                marginTop: "10px",
                color: readinessColor,
              }}
            >
              {readinessScore}%
            </div>

            <p style={{ color: "var(--text-muted)" }}>
              {readinessLabel}
            </p>
          </div>

          {/* HNDL Mosca Risk Simulator Panel */}
          <HNDLRiskPanel scanId={scanId} />

          <div className="metric-grid">

            <div className="metric-card">
              <div className="metric-value">
                {cbom.summary?.total_assets || 0}
              </div>
              <div className="metric-label">
                Total Assets
              </div>
            </div>

            <div
              className="metric-card"
              style={{ borderLeft: "4px solid red" }}
            >
              <div className="metric-value">
                {cbom.summary?.risk_distribution?.CRITICAL || 0}
              </div>
              <div className="metric-label">
                Critical Vulnerabilities
              </div>
            </div>

            <div
              className="metric-card"
              style={{ borderLeft: "4px solid green" }}
            >
              <div className="metric-value">
                {cbom.summary?.pqc_status_distribution?.PQC_READY || 0}
              </div>
              <div className="metric-label">
                PQC Ready
              </div>
            </div>

          </div>

          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Asset</th>
                  <th>TLS</th>
                  <th>Cipher</th>
                  <th>PQC Status</th>
                  <th>Risk</th>

                  {/* ML columns added */}
                  <th>AI Risk</th>
                  <th>Anomaly</th>
                </tr>
              </thead>

              <tbody>
                {cbom.crypto_assets?.map((asset, idx) => {

                  /* ML results lookup */
                  const mlScore = scanResults?.[idx]?.ml_risk_score;
                  const anomaly = scanResults?.[idx]?.anomaly_detection;

                  return (
                    <tr key={idx}>

                      <td>
                        <code>
                          {asset.host}:{asset.port}
                        </code>
                      </td>

                      <td>
                        <TLSVersionBadge
                          version={
                            asset.tls_configuration?.protocol_version || "UNKNOWN"
                          }
                        />
                      </td>

                      <td>
                        <code>
                          {asset.tls_configuration?.negotiated_cipher || "Unknown"}
                        </code>
                      </td>

                      <td>
                        <PQCStatusPill
                          status={asset.quantum_assessment?.pqc_status}
                        />
                      </td>

                      <td>
                        <RiskBadge
                          score={asset.quantum_assessment?.risk_score}
                        />
                      </td>

                      {/* ML risk score */}
                      <td>
                        {mlScore !== undefined ? mlScore.toFixed(1) : "-"}
                      </td>

                      {/* anomaly detection */}
                      <td>
                        {anomaly ? (
                          <div style={{ fontSize: "0.85rem" }}>

                            <div>
                              {anomaly.is_anomaly ? "⚠️ Anomaly" : "Normal"}
                            </div>

                            <div style={{ color: "var(--text-muted)" }}>
                              Score:{" "}
                              {anomaly.anomaly_score?.toFixed(2) ?? "-"}
                            </div>

                            <div style={{ color: "var(--text-muted)" }}>
                              Confidence: {anomaly.confidence ?? "-"}
                            </div>

                            {anomaly.reasons?.length > 0 && (
                              <div style={{ color: "orange" }}>
                                {anomaly.reasons.join(", ")}
                              </div>
                            )}

                          </div>
                        ) : (
                          "-"
                        )}
                      </td>

                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {cbom.risk_matrix && cbom.risk_matrix.length > 0 && (
            <div className="card" style={{ marginTop: "2rem" }}>
              <h3>Risk Matrix</h3>

              <table>
                <thead>
                  <tr>
                    <th>Host</th>
                    <th>Port</th>
                    <th>Risk Score</th>
                    <th>PQC Status</th>
                    <th>Deadline</th>
                  </tr>
                </thead>

                <tbody>
                  {cbom.risk_matrix.map((r, i) => (
                    <tr key={i}>
                      <td>{r.host}</td>
                      <td>{r.port}</td>
                      <td>{r.risk_score}</td>
                      <td>{r.pqc_status}</td>
                      <td>{r.migration_deadline}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {asset && (
            <div className="card" style={{ marginTop: "2rem" }}>
              <h3>Quantum Threat Assessment</h3>

              <p>
                <strong>Estimated Quantum Threat:</strong>{" "}
                {asset.quantum_assessment?.threat_assessment?.estimated_quantum_threat}
              </p>

              <p>
                <strong>Migration Deadline:</strong>{" "}
                {asset.quantum_assessment?.threat_assessment?.migration_deadline}
              </p>

              <p>
                <strong>Urgency:</strong>{" "}
                {asset.quantum_assessment?.threat_assessment?.urgency}
              </p>
            </div>
          )}

          {asset?.certificate_info && (
            <div className="card" style={{ marginTop: "2rem" }}>
              <h3>Certificate Information</h3>

              <p>
                <strong>Subject:</strong>{" "}
                {asset.certificate_info?.subject?.commonName}
              </p>

              <p>
                <strong>Issuer:</strong>{" "}
                {asset.certificate_info?.issuer?.organizationName}
              </p>

              <p>
                <strong>Valid From:</strong>{" "}
                {asset.certificate_info?.validity?.not_before}
              </p>

              <p>
                <strong>Valid Until:</strong>{" "}
                {asset.certificate_info?.validity?.not_after}
              </p>

              <p>
                <strong>Days Until Expiry:</strong>{" "}
                {asset.certificate_info?.validity?.days_until_expiry}
              </p>
            </div>
          )}

          {asset?.recommendations && (
            <div className="card" style={{ marginTop: "2rem" }}>
              <h3>Post-Quantum Migration Recommendations</h3>

              {asset.recommendations.map((r, i) => (
                <div key={i} style={{ marginBottom: "1rem" }}>
                  <strong>{r.component}</strong>

                  <p>
                    Current: <code>{r.current}</code>
                  </p>

                  <p>
                    Recommended: <code>{r.recommended}</code>
                  </p>

                  <p>
                    Hybrid: <code>{r.hybrid_option}</code>
                  </p>

                  <p style={{ color: "var(--text-muted)" }}>
                    {r.rationale}
                  </p>
                </div>
              ))}
            </div>
          )}

          {cbom.pqc_migration_plan && (
            <div className="card" style={{ marginTop: "2rem" }}>
              <h3>PQC Migration Plan</h3>

              {cbom.pqc_migration_plan.immediate_actions?.map((a, i) => (
                <p key={i}>
                  {a.host}:{a.port} → {a.component}
                </p>
              ))}

              {cbom.pqc_migration_plan.short_term_actions?.map((a, i) => (
                <p key={i}>
                  {a.host}:{a.port} → {a.component}
                </p>
              ))}

              {cbom.pqc_migration_plan.planned_actions?.map((a, i) => (
                <p key={i}>
                  {a.host}:{a.port} → {a.component}
                </p>
              ))}
            </div>
          )}
          {/* ─── VPN Inventory Section ─── */}
          {vpnResults && vpnResults.vpn_inventory && vpnResults.vpn_inventory.length > 0 && (
            <div className="card" style={{ marginTop: "2rem" }}>
              <h3>🔒 VPN Endpoint Inventory</h3>
              <p style={{ color: "var(--text-muted)", marginBottom: "1rem" }}>
                {vpnResults.vpn_endpoints_found} VPN endpoint(s) discovered across public-facing infrastructure.
              </p>

              <div className="table-wrapper">
                <table>
                  <thead>
                    <tr>
                      <th>Host</th>
                      <th>Port / Protocol</th>
                      <th>VPN Type</th>
                      <th>TLS / Cipher</th>
                      <th>Key Exchange / DH</th>
                      <th>PQC Status</th>
                      <th>Risk</th>
                    </tr>
                  </thead>
                  <tbody>
                    {vpnResults.vpn_inventory.map((vpn, idx) => {
                      const riskColor =
                        vpn.quantum_assessment?.risk_level === "CRITICAL" ? "red" :
                        vpn.quantum_assessment?.risk_level === "HIGH" ? "orange" :
                        vpn.quantum_assessment?.risk_level === "MEDIUM" ? "gold" :
                        vpn.quantum_assessment?.risk_level === "LOW" ? "yellowgreen" :
                        "var(--accent-safe)";

                      const pqcColor =
                        vpn.quantum_assessment?.pqc_status === "PQC_READY" ? "var(--accent-safe)" :
                        vpn.quantum_assessment?.pqc_status === "HYBRID_PQC" ? "gold" :
                        vpn.quantum_assessment?.pqc_status === "CRITICAL" ? "red" :
                        "orange";

                      return (
                        <tr key={idx}>
                          <td><code>{vpn.host}</code></td>
                          <td>
                            <code>{vpn.port}</code>
                            <span style={{ color: "var(--text-muted)", fontSize: "0.8rem", marginLeft: "0.3rem" }}>
                              {vpn.transport}
                            </span>
                          </td>
                          <td>
                            <span style={{ fontWeight: "600" }}>{vpn.vpn_protocol}</span>
                            {vpn.vpn_product && vpn.vpn_product !== vpn.vpn_protocol && (
                              <div style={{ color: "var(--text-muted)", fontSize: "0.8rem" }}>
                                {vpn.vpn_product}
                              </div>
                            )}
                          </td>
                          <td>
                            <code style={{ fontSize: "0.8rem" }}>
                              {vpn.tls_version || "N/A"}
                            </code>
                            {vpn.cipher_suite && (
                              <div style={{ color: "var(--text-muted)", fontSize: "0.75rem" }}>
                                {vpn.cipher_suite}
                              </div>
                            )}
                            {vpn.encryption_algorithms?.length > 0 && !vpn.cipher_suite && (
                              <div style={{ color: "var(--text-muted)", fontSize: "0.75rem" }}>
                                {vpn.encryption_algorithms.join(", ")}
                              </div>
                            )}
                          </td>
                          <td style={{ fontSize: "0.8rem" }}>
                            {vpn.dh_groups?.length > 0
                              ? vpn.dh_groups.join(", ")
                              : "—"}
                          </td>
                          <td>
                            <span style={{
                              padding: "0.2rem 0.6rem",
                              borderRadius: "4px",
                              background: pqcColor + "22",
                              color: pqcColor,
                              fontWeight: "600",
                              fontSize: "0.8rem",
                            }}>
                              {vpn.quantum_assessment?.pqc_status || "UNKNOWN"}
                            </span>
                          </td>
                          <td>
                            <span style={{
                              padding: "0.2rem 0.6rem",
                              borderRadius: "4px",
                              background: riskColor + "22",
                              color: riskColor,
                              fontWeight: "600",
                              fontSize: "0.8rem",
                            }}>
                              {vpn.quantum_assessment?.risk_level || "UNKNOWN"}
                            </span>
                            <div style={{ color: "var(--text-muted)", fontSize: "0.75rem" }}>
                              Score: {vpn.quantum_assessment?.risk_score ?? "—"}
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              {/* VPN Recommendations */}
              {vpnResults.vpn_inventory.some(v => v.recommendations?.length > 0) && (
                <div style={{ marginTop: "1.5rem" }}>
                  <h4>VPN Post-Quantum Migration Recommendations</h4>
                  {vpnResults.vpn_inventory.map((vpn, vpnIdx) =>
                    (vpn.recommendations || []).map((rec, recIdx) => (
                      <div key={`${vpnIdx}-${recIdx}`} style={{
                        background: "var(--surface)",
                        borderRadius: "8px",
                        padding: "0.8rem 1rem",
                        marginBottom: "0.8rem",
                        borderLeft: `4px solid ${rec.priority === "CRITICAL" ? "red" : rec.priority === "HIGH" ? "orange" : "gold"}`,
                      }}>
                        <div style={{ fontWeight: "600", marginBottom: "0.3rem" }}>
                          <code>{vpn.host}:{vpn.port}</code> — {rec.component}
                          <span style={{
                            marginLeft: "0.5rem",
                            padding: "0.1rem 0.4rem",
                            borderRadius: "3px",
                            background: rec.priority === "CRITICAL" ? "#ff000022" : rec.priority === "HIGH" ? "#ff800022" : "#ffd70022",
                            color: rec.priority === "CRITICAL" ? "red" : rec.priority === "HIGH" ? "orange" : "gold",
                            fontSize: "0.75rem",
                          }}>
                            {rec.priority}
                          </span>
                        </div>
                        <p style={{ margin: "0.2rem 0", fontSize: "0.85rem" }}>
                          Current: <code>{rec.current}</code> → Recommended: <code>{rec.recommended}</code>
                        </p>
                        {rec.hybrid_option && (
                          <p style={{ margin: "0.2rem 0", fontSize: "0.85rem", color: "var(--text-muted)" }}>
                            Hybrid: <code>{rec.hybrid_option}</code>
                          </p>
                        )}
                        {rec.nist_standard && (
                          <p style={{ margin: "0.2rem 0", fontSize: "0.8rem", color: "var(--text-muted)" }}>
                            NIST: {rec.nist_standard}
                          </p>
                        )}
                        <p style={{ margin: "0.3rem 0 0", fontSize: "0.82rem", color: "var(--text-muted)" }}>
                          {rec.rationale}
                        </p>
                      </div>
                    ))
                  )}
                </div>
              )}
            </div>
          )}

          {/* ─── Analytics Charts Section ─── */}
          <div className="charts-section">
            <div className="charts-section-title">
              <h3>Quantum Risk Analytics</h3>
              <div className="divider"></div>
            </div>

            <div className="charts-grid">
              <CRQCTimelineChart
                detectedAlgorithms={
                  cbom.crypto_assets
                    ?.flatMap(a => [
                      a.cipher_analysis?.key_exchange?.algorithm,
                      a.cipher_analysis?.authentication?.algorithm,
                    ])
                    .filter(Boolean) || []
                }
              />
              <CryptoPostureRadar cbom={cbom} />
              {hndlData && <MoscaTimelineChart hndlData={hndlData} />}
              <VulnerabilityBreakdown cbom={cbom} />
            </div>
          </div>

          <details style={{ marginTop: "2rem" }}>
            <summary>Raw CBOM Data</summary>
            <pre>
              {JSON.stringify(cbom, null, 2)}
            </pre>
          </details>

        </motion.div>
      </div>
    </div>
  );
}

export default Results;
