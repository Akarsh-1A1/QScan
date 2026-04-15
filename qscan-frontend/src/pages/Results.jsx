import React, { useState, useEffect } from "react";
import { useParams, Link } from "react-router-dom";
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
import QuantaChatbot from "../components/common/QuantaChatbot";
import VPNScanResult from "../components/VPNScanResult";

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

import CompliancePanel from "../components/compliance/CompliancePanel";
import RemediationPlaybook from "../components/remediation/RemediationPlaybook";

import "./pages.css";

function Results() {
  const { scanId } = useParams();

  /* ML branch added scanResults */
  const { cbom, scanResults, loading, error } = useScanResults(scanId);

  // Track HNDL data for charts + PDF
  const [hndlData, setHndlData] = useState(null);

  useEffect(() => {
    if (scanId && cbom) {
      scanApi.getHNDLRisk(scanId).then(res => {
        setHndlData(res.data.hndl_risk);
      }).catch(() => { });
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
            <Link
              to={`/certificate/${scanId}`}
              className="btn-report btn-report-pdf"
              style={{ textDecoration: 'none', background: 'linear-gradient(135deg, #0ffda1, #0fa)', color: '#0a0f1a' }}
            >
              🛡️ View PQC Certificate
            </Link>
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

          {/* VPN Scan Results */}
          {scanResults?.some(r => r.vpn_protocol) && (
            <div style={{ marginTop: "2rem" }}>
              <VPNScanResult
                endpoints={scanResults.filter(r => r.vpn_protocol)}
              />
            </div>
          )}

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

          <CompliancePanel cbom={cbom} />
          <RemediationPlaybook cbom={cbom} />

          <details style={{ marginTop: "2rem" }}>
            <summary>Raw CBOM Data</summary>
            <pre>
              {JSON.stringify(cbom, null, 2)}
            </pre>
          </details>

        </motion.div>

        <QuantaChatbot cbom={cbom} scanResults={scanResults} scanId={scanId} />
      </div>
    </div>
  );
}

export default Results;