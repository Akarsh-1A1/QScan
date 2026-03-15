import React from "react";
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

import { calculateQuantumReadinessScore } from "../utils/pqcClassifier";

import "./pages.css";

function Results() {
  const { scanId } = useParams();
  const { cbom, loading, error } = useScanResults(scanId);

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

          <div className="metric-grid">

            <div className="metric-card">
              <div className="metric-value">
                {cbom.stats.totalAssets}
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
                {cbom.stats.criticalCount}
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
                {cbom.stats.pqcReadyCount}
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
                </tr>
              </thead>

              <tbody>
                {cbom.crypto_assets.map((asset, idx) => (
                  <tr key={idx}>

                    <td>
                      <code>
                        {asset.host}:{asset.port}
                      </code>
                    </td>

                    <td>
                      <TLSVersionBadge
                        version={asset.tls_version}
                      />
                    </td>

                    <td>
                      <code>{asset.cipher_suite}</code>
                    </td>

                    <td>
                      <PQCStatusPill
                        status={asset.pqcClassification.status}
                      />
                    </td>

                    <td>
                      <RiskBadge score={asset.riskScore} />
                    </td>

                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* -------------------------
              RISK MATRIX (NEW)
          -------------------------- */}

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
                {asset.threatTimeline}
              </p>

              <p>
                <strong>Migration Deadline:</strong>{" "}
                {asset.migrationDeadline}
              </p>

              <p>
                <strong>Urgency:</strong>{" "}
                {asset.urgency}
              </p>
            </div>
          )}

          {asset?.formattedCert && (
            <div className="card" style={{ marginTop: "2rem" }}>
              <h3>Certificate Information</h3>

              <p>
                <strong>Subject:</strong>{" "}
                {asset.formattedCert.subject}
              </p>

              <p>
                <strong>Issuer:</strong>{" "}
                {asset.formattedCert.issuer}
              </p>

              <p>
                <strong>Valid From:</strong>{" "}
                {asset.formattedCert.validFrom}
              </p>

              <p>
                <strong>Valid Until:</strong>{" "}
                {asset.formattedCert.validUntil}
              </p>

              <p>
                <strong>Days Until Expiry:</strong>{" "}
                {asset.formattedCert.daysUntilExpiry}
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

          {/* -------------------------
              PQC MIGRATION PLAN (NEW)
          -------------------------- */}

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