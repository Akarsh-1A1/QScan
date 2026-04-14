import React, { useState, useEffect } from "react";
import { scanApi } from "../../api/scanApi";
import { motion } from "framer-motion";
import "./hndl_panel.css";

function HNDLRiskPanel({ scanId }) {
  const [hndlData, setHndlData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [migrationYears, setMigrationYears] = useState(3);
  const [dataLifeYears, setDataLifeYears] = useState(7);

  const fetchHNDLRisk = async (mYears = migrationYears, dYears = dataLifeYears) => {
    setLoading(true);
    setError(null);

    try {
      const response = await scanApi.getHNDLRisk(scanId, mYears, dYears);
      setHndlData(response.data.hndl_risk);
    } catch (err) {
      setError(err.message || "Failed to compute HNDL risk");
      console.error("HNDL fetch error:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (scanId) {
      fetchHNDLRisk();
    }
  }, [scanId]);

  const handleMigrationChange = (e) => {
    const value = parseInt(e.target.value);
    setMigrationYears(value);
    fetchHNDLRisk(value, dataLifeYears);
  };

  const handleDataLifeChange = (e) => {
    const value = parseInt(e.target.value);
    setDataLifeYears(value);
    fetchHNDLRisk(migrationYears, value);
  };

  if (error && !hndlData) {
    return (
      <div className="hndl-error">
        <p>⚠️ {error}</p>
      </div>
    );
  }

  if (loading && !hndlData) {
    return (
      <div className="hndl-skeleton">
        <div className="skeleton-bar" style={{ width: "100%", height: "200px" }} />
      </div>
    );
  }

  if (!hndlData) {
    return null;
  }

  const breachColor = hndlData.mosca_breach
    ? "var(--accent-red)"
    : "var(--accent-safe)";

  const breachText = hndlData.mosca_breach
    ? "🔴 BREACH WINDOW OPEN"
    : "🟢 SAFE";

  const urgencyBg = hndlData.mosca_breach
    ? "#8B0000"
    : "#006400";

  return (
    <motion.div
      className="hndl-panel"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
    >
      {/* Header */}
      <div className="hndl-header">
        <h3>HNDL Mosca Inequality Risk</h3>
        <p className="subtitle">
          Harvest Now, Decrypt Later Vulnerability Assessment
        </p>
      </div>

      {/* Status Badge */}
      <div className="hndl-status" style={{ borderLeftColor: breachColor }}>
        <div
          className="status-badge"
          style={{
            backgroundColor: urgencyBg,
            color: "white",
            padding: "12px 20px",
            borderRadius: "8px",
            display: "inline-block",
            fontWeight: "bold",
            fontSize: "1.1rem",
          }}
        >
          {breachText}
        </div>
        <div className="urgency-label">
          Urgency: <span style={{ color: breachColor }}>{hndlData.urgency}</span>
        </div>
      </div>

      {/* Mosca Inequality Equation */}
      <div className="hndl-equation card">
        <h4>Mosca Inequality (X + Y &gt; Z)</h4>
        <div className="equation-display">
          <div className="equation-term">
            <span className="label">X (Migration)</span>
            <span className="value">{hndlData.migration_years_x} yrs</span>
          </div>
          <span className="operator">+</span>
          <div className="equation-term">
            <span className="label">Y (Data Life)</span>
            <span className="value">{hndlData.data_life_years_y} yrs</span>
          </div>
          <span className="operator">=</span>
          <div className="equation-term">
            <span className="label">Sum</span>
            <span className="value" style={{ color: breachColor }}>
              {hndlData.mosca_sum}
            </span>
          </div>
          <span className="operator">vs</span>
          <div className="equation-term">
            <span className="label">Z (CRQC)</span>
            <span className="value">{hndlData.crqc_timeline_years} yrs</span>
          </div>
        </div>
        <p className="equation-note">
          {hndlData.algorithm_assessed} cryptography
          <br />
          <small>Source: {hndlData.crqc_source}</small>
        </p>
      </div>

      {/* Breach Window Information */}
      <div className="hndl-breach-window card">
        <h4>Breach Window Timeline</h4>
        <div className="breach-info">
          <div className="info-row">
            <span className="info-label">Current Year:</span>
            <span className="info-value">{hndlData.current_year}</span>
          </div>
          <div className="info-row">
            <span className="info-label">Breach Window Opens:</span>
            <span className="info-value" style={{ color: breachColor }}>
              {hndlData.breach_window_year}
            </span>
          </div>
          <div className="info-row">
            <span className="info-label">Years Until Breach:</span>
            <span className="info-value">
              {hndlData.years_until_breach} year{hndlData.years_until_breach !== 1 ? "s" : ""}
            </span>
          </div>
        </div>
      </div>

      {/* Risk Metrics */}
      <div className="hndl-risk-metrics card">
        <h4>Potential Exposure</h4>
        <div className="metrics-grid">
          <div className="metric">
            <div className="metric-label">Sessions at Risk</div>
            <div className="metric-value">
              {hndlData.sessions_at_risk.toLocaleString()}
            </div>
          </div>
          <div className="metric">
            <div className="metric-label">Data Exposed (GB)</div>
            <div className="metric-value">~{hndlData.data_at_risk_gb.toLocaleString()}</div>
          </div>
        </div>
      </div>

      {/* Interactive Sliders */}
      <div className="hndl-controls card">
        <h4>Adjust Parameters</h4>

        <div className="slider-group">
          <label htmlFor="migration-slider">
            Migration Lead-Time (X): <strong>{migrationYears} years</strong>
          </label>
          <input
            id="migration-slider"
            type="range"
            min="1"
            max="10"
            value={migrationYears}
            onChange={handleMigrationChange}
            className="slider"
            disabled={loading}
          />
          <small>Time available to migrate to PQC</small>
        </div>

        <div className="slider-group">
          <label htmlFor="data-slider">
            Data Shelf-Life (Y): <strong>{dataLifeYears} years</strong>
          </label>
          <input
            id="data-slider"
            type="range"
            min="1"
            max="15"
            value={dataLifeYears}
            onChange={handleDataLifeChange}
            className="slider"
            disabled={loading}
          />
          <small>RBI banking compliance mandate: 7 years minimum</small>
        </div>
      </div>

      {/* Recommendation */}
      <div className="hndl-recommendation card" style={{ borderLeftColor: breachColor }}>
        <h4>Recommendation</h4>
        <p className="recommendation-text">{hndlData.recommendation}</p>
      </div>
    </motion.div>
  );
}

export default HNDLRiskPanel;
