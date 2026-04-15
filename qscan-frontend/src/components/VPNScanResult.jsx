import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { ChevronDown, ChevronUp, AlertTriangle, CheckCircle, Shield } from 'lucide-react';
import { RiskBadge } from './common/badges';
import './vpn_scan_result.css';

function VPNScanResult({ endpoints = [] }) {
  const [expandedId, setExpandedId] = useState(null);

  if (!endpoints || endpoints.length === 0) {
    return (
      <div className="vpn-empty-state">
        <p>No VPN protocols detected on this scan</p>
      </div>
    );
  }

  const getProtocolIcon = (protocol) => {
    if (!protocol) return '🌐';
    const lower = protocol.toLowerCase();
    if (lower.includes('ikev2') || lower.includes('ipsec')) return '🔐';
    if (lower.includes('openvpn')) return '🔒';
    if (lower.includes('wireguard')) return '⚡';
    if (lower.includes('ssl') || lower.includes('anyconnect')) return '🔑';
    if (lower.includes('pptp') || lower.includes('l2tp')) return '⚠️';
    return '🌐';
  };

  const getConfirmationRibbon = (confirmed) => {
    if (!confirmed) return null;
    return <span className="vpn-confirmed-ribbon">CONFIRMED</span>;
  };

  const toggleExpand = (id) => {
    setExpandedId(expandedId === id ? null : id);
  };

  return (
    <div className="vpn-results-container">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <div className="vpn-header">
          <h3>
            <Shield size={24} style={{ marginRight: '0.75rem', verticalAlign: 'middle' }} />
            VPN Protocol Detection
          </h3>
          <span className="vpn-count-badge">{endpoints.length} endpoint{endpoints.length !== 1 ? 's' : ''}</span>
        </div>

        <div className="vpn-endpoints-list">
          {endpoints.map((endpoint, idx) => (
            <motion.div
              key={`${endpoint.host}-${endpoint.port}`}
              className={`vpn-endpoint-card ${expandedId === idx ? 'expanded' : ''}`}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: idx * 0.1 }}
            >
              {getConfirmationRibbon(endpoint.confirmed)}

              {/* Header / Summary */}
              <div className="vpn-endpoint-header" onClick={() => toggleExpand(idx)}>
                <div className="vpn-endpoint-title">
                  <span className="vpn-protocol-icon">{getProtocolIcon(endpoint.vpn_protocol)}</span>
                  <div className="vpn-endpoint-info">
                    <h4>
                      {endpoint.vpn_protocol || 'Unknown VPN'}
                      {endpoint.vpn_product && <span className="vpn-product-tag">{endpoint.vpn_product}</span>}
                    </h4>
                    <p className="vpn-endpoint-address">
                      {endpoint.host}:{endpoint.port} ({endpoint.transport})
                    </p>
                  </div>
                </div>

                <div className="vpn-endpoint-badges">
                  <RiskBadge score={endpoint.quantum_risk_score} size="sm" />
                  <div className={`vpn-pqc-status pqc-${endpoint.pqc_status.toLowerCase()}`}>
                    {endpoint.pqc_status.replace(/_/g, '-')}
                  </div>
                  <button className="vpn-expand-btn" aria-label="Toggle details">
                    {expandedId === idx ? (
                      <ChevronUp size={20} />
                    ) : (
                      <ChevronDown size={20} />
                    )}
                  </button>
                </div>
              </div>

              {/* Expanded Details */}
              {expandedId === idx && (
                <motion.div
                  className="vpn-endpoint-details"
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                >
                  {/* Cryptographic Details */}
                  {endpoint.tls_version && (
                    <div className="vpn-details-section">
                      <h5>Cryptographic Configuration</h5>
                      <div className="vpn-details-grid">
                        {endpoint.tls_version && (
                          <div className="vpn-detail-item">
                            <span className="vpn-detail-label">TLS Version:</span>
                            <code>{endpoint.tls_version}</code>
                          </div>
                        )}
                        {endpoint.cipher_suite && (
                          <div className="vpn-detail-item">
                            <span className="vpn-detail-label">Cipher Suite:</span>
                            <code>{endpoint.cipher_suite}</code>
                          </div>
                        )}
                        {endpoint.cipher_bits && (
                          <div className="vpn-detail-item">
                            <span className="vpn-detail-label">Key Bits:</span>
                            <code>{endpoint.cipher_bits}</code>
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Algorithms */}
                  {(endpoint.encryption_algorithms?.length > 0 ||
                    endpoint.integrity_algorithms?.length > 0 ||
                    endpoint.dh_groups?.length > 0) && (
                    <div className="vpn-details-section">
                      <h5>Supported Algorithms</h5>
                      <div className="vpn-algo-list">
                        {endpoint.encryption_algorithms?.length > 0 && (
                          <div>
                            <span className="vpn-algo-label">Encryption:</span>
                            <div className="vpn-algo-tags">
                              {endpoint.encryption_algorithms.map((algo, i) => (
                                <span key={i} className="vpn-algo-tag">{algo}</span>
                              ))}
                            </div>
                          </div>
                        )}
                        {endpoint.integrity_algorithms?.length > 0 && (
                          <div>
                            <span className="vpn-algo-label">Integrity:</span>
                            <div className="vpn-algo-tags">
                              {endpoint.integrity_algorithms.map((algo, i) => (
                                <span key={i} className="vpn-algo-tag">{algo}</span>
                              ))}
                            </div>
                          </div>
                        )}
                        {endpoint.dh_groups?.length > 0 && (
                          <div>
                            <span className="vpn-algo-label">DH Groups:</span>
                            <div className="vpn-algo-tags">
                              {endpoint.dh_groups.map((group, i) => (
                                <span key={i} className="vpn-algo-tag">{group}</span>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Notes */}
                  {endpoint.notes && (
                    <div className="vpn-details-section">
                      <h5>Notes</h5>
                      <p className="vpn-notes">{endpoint.notes}</p>
                      {endpoint.risk_score_is_estimate && (
                        <div className="vpn-estimate-warning">
                          <AlertTriangle size={16} />
                          <span>Risk score is estimated (cipher not fully detected)</span>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Recommendations */}
                  {endpoint.recommendations?.length > 0 && (
                    <div className="vpn-details-section">
                      <h5>PQC Migration Recommendations</h5>
                      <div className="vpn-recommendations">
                        {endpoint.recommendations.map((rec, i) => (
                          <div key={i} className={`vpn-recommendation vpn-priority-${rec.priority.toLowerCase()}`}>
                            <div className="vpn-rec-header">
                              <span className="vpn-rec-component">{rec.component}</span>
                              <span className={`vpn-rec-priority vpn-priority-${rec.priority.toLowerCase()}`}>
                                {rec.priority}
                              </span>
                            </div>
                            <div className="vpn-rec-body">
                              <div className="vpn-rec-item">
                                <span className="vpn-rec-label">Current:</span>
                                <code>{rec.current}</code>
                              </div>
                              <div className="vpn-rec-arrow">→</div>
                              <div className="vpn-rec-item">
                                <span className="vpn-rec-label">Recommended:</span>
                                <code>{rec.recommended}</code>
                              </div>
                            </div>
                            {rec.hybrid_option && (
                              <div className="vpn-rec-hybrid">
                                <span className="vpn-rec-label">Hybrid Option:</span>
                                <code>{rec.hybrid_option}</code>
                              </div>
                            )}
                            <p className="vpn-rec-rationale">{rec.rationale}</p>
                            {rec.nist_standard && (
                              <p className="vpn-rec-standard">
                                <CheckCircle size={14} />
                                {rec.nist_standard}
                              </p>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Risk Assessment */}
                  <div className="vpn-details-section">
                    <h5>Quantum-Safe Readiness Assessment</h5>
                    <div className="vpn-risk-assessment">
                      <div className="vpn-risk-item">
                        <span className="vpn-risk-label">Current Status:</span>
                        <div className={`vpn-pqc-status-large pqc-${endpoint.pqc_status.toLowerCase()}`}>
                          {endpoint.pqc_status.replace(/_/g, '-')}
                        </div>
                      </div>
                      <div className="vpn-risk-item">
                        <span className="vpn-risk-label">Risk Level:</span>
                        <RiskBadge score={endpoint.quantum_risk_score} size="md" />
                      </div>
                      <div className="vpn-risk-item">
                        <span className="vpn-risk-label">Risk Score:</span>
                        <span className="vpn-risk-score">{endpoint.quantum_risk_score.toFixed(1)}/100</span>
                      </div>
                    </div>
                  </div>
                </motion.div>
              )}
            </motion.div>
          ))}
        </div>

        {/* Summary Stats */}
        <div className="vpn-summary-stats">
          <div className="vpn-stat">
            <span className="vpn-stat-label">Critical Risk</span>
            <span className="vpn-stat-value">
              {endpoints.filter((e) => e.quantum_risk_score >= 80).length}
            </span>
          </div>
          <div className="vpn-stat">
            <span className="vpn-stat-label">PQC Ready</span>
            <span className="vpn-stat-value">
              {endpoints.filter((e) => e.pqc_status === 'PQC_READY').length}
            </span>
          </div>
          <div className="vpn-stat">
            <span className="vpn-stat-label">Action Required</span>
            <span className="vpn-stat-value">
              {endpoints.filter((e) => e.pqc_status === 'CRITICAL' || e.pqc_status === 'MIGRATION_NEEDED').length}
            </span>
          </div>
        </div>
      </motion.div>
    </div>
  );
}

export default VPNScanResult;
