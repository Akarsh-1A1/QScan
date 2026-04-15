import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { scanApi } from '../api/scanApi';
import './pages.css';

const STATUS_CONFIG = {
  PQC_READY: {
    label: 'PQC Ready — Quantum Safe',
    icon: '🛡️',
    color: '#0ffda1',
    bgGradient: 'linear-gradient(135deg, rgba(15,253,161,0.15), rgba(15,253,209,0.05))',
    borderColor: '#0ffda1',
    description: 'All cryptographic components meet NIST Post-Quantum Cryptography standards.',
  },
  HYBRID_PQC: {
    label: 'Hybrid PQC — Transitional',
    icon: '🔶',
    color: '#ffa726',
    bgGradient: 'linear-gradient(135deg, rgba(255,167,38,0.15), rgba(255,167,38,0.05))',
    borderColor: '#ffa726',
    description: 'Mix of PQC and classical algorithms detected. Full migration recommended.',
  },
  MIGRATION_NEEDED: {
    label: 'Migration Needed — Not Quantum Safe',
    icon: '⚠️',
    color: '#ff3b5c',
    bgGradient: 'linear-gradient(135deg, rgba(255,59,92,0.15), rgba(255,59,92,0.05))',
    borderColor: '#ff3b5c',
    description: 'No PQC algorithms detected. Immediate migration to NIST-approved algorithms required.',
  },
  CRITICAL: {
    label: 'Critical — Immediate Action Required',
    icon: '🚨',
    color: '#ff1744',
    bgGradient: 'linear-gradient(135deg, rgba(255,23,68,0.2), rgba(255,59,92,0.05))',
    borderColor: '#ff1744',
    description: 'Critical vulnerabilities detected. Deprecated protocols or expired certificates found.',
  },
};

function Certificate() {
  const { scanId } = useParams();
  const [cert, setCert] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!scanId) return;
    setLoading(true);
    scanApi.issueCertificate(scanId)
      .then(res => {
        setCert(res.data);
        setLoading(false);
      })
      .catch(err => {
        setError(err.response?.data?.detail || 'Failed to issue certificate');
        setLoading(false);
      });
  }, [scanId]);

  if (loading) {
    return (
      <div className="container" style={{ padding: '4rem 0', textAlign: 'center' }}>
        <motion.div
          animate={{ rotate: 360 }}
          transition={{ duration: 1.5, repeat: Infinity, ease: 'linear' }}
          style={{ fontSize: '3rem', display: 'inline-block' }}
        >
          🔐
        </motion.div>
        <p style={{ marginTop: '1rem', color: 'var(--text-muted)' }}>
          Generating PQC Readiness Certificate...
        </p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="container" style={{ padding: '4rem 0', textAlign: 'center' }}>
        <div style={{ fontSize: '3rem' }}>⚠️</div>
        <h2 style={{ color: '#ff3b5c' }}>Certificate Generation Failed</h2>
        <p style={{ color: 'var(--text-muted)' }}>{error}</p>
        <Link to={`/results/${scanId}`} className="btn btn-primary" style={{ marginTop: '1rem' }}>
          ← Back to Results
        </Link>
      </div>
    );
  }

  const config = STATUS_CONFIG[cert.status] || STATUS_CONFIG.MIGRATION_NEEDED;

  return (
    <div style={{ minHeight: '100vh', padding: '3rem 1rem' }}>
      <div className="container" style={{ maxWidth: '800px' }}>

        {/* Actions Bar */}
        <div style={{ display: 'flex', gap: '1rem', marginBottom: '2rem', flexWrap: 'wrap' }}>
          <Link to={`/results/${scanId}`} className="btn btn-secondary">
            ← Back to Results
          </Link>
          <button onClick={() => window.print()} className="btn btn-primary">
            🖨️ Print Certificate
          </button>
        </div>

        {/* Certificate Card */}
        <motion.div
          className="cert-container"
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.6 }}
          style={{
            background: config.bgGradient,
            border: `2px solid ${config.borderColor}`,
            borderRadius: '16px',
            padding: '3rem 2.5rem',
            position: 'relative',
            overflow: 'hidden',
          }}
        >
          {/* Corner accents */}
          <div style={{
            position: 'absolute', top: 0, left: 0, width: '80px', height: '80px',
            borderTop: `3px solid ${config.borderColor}`,
            borderLeft: `3px solid ${config.borderColor}`,
            borderRadius: '16px 0 0 0',
          }} />
          <div style={{
            position: 'absolute', bottom: 0, right: 0, width: '80px', height: '80px',
            borderBottom: `3px solid ${config.borderColor}`,
            borderRight: `3px solid ${config.borderColor}`,
            borderRadius: '0 0 16px 0',
          }} />

          {/* Header */}
          <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
            <motion.div
              style={{ fontSize: '4rem', marginBottom: '0.5rem' }}
              animate={cert.status === 'CRITICAL' ? { opacity: [1, 0.3, 1] } : {}}
              transition={{ duration: 1, repeat: Infinity }}
            >
              {config.icon}
            </motion.div>
            <h1 style={{
              fontSize: '1.6rem',
              color: 'var(--text-primary)',
              margin: '0 0 0.5rem',
              textTransform: 'uppercase',
              letterSpacing: '2px',
            }}>
              QScan Security Certificate
            </h1>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
              Quantum Readiness Assessment • {cert.issuer}
            </p>
          </div>

          {/* Status Badge */}
          <div style={{
            textAlign: 'center',
            padding: '1.5rem',
            borderRadius: '12px',
            background: `rgba(0,0,0,0.3)`,
            border: `1px solid ${config.borderColor}`,
            marginBottom: '2rem',
          }}>
            <div style={{
              fontSize: '1.3rem',
              fontWeight: 700,
              color: config.color,
              fontFamily: '"JetBrains Mono", monospace',
            }}>
              {config.label}
            </div>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginTop: '0.5rem' }}>
              {config.description}
            </p>
          </div>

          {/* Certificate Details */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: '1fr 1fr',
            gap: '1rem',
            marginBottom: '2rem',
          }}>
            <DetailRow label="Awarded To" value={cert.issued_to} accent={config.color} />
            <DetailRow label="Certificate ID" value={cert.certificate_id} mono />
            <DetailRow label="Date Issued" value={new Date(cert.issued_at).toLocaleDateString('en-IN', { day: 'numeric', month: 'long', year: 'numeric' })} />
            <DetailRow label="Valid Until" value={new Date(cert.valid_until).toLocaleDateString('en-IN', { day: 'numeric', month: 'long', year: 'numeric' })} />
            <DetailRow label="Risk Score" value={`${cert.risk_score} / 100`} accent={cert.risk_score < 30 ? '#0ffda1' : cert.risk_score < 70 ? '#ffa726' : '#ff3b5c'} />
            <DetailRow label="Assets Scanned" value={cert.total_assets} />
          </div>

          {/* NIST Algorithms */}
          <div style={{
            padding: '1.25rem',
            background: 'rgba(0,0,0,0.2)',
            borderRadius: '8px',
            marginBottom: '2rem',
            borderLeft: `3px solid ${config.borderColor}`,
          }}>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', margin: '0 0 0.5rem' }}>
              <strong>NIST PQC Algorithms Detected:</strong>
            </p>
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
              {cert.nist_algorithms.map((alg, i) => (
                <span key={i} style={{
                  padding: '0.35rem 0.75rem',
                  borderRadius: '6px',
                  fontSize: '0.85rem',
                  fontFamily: '"JetBrains Mono", monospace',
                  fontWeight: 600,
                  background: alg === 'None detected'
                    ? 'rgba(255,59,92,0.2)'
                    : 'rgba(15,253,209,0.15)',
                  color: alg === 'None detected' ? '#ff3b5c' : '#0ffda1',
                  border: `1px solid ${alg === 'None detected' ? '#ff3b5c' : '#0ffda1'}`,
                }}>
                  {alg}
                </span>
              ))}
            </div>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', marginTop: '0.5rem' }}>
              Standard: {cert.standard}
            </p>
          </div>

          {/* Integrity Section */}
          <div style={{
            padding: '1rem',
            background: 'rgba(0,0,0,0.15)',
            borderRadius: '8px',
            borderTop: '1px solid rgba(255,255,255,0.1)',
          }}>
            <p style={{
              color: 'var(--text-muted)',
              fontSize: '0.75rem',
              fontFamily: '"JetBrains Mono", monospace',
              margin: '0 0 0.25rem',
            }}>
              CBOM Hash: {cert.cbom_hash}
            </p>
            <p style={{
              color: 'var(--text-muted)',
              fontSize: '0.75rem',
              fontFamily: '"JetBrains Mono", monospace',
              margin: 0,
            }}>
              HMAC-SHA256: {cert.signature?.slice(0, 32)}...
            </p>
          </div>

          {/* Footer */}
          <div style={{
            textAlign: 'center',
            marginTop: '2rem',
            paddingTop: '1.5rem',
            borderTop: `1px solid rgba(255,255,255,0.1)`,
          }}>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', margin: 0 }}>
              This certificate is digitally signed and can be independently verified.
            </p>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.75rem', marginTop: '0.5rem' }}>
              Punjab National Bank Cybersecurity Hackathon 2026 — Team CacheMe
            </p>
          </div>
        </motion.div>

      </div>
    </div>
  );
}

function DetailRow({ label, value, accent, mono }) {
  return (
    <div style={{
      padding: '0.75rem 1rem',
      background: 'rgba(0,0,0,0.15)',
      borderRadius: '6px',
    }}>
      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
        {label}
      </div>
      <div style={{
        fontSize: '0.95rem',
        fontWeight: 600,
        color: accent || 'var(--text-primary)',
        fontFamily: mono ? '"JetBrains Mono", monospace' : 'inherit',
        wordBreak: 'break-all',
      }}>
        {value}
      </div>
    </div>
  );
}

export default Certificate;
