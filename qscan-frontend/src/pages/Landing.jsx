import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Zap, BarChart3, Lock } from 'lucide-react';
import { scanApi } from '../api/scanApi';
import './pages.css';

function Landing() {
  const [stats, setStats] = useState([
    { label: 'Scans Completed', value: '—', color: 'var(--accent-blue)' },
    { label: 'High-Risk Assets', value: '—', color: 'var(--accent-danger)' },
    { label: 'PQC Ready', value: '—', color: 'var(--accent-safe)' },
  ]);

  useEffect(() => {
    scanApi.getHistory()
      .then(res => {
        const scans = res.data || [];
        const completed = scans.filter(s => s.status === 'completed');
        const totalAssets = completed.reduce((sum, s) => sum + (s.assets_found || 0), 0);
        const highRisk = completed.filter(s => s.risk_score && s.risk_score >= 60).length;
        setStats([
          { label: 'Scans Completed', value: String(completed.length), color: 'var(--accent-blue)' },
          { label: 'High-Risk Targets', value: String(highRisk), color: 'var(--accent-danger)' },
          { label: 'Total Assets Found', value: String(totalAssets), color: 'var(--accent-safe)' },
        ]);
      })
      .catch(() => {
        // API not available — show zeros
        setStats([
          { label: 'Scans Completed', value: '0', color: 'var(--accent-blue)' },
          { label: 'High-Risk Targets', value: '0', color: 'var(--accent-danger)' },
          { label: 'Total Assets Found', value: '0', color: 'var(--accent-safe)' },
        ]);
      });
  }, []);

  const features = [
    {
      icon: <Lock size={32} />,
      title: 'Cryptographic Inventory',
      description: 'Discover all TLS certificates, VPN endpoints, and API cipher suites with detailed analysis'
    },
    {
      icon: <BarChart3 size={32} />,
      title: 'CBOM Generation',
      description: 'Automatically generate comprehensive Cryptographic Bill of Materials for your infrastructure'
    },
    {
      icon: <Zap size={32} />,
      title: 'PQC Certification',
      description: 'Assess quantum-safety status and generate PQC readiness certificates'
    }
  ];

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: 0.1,
        delayChildren: 0.2,
      },
    },
  };

  const itemVariants = {
    hidden: { opacity: 0, y: 20 },
    visible: {
      opacity: 1,
      y: 0,
      transition: { duration: 0.6 },
    },
  };

  return (
    <>
      {/* Hero Section */}
      <section className="hero">
        <div className="scanline-overlay"></div>
        <div className="grid-bg" style={{ position: 'absolute', inset: 0, zIndex: 0 }}></div>
        
        <div className="hero-content">
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
          >
            <h1>Quantum-Proof Your Banking Infrastructure</h1>
            <p className="hero-subtext">
              Scan, assess, and certify your cryptographic readiness before quantum computers break your encryption.
            </p>
          </motion.div>

          <motion.div
            className="hero-ctas"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, delay: 0.2 }}
          >
            <Link to="/scan" className="btn btn-primary btn-lg">
              → Start New Scan
            </Link>
            <Link to="/history" className="btn btn-secondary btn-lg">
              View Past Scans
            </Link>
          </motion.div>
        </div>

        <motion.div
          className="hero-glow"
          animate={{
            scale: [1, 1.1, 1],
            opacity: [0.5, 0.8, 0.5]
          }}
          transition={{
            duration: 4,
            repeat: Infinity
          }}
        />
      </section>

      {/* Features Section */}
      <section className="section">
        <div className="container">
          <motion.div
            variants={containerVariants}
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true }}
          >
            <h2 style={{ textAlign: 'center', marginBottom: '3rem' }}>How It Works</h2>
            <div className="grid grid-3">
              {features.map((feature, idx) => (
                <motion.div
                  key={idx}
                  className="card glass glass-hover"
                  variants={itemVariants}
                >
                  <div style={{ color: 'var(--accent-quantum)', marginBottom: '1rem' }}>
                    {feature.icon}
                  </div>
                  <h3>{feature.title}</h3>
                  <p>{feature.description}</p>
                </motion.div>
              ))}
            </div>
          </motion.div>
        </div>
      </section>

      {/* Stats Section */}
      <section className="section" style={{ backgroundColor: 'var(--bg-secondary)' }}>
        <div className="container">
          <h2 style={{ textAlign: 'center', marginBottom: '3rem' }}>Platform Statistics</h2>
          <div className="grid grid-3">
            {stats.map((stat, idx) => (
              <motion.div
                key={idx}
                className="stat-card"
                initial={{ opacity: 0, scale: 0.8 }}
                whileInView={{ opacity: 1, scale: 1 }}
                transition={{ duration: 0.5, delay: idx * 0.1 }}
                viewport={{ once: true }}
              >
                <motion.div
                  className="stat-value"
                  style={{ color: stat.color }}
                  initial={{ opacity: 0 }}
                  whileInView={{ opacity: 1 }}
                  transition={{ duration: 1, delay: idx * 0.1 + 0.3 }}
                  viewport={{ once: true }}
                >
                  {stat.value}
                </motion.div>
                <div className="stat-label">{stat.label}</div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* NIST PQC Section */}
      <section className="section">
        <div className="container">
          <h2 style={{ textAlign: 'center', marginBottom: '2rem' }}>NIST Post-Quantum Cryptography</h2>
          <div className="nist-badges">
            {['ML-KEM', 'ML-DSA', 'SLH-DSA', 'X25519'].map((alg, idx) => (
              <motion.div
                key={idx}
                className="badge badge-safe"
                style={{ padding: '0.8rem 1.5rem', fontSize: '1rem', cursor: 'pointer' }}
                whileHover={{ scale: 1.1 }}
                whileTap={{ scale: 0.95 }}
              >
                {alg}
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="section" style={{ textAlign: 'center', backgroundColor: 'var(--bg-secondary)' }}>
        <div className="container">
          <h2>Ready to Assess Your Quantum Readiness?</h2>
          <p style={{ fontSize: '1.1rem', marginBottom: '2rem' }}>
            Start scanning your infrastructure today and get a comprehensive cryptographic assessment.
          </p>
          <Link to="/scan" className="btn btn-primary btn-lg">
            Launch Scanner
          </Link>
        </div>
      </section>
    </>
  );
}

export default Landing;
