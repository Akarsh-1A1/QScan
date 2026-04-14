import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import toast from 'react-hot-toast';
import { useStartScan, useScan } from '../hooks/useScan';
import './pages.css';

function NewScan() {
  const [activeTab, setActiveTab] = useState('single');
  const [target, setTarget] = useState('');
  const [scanTypes, setScanTypes] = useState([
    'tls_analysis',
    'cipher_detection',
    'certificate_validation'
  ]);
  const [discover, setDiscover] = useState(false);
  const [vpn, setVpn] = useState(false);
  const navigate = useNavigate();

  const { scanId, loading: starting, error: startError, startScan } = useStartScan();
  const { scan, progress, logs } = useScan(scanId);

  const handleScanTypeChange = (type) => {
    setScanTypes(prev =>
      prev.includes(type)
        ? prev.filter(t => t !== type)
        : [...prev, type]
    );
  };

  const handleLaunchScan = async (e) => {
    e.preventDefault();

    if (!target.trim()) {
      toast.error('Please enter a target domain or IP');
      return;
    }

    try {
      const id = await startScan(target, scanTypes, discover, vpn);
      toast.success(`Scan ${id} started!`);
    } catch (err) {
      toast.error(`Failed to start scan: ${err.message}`);
    }
  };

  // Auto-redirect when scan completes
  React.useEffect(() => {
    if (scan && (scan.status === 'completed' || scan.status === 'complete') && scanId) {
      toast.success('Scan complete! Redirecting to results...');
      setTimeout(() => navigate(`/results/${scanId}`), 2000);
    }
  }, [scan, scanId, navigate]);

  if (scanId && scan && scan.status !== 'completed' && scan.status !== 'complete') {
    return (
      <div style={{ minHeight: '100vh' }}>
        <div className="container" style={{ padding: '3rem 0' }}>
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
          >
            <h2>Scanning {target}</h2>
            <p style={{ color: 'var(--text-muted)', marginBottom: '2rem' }}>
              Scan ID: <code>{scanId}</code>
            </p>

            <div className="progress-bar">
              <motion.div
                className="progress-fill"
                initial={{ width: '0%' }}
                animate={{ width: `${progress}%` }}
                transition={{ duration: 0.3 }}
                style={{ width: `${Math.min(progress, 100)}%` }}
              />
            </div>

            <p style={{ textAlign: 'center', marginBottom: '2rem' }}>
              {progress}% Complete
            </p>

            <div className="progress-terminal">
              {logs.map((log, idx) => (
                <motion.div
                  key={idx}
                  className="terminal-line"
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                >
                  {log}
                </motion.div>
              ))}
              {logs.length === 0 && <div className="terminal-line">Initializing scan...</div>}
              <span className="terminal-cursor"></span>
            </div>
          </motion.div>
        </div>
      </div>
    );
  }

  return (
    <div style={{ minHeight: '100vh' }}>
      <div className="container" style={{ padding: '3rem 0', maxWidth: '800px' }}>
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
        >
          <h2>Start a New Scan</h2>
          <p style={{ color: 'var(--text-muted)', marginBottom: '2rem' }}>
            Enter your target and configure scan options to begin quantum readiness assessment.
          </p>

          <form onSubmit={handleLaunchScan} className="scan-form">
            {/* Tabs */}
            <div className="tab-selector">
              <button
                type="button"
                className={`tab-btn ${activeTab === 'single' ? 'active' : ''}`}
                onClick={() => setActiveTab('single')}
              >
                Single Target
              </button>
              <button
                type="button"
                className={`tab-btn ${activeTab === 'bulk' ? 'active' : ''}`}
                onClick={() => setActiveTab('bulk')}
              >
                Bulk Import
              </button>
            </div>

            {/* Target Input */}
            <div className="form-group">
              <label>Target Domain / IP / CIDR</label>
              <input
                type="text"
                placeholder="e.g., api.pnb.co.in or 103.25.x.x"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                className="glass"
              />
            </div>

            {/* Scan Types */}
            <div className="form-group">
              <label>Scan Types</label>
              <div className="checkbox-group">
                {[
                  { id: 'tls_analysis', label: 'TLS Certificate Analysis' },
                  { id: 'cipher_detection', label: 'Cipher Suite Detection' },
                  { id: 'certificate_validation', label: 'Certificate Validation' },
                  { id: 'key_exchange', label: 'Key Exchange Algorithm' },
                  { id: 'security_headers', label: 'Security Headers' },
                  { id: 'api_detection', label: 'API Endpoint Detection' }
                ].map(type => (
                  <div key={type.id} className="checkbox-item">
                    <input
                      type="checkbox"
                      id={type.id}
                      checked={scanTypes.includes(type.id)}
                      onChange={() => handleScanTypeChange(type.id)}
                    />
                    <label htmlFor={type.id}>{type.label}</label>
                  </div>
                ))}
              </div>
            </div>

            {/* Options */}
            <div className="form-group">
              <div className="checkbox-item">
                <input
                  type="checkbox"
                  id="discover"
                  checked={discover}
                  onChange={(e) => setDiscover(e.target.checked)}
                />
                <label htmlFor="discover">Enable Asset Discovery (subdomain enumeration)</label>
              </div>
              <div className="checkbox-item" style={{ marginTop: '0.5rem' }}>
                <input
                  type="checkbox"
                  id="vpn"
                  checked={vpn}
                  onChange={(e) => setVpn(e.target.checked)}
                />
                <label htmlFor="vpn">
                  Enable VPN Scanning (IKEv2/IPsec, OpenVPN, SSL VPN, WireGuard)
                </label>
              </div>
            </div>

            {/* Error Display */}
            {startError && (
              <motion.div
                className="card card-danger"
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
                style={{ marginBottom: '1.5rem' }}
              >
                {startError}
              </motion.div>
            )}

            {/* Submit Button */}
            <motion.button
              type="submit"
              className="btn btn-primary"
              style={{ width: '100%', padding: '1rem', marginTop: '1.5rem' }}
              disabled={starting}
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
            >
              {starting ? 'Starting Scan...' : '→ Launch Scan'}
            </motion.button>
          </form>

          {/* Info Box */}
          <div className="card" style={{ marginTop: '2rem', padding: '1rem' }}>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
              💡 <strong>Tip:</strong> Standard scan depth is recommended for most organizations. 
              Deep scans include extensive enumeration and may take longer.
            </p>
          </div>
        </motion.div>
      </div>
    </div>
  );
}

export default NewScan;
