import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { useScanHistory } from '../hooks/useScan';
import { motion } from 'framer-motion';
import { Trash2 } from 'lucide-react';
import { EmptyState, RiskBadge } from '../components/common/badges';
import toast from 'react-hot-toast';
import './pages.css';

function History() {
  const { history, loading, deleteScan, refetch } = useScanHistory(); // ✅ added refetch
  const [searchTerm, setSearchTerm] = useState('');

  const filteredHistory = history.filter(scan =>
    (scan.domain || scan.target).toLowerCase().includes(searchTerm.toLowerCase()) ||
    scan.scan_id.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handleDelete = async (scanId) => {
    if (window.confirm('Are you sure you want to delete this scan?')) {
      try {
        await deleteScan(scanId);
        toast.success('Scan deleted');
      } catch (err) {
        toast.error('Failed to delete scan');
      }
    }
  };

  if (loading) {
    return <div className="container"><p>Loading history...</p></div>;
  }

  if (history.length === 0) {
    return (
      <div className="container" style={{ padding: '3rem 0', minHeight: '60vh', display: 'flex', alignItems: 'center' }}>
        <EmptyState
          icon="📭"
          title="No Scans Yet"
          message="Start a new scan to see results here"
          action={<Link to="/scan" className="btn btn-primary">Start Scan</Link>}
        />
      </div>
    );
  }

  return (
    <div style={{ minHeight: '100vh' }}>
      <div className="container" style={{ padding: '3rem 0' }}>
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
        >

          {/* 🔥 Header + Refresh */}
          <div style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center"
          }}>
            <div>
              <h2>Scan History</h2>
              <p style={{ color: 'var(--text-muted)', marginBottom: '2rem' }}>
                Showing {filteredHistory.length} of {history.length} scans
              </p>
            </div>

            <button
              onClick={async () => {
                toast.loading("Refreshing...");
                await refetch();
                toast.dismiss();
                toast.success("Updated");
              }}
              style={{
                padding: "0.5rem 1rem",
                borderRadius: "8px",
                border: "1px solid rgba(0,255,170,0.3)",
                background: "linear-gradient(135deg, rgba(0,255,170,0.15), rgba(0,200,255,0.15))",
                color: "#00ffd0",
                cursor: "pointer",
                fontWeight: "500",
                transition: "all 0.2s ease",
              }}
              onMouseOver={(e) => {
                e.target.style.transform = "scale(1.05)";
                e.target.style.boxShadow = "0 0 8px rgba(0,255,170,0.4)";
              }}
              onMouseOut={(e) => {
                e.target.style.transform = "scale(1)";
                e.target.style.boxShadow = "none";
              }}
            >
              🔄 Refresh
            </button>
          </div>

          {/* Search */}
          <div className="history-filter">
            <input
              type="text"
              placeholder="Search by domain or scan ID..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="glass"
            />
          </div>

          {/* Table */}
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Scan ID</th>
                  <th>Target</th>
                  <th>Date</th>
                  <th>Assets Found</th>
                  <th>Risk Score</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredHistory.map((scan, idx) => (
                  <motion.tr
                    key={scan.scan_id}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: idx * 0.05 }}
                  >
                    <td><code>{scan.scan_id.slice(0, 20)}</code></td>
                    <td>{scan.domain || scan.target}</td>
                    <td>{new Date(scan.timestamp).toLocaleDateString()}</td>
                    <td>{scan.assets_found || '—'}</td>
                    <td>
                      <RiskBadge score={scan.risk_score} size="sm" />
                    </td>
                    <td>
                      <span className={`badge badge-${scan.status === 'completed' ? 'safe' : scan.status}`}>
                        {scan.status}
                      </span>
                    </td>
                    <td>
                      <Link
                        to={`/results/${scan.scan_id}`}
                        className="btn btn-sm btn-secondary"
                        style={{ marginRight: '0.5rem' }}
                      >
                        View
                      </Link>
                      <button
                        onClick={() => handleDelete(scan.scan_id)}
                        className="btn btn-sm btn-danger"
                        title="Delete scan"
                      >
                        <Trash2 size={16} />
                      </button>
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>

          {filteredHistory.length === 0 && searchTerm && (
            <EmptyState
              icon="🔍"
              title="No Results"
              message={`No scans found matching "${searchTerm}"`}
            />
          )}

        </motion.div>
      </div>
    </div>
  );
}

export default History;