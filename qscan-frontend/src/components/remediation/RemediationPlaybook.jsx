import React, { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import "./remediation.css";

const PLAYBOOKS = {
  NGINX: {
    name: "Nginx (OpenSSL 3.x)",
    code: `server {
    listen 443 ssl http2;
    server_name example.bank.in;

    # PCI DSS & RBI Compliant TLS
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;

    # Enable Kyber (ML-KEM-768) Hybrid Key Exchange
    # Requires OpenSSL 3.0+ with OQS provider
    ssl_ecdh_curve X25519:X25519+Kyber768;

    # Strong Ciphers
    ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:TLS_AES_256_GCM_SHA384;
}`,
    instructions: [
      "Ensure Nginx is compiled against a quantum-safe fork like OQS-OpenSSL.",
      "Update ssl_ecdh_curve to include X25519+Kyber768 (Hybrid PQC).",
      "Restart Nginx service: sudo systemctl restart nginx",
    ],
  },
  APACHE: {
    name: "Apache HTTP Server",
    code: `<VirtualHost *:443>
    ServerName example.bank.in

    # RBI Compliant Protocols
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1

    # Enable Kyber Hybrid
    # Requires mod_ssl compiled with OQS
    SSLCurve X25519:X25519+Kyber768

    # Honor Cipher Order
    SSLHonorCipherOrder on
    SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
</VirtualHost>`,
    instructions: [
      "Ensure Apache mod_ssl uses a quantum-safe OpenSSL provider.",
      "Add SSLCurve directive to enable ML-KEM-768.",
      "Restart Apache service: sudo systemctl restart apache2",
    ],
  },
  AWS_ALB: {
    name: "AWS App Load Balancer",
    code: `# AWS explicitly supports Hybrid PQC policies
aws elbv2 modify-listener \\
    --listener-arn arn:aws:elasticloadbalancing:... \\
    --ssl-policy TLSHybrid-PQ-2023-06`,
    instructions: [
      "AWS ALB now supports hybrid post-quantum TLS policies natively.",
      "Change the listener policy to TLSHybrid-PQ-2023-06 via Console or CLI.",
      "This enables Kyber hybrid key exchange immediately.",
    ],
  },
};

export default function RemediationPlaybook({ cbom }) {
  const [activeTab, setActiveTab] = useState("NGINX");
  const [copied, setCopied] = useState(false);

  // Extract needed migrations
  const plans = cbom?.pqc_migration_plan || [];
  const needsMigration = plans.length > 0 || cbom?.summary?.overall_quantum_readiness === "NOT_READY";

  if (!needsMigration) return null;

  const currentPlaybook = PLAYBOOKS[activeTab];

  const handleCopy = () => {
    navigator.clipboard.writeText(currentPlaybook.code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <motion.div
      className="remediation-section"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.6, delay: 0.2 }}
    >
      <div className="remediation-header">
        <div>
          <h3>Engineer's Remediation Playbook</h3>
          <p className="remediation-subtitle">
            Copy-paste templates to instantly enable ML-KEM-768 (Kyber) Hybrid PQC on your infrastructure.
          </p>
        </div>
      </div>

      <div className="remediation-container">
        <div className="remediation-tabs">
          {Object.entries(PLAYBOOKS).map(([key, pb]) => (
            <button
              key={key}
              className={`remediation-tab ${activeTab === key ? "active" : ""}`}
              onClick={() => setActiveTab(key)}
            >
              {pb.name}
            </button>
          ))}
        </div>

        <div className="remediation-content">
          <div className="remediation-instructions">
            <h4>Implementation Steps</h4>
            <ol>
              {currentPlaybook.instructions.map((step, i) => (
                <li key={i}>{step}</li>
              ))}
            </ol>
          </div>

          <div className="remediation-code-block">
            <div className="code-header">
              <span>Configuration Snippet</span>
              <button className="copy-btn" onClick={handleCopy}>
                {copied ? "✅ Copied!" : "📋 Copy Code"}
              </button>
            </div>
            <pre>
              <code>{currentPlaybook.code}</code>
            </pre>
          </div>
        </div>
      </div>
    </motion.div>
  );
}
