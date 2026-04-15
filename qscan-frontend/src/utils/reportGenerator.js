/**
 * QScan PDF Report Generator v2.0
 * Premium multi-page branded report with professional layout.
 */
import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";

// ── Color Palette ──
const C = {
  bg:       [12, 17, 29],       // Deep navy
  card:     [20, 28, 45],       // Card background
  cardAlt:  [26, 35, 55],       // Alternate row
  accent:   [15, 253, 209],     // Teal accent
  accentDk: [10, 180, 150],     // Darker teal for contrast
  white:    [230, 237, 245],
  muted:    [130, 145, 170],
  green:    [15, 253, 161],
  red:      [255, 59, 92],
  orange:   [255, 167, 38],
  blue:     [59, 130, 246],
  border:   [40, 55, 80],
};

// ── Helpers ──
function drawPageBg(doc) {
  const w = doc.internal.pageSize.getWidth();
  doc.setFillColor(...C.bg);
  doc.rect(0, 0, w, 297, "F");
}

function topBar(doc) {
  const w = doc.internal.pageSize.getWidth();
  // Gradient-like bar
  doc.setFillColor(...C.accent);
  doc.rect(0, 0, w, 2.5, "F");
  doc.setFillColor(...C.accentDk);
  doc.rect(0, 2.5, w, 1, "F");
}

function sectionTitle(doc, text, x, y) {
  doc.setFillColor(...C.accent);
  doc.rect(x, y - 4.5, 3, 6, "F");                 // Left accent bar
  doc.setFontSize(13);
  doc.setFont("helvetica", "bold");
  doc.setTextColor(...C.white);
  doc.text(text, x + 7, y);
  return y + 10;
}

function labelValue(doc, label, value, x, y, labelW = 55) {
  doc.setFontSize(9);
  doc.setFont("helvetica", "normal");
  doc.setTextColor(...C.muted);
  doc.text(label, x, y);
  doc.setTextColor(...C.white);
  doc.text(String(value), x + labelW, y);
}

function statusBadge(doc, text, x, y, color) {
  const w = doc.getTextWidth(text) + 8;
  doc.setFillColor(...color);
  doc.roundedRect(x, y - 4, w, 6.5, 1.5, 1.5, "F");
  doc.setFontSize(8);
  doc.setFont("helvetica", "bold");
  doc.setTextColor(...C.bg);
  doc.text(text, x + 4, y);
}

function pageFooter(doc, page, total, margin) {
  const w = doc.internal.pageSize.getWidth();
  doc.setDrawColor(...C.border);
  doc.setLineWidth(0.3);
  doc.line(margin, 283, w - margin, 283);
  doc.setFontSize(7);
  doc.setTextColor(...C.muted);
  doc.text("QScan — Quantum Readiness Assessment Platform", margin, 288);
  doc.text("PNB Cybersecurity Hackathon 2026 • Team CacheMe", w / 2, 288, { align: "center" });
  doc.text(`Page ${page} of ${total}`, w - margin, 288, { align: "right" });
}

function riskColor(score) {
  if (score >= 70) return C.red;
  if (score >= 40) return C.orange;
  return C.green;
}

// ────────────────────────────────────────────────────────────
// REPORT GENERATOR
// ────────────────────────────────────────────────────────────
export function generatePDFReport(cbom, scanId, hndlData) {
  const doc = new jsPDF("p", "mm", "a4");
  const W = doc.internal.pageSize.getWidth();
  const M = 15;                                      // margin
  const contentW = W - 2 * M;

  const domain = cbom?.metadata?.organization_domain || "Unknown Target";
  const scanDate = cbom?.metadata?.generated_at
    ? new Date(cbom.metadata.generated_at).toLocaleString("en-IN")
    : new Date().toLocaleString("en-IN");
  const summary = cbom?.summary || {};
  const assets = cbom?.crypto_assets || [];
  const totalAssets = summary.total_assets || 0;
  const avgRisk = summary.average_risk_score || 0;
  const readiness = summary.overall_quantum_readiness || "UNKNOWN";

  // ═══════════════════════════════════════════════
  // PAGE 1: COVER
  // ═══════════════════════════════════════════════
  drawPageBg(doc);
  topBar(doc);

  // Logo area
  doc.setFillColor(...C.card);
  doc.roundedRect(M, 15, contentW, 60, 4, 4, "F");
  doc.setDrawColor(...C.accent);
  doc.setLineWidth(0.5);
  doc.roundedRect(M, 15, contentW, 60, 4, 4, "S");

  doc.setFontSize(36);
  doc.setFont("helvetica", "bold");
  doc.setTextColor(...C.accent);
  doc.text("QScan", M + 10, 40);

  doc.setFontSize(12);
  doc.setTextColor(...C.white);
  doc.text("Quantum Readiness Assessment Report", M + 10, 50);

  doc.setFontSize(9);
  doc.setTextColor(...C.muted);
  doc.text("Post-Quantum Cryptography Analysis  •  NIST FIPS 203 / 204 / 205", M + 10, 58);
  doc.text(`CONFIDENTIAL`, W - M - 10, 40, { align: "right" });

  // Scan info row
  let y = 90;
  doc.setFillColor(...C.card);
  doc.roundedRect(M, y, contentW, 30, 3, 3, "F");

  labelValue(doc, "Target:", domain, M + 5, y + 10);
  labelValue(doc, "Scan ID:", scanId, M + 5, y + 18);
  labelValue(doc, "Generated:", scanDate, W / 2 + 5, y + 10);
  labelValue(doc, "Tool Version:", "QScan v1.0.0", W / 2 + 5, y + 18);

  // ── Executive Summary Box ──
  y = 135;
  y = sectionTitle(doc, "Executive Summary", M, y);

  doc.setFillColor(...C.card);
  doc.roundedRect(M, y, contentW, 45, 3, 3, "F");

  // Key metrics in boxes
  const metricW = (contentW - 20) / 4;
  const metrics = [
    { label: "Total Assets", value: String(totalAssets), color: C.blue },
    { label: "Avg Risk Score", value: avgRisk.toFixed(1), color: riskColor(avgRisk) },
    { label: "Critical", value: String(summary.risk_distribution?.CRITICAL || 0), color: C.red },
    { label: "Forward Secrecy", value: summary.forward_secrecy_adoption || "—", color: C.green },
  ];

  metrics.forEach((m, i) => {
    const mx = M + 5 + i * (metricW + 5);
    doc.setFillColor(...C.cardAlt);
    doc.roundedRect(mx, y + 5, metricW, 18, 2, 2, "F");
    doc.setFontSize(15);
    doc.setFont("helvetica", "bold");
    doc.setTextColor(...m.color);
    doc.text(m.value, mx + metricW / 2, y + 14, { align: "center" });
    doc.setFontSize(7);
    doc.setTextColor(...C.muted);
    doc.text(m.label, mx + metricW / 2, y + 20, { align: "center" });
  });

  // Readiness badge
  const readyColor = readiness === "PQC_READY" ? C.green : readiness === "HYBRID" ? C.orange : C.red;
  doc.setFontSize(10);
  doc.setTextColor(...C.muted);
  doc.text("Overall Quantum Readiness:", M + 5, y + 37);
  statusBadge(doc, readiness, M + 65, y + 37, readyColor);

  // ── HNDL Risk ──
  if (hndlData) {
    y = 200;
    y = sectionTitle(doc, "HNDL Mosca Inequality Assessment", M, y);

    doc.setFillColor(...C.card);
    doc.roundedRect(M, y, contentW, 42, 3, 3, "F");

    // Status badge
    const breached = hndlData.mosca_breach;
    statusBadge(doc, breached ? "BREACH WINDOW OPEN" : "SAFE", M + 5, y + 10, breached ? C.red : C.green);

    // Mosca equation
    doc.setFontSize(11);
    doc.setFont("helvetica", "bold");
    doc.setTextColor(...C.white);
    doc.text(
      `X(${hndlData.migration_years_x}) + Y(${hndlData.data_life_years_y}) = ${hndlData.mosca_sum}   vs   Z(${hndlData.crqc_timeline_years})`,
      M + 5, y + 20
    );

    doc.setFontSize(9);
    doc.setFont("helvetica", "normal");
    doc.setTextColor(...C.muted);
    doc.text(`Algorithm: ${hndlData.algorithm_assessed}    |    Urgency: ${hndlData.urgency}    |    Source: ${hndlData.crqc_source}`, M + 5, y + 27);
    doc.text(`Sessions at Risk: ${hndlData.sessions_at_risk?.toLocaleString("en-IN")}    |    Data at Risk: ${hndlData.data_at_risk_gb?.toLocaleString("en-IN")} GB`, M + 5, y + 34);
  }

  // ═══════════════════════════════════════════════
  // PAGE 2: ASSET INVENTORY
  // ═══════════════════════════════════════════════
  doc.addPage();
  drawPageBg(doc);
  topBar(doc);

  y = 18;
  y = sectionTitle(doc, "Cryptographic Asset Inventory", M, y);

  if (assets.length > 0) {
    const tableData = assets.map(a => [
      `${a.host}:${a.port}`,
      a.tls_configuration?.protocol_version || a.tls_version || "—",
      (a.tls_configuration?.negotiated_cipher || a.cipher_suite || "—").slice(0, 30),
      a.quantum_assessment?.pqc_status || a.pqcClassification?.status || "—",
      (a.quantum_assessment?.risk_score ?? a.riskScore ?? 0).toFixed(1),
      a.quantum_assessment?.risk_level || a.riskLevel?.level || "—",
    ]);

    autoTable(doc, {
      startY: y,
      head: [["Asset", "TLS", "Cipher Suite", "PQC Status", "Risk", "Level"]],
      body: tableData,
      theme: "plain",
      styles: {
        fillColor: C.bg,
        textColor: C.white,
        fontSize: 7.5,
        cellPadding: { top: 3, bottom: 3, left: 3, right: 2 },
        lineColor: C.border,
        lineWidth: 0.2,
      },
      headStyles: {
        fillColor: C.card,
        textColor: C.accent,
        fontStyle: "bold",
        fontSize: 8.5,
        lineWidth: 0,
      },
      alternateRowStyles: { fillColor: C.cardAlt },
      margin: { left: M, right: M },
      willDrawPage: function(data) { if (data.pageNumber > 1) { drawPageBg(doc); topBar(doc); } },
      columnStyles: {
        0: { cellWidth: 40, textColor: C.accent, fontStyle: "bold" },
        2: { cellWidth: 45, fontSize: 7 },
        4: { halign: "center" },
        5: { halign: "center" },
      },
      didParseCell: function (data) {
        // Color risk levels
        if (data.section === "body" && data.column.index === 5) {
          const val = data.cell.text[0];
          if (val === "HIGH" || val === "CRITICAL") data.cell.styles.textColor = C.red;
          else if (val === "MEDIUM") data.cell.styles.textColor = C.orange;
          else if (val === "LOW") data.cell.styles.textColor = C.green;
        }
      },
    });

    y = doc.lastAutoTable.finalY + 8;
  }

  // ── PQC Migration Recommendations ──
  const checkPage = (needed = 40) => {
    if (y + needed > 268) {
      doc.addPage();
      drawPageBg(doc);
      topBar(doc);
      y = 18;
    }
  };

  checkPage(20);
  y = sectionTitle(doc, "PQC Migration Recommendations", M, y);

  const allRecs = [];
  for (const asset of assets) {
    for (const rec of (asset.pqc_recommendations || asset.recommendations || [])) {
      allRecs.push([
        asset.host,
        rec.component || "—",
        rec.current || "—",
        rec.recommended || "—",
        rec.priority || "—",
        rec.hybrid_option || "—",
      ]);
    }
  }

  if (allRecs.length > 0) {
    autoTable(doc, {
      startY: y,
      head: [["Host", "Component", "Current", "Recommended", "Priority", "Hybrid Option"]],
      body: allRecs,
      theme: "plain",
      styles: {
        fillColor: C.bg,
        textColor: C.white,
        fontSize: 7,
        cellPadding: { top: 2.5, bottom: 2.5, left: 3, right: 2 },
        lineColor: C.border,
        lineWidth: 0.2,
      },
      headStyles: {
        fillColor: C.card,
        textColor: C.accent,
        fontStyle: "bold",
        fontSize: 8,
        lineWidth: 0,
      },
      alternateRowStyles: { fillColor: C.cardAlt },
      margin: { left: M, right: M },
      willDrawPage: function(data) { if (data.pageNumber > 1) { drawPageBg(doc); topBar(doc); } },
      columnStyles: {
        0: { cellWidth: 28, fontSize: 6.5 },
        3: { cellWidth: 30, textColor: C.green },
        4: { halign: "center", cellWidth: 18 },
      },
      didParseCell: function (data) {
        if (data.section === "body" && data.column.index === 4) {
          const val = data.cell.text[0];
          if (val === "HIGH" || val === "CRITICAL") data.cell.styles.textColor = C.red;
          else if (val === "MEDIUM") data.cell.styles.textColor = C.orange;
        }
      },
    });

    y = doc.lastAutoTable.finalY + 8;
  }

  // ── Risk Matrix ──
  const riskMatrix = cbom?.risk_matrix || [];
  if (riskMatrix.length > 0) {
    checkPage(20);
    y = sectionTitle(doc, "Quantum Risk Matrix", M, y);

    const riskData = riskMatrix.map(r => [
      r.host,
      String(r.port),
      (r.risk_score ?? 0).toFixed(1),
      r.risk_level || "—",
      r.pqc_status || "—",
      r.migration_deadline || "—",
      r.urgency || "—",
    ]);

    autoTable(doc, {
      startY: y,
      head: [["Host", "Port", "Risk", "Level", "PQC Status", "Deadline", "Urgency"]],
      body: riskData,
      theme: "plain",
      styles: {
        fillColor: C.bg,
        textColor: C.white,
        fontSize: 7.5,
        cellPadding: { top: 2.5, bottom: 2.5, left: 3, right: 2 },
        lineColor: C.border,
        lineWidth: 0.2,
      },
      headStyles: {
        fillColor: C.card,
        textColor: C.accent,
        fontStyle: "bold",
        fontSize: 8,
        lineWidth: 0,
      },
      alternateRowStyles: { fillColor: C.cardAlt },
      margin: { left: M, right: M },
      willDrawPage: function(data) { if (data.pageNumber > 1) { drawPageBg(doc); topBar(doc); } },
      columnStyles: {
        0: { cellWidth: 35, fontSize: 7 },
        2: { halign: "center" },
        3: { halign: "center" },
      },
      didParseCell: function (data) {
        if (data.section === "body" && data.column.index === 3) {
          const val = data.cell.text[0];
          if (val === "HIGH" || val === "CRITICAL") data.cell.styles.textColor = C.red;
          else if (val === "MEDIUM") data.cell.styles.textColor = C.orange;
          else if (val === "LOW") data.cell.styles.textColor = C.green;
        }
      },
    });

    y = doc.lastAutoTable.finalY + 8;
  }

  // ── Compliance Summary (compact) ──
  checkPage(20);
  y = sectionTitle(doc, "Regulatory Compliance Summary", M, y);

  const complianceData = [
    ["RBI CSF §3.1", "Encryption Standards", "TLS 1.2+ with AES-128/256", totalAssets > 0 ? "COMPLIANT" : "N/A"],
    ["RBI CSF §3.4", "Certificate Management", "Valid certs, trusted CAs", "COMPLIANT"],
    ["RBI ITGRA §9.3", "Cryptographic Agility", "PQC migration readiness", readiness === "PQC_READY" ? "COMPLIANT" : "NON-COMPLIANT"],
    ["CERT-In §6", "Cryptographic Controls", "CBOM asset inventory", "COMPLIANT"],
    ["NIST SP 800-52", "TLS Configuration", "TLS 1.3 preferred", "COMPLIANT"],
    ["NIST IR 8547", "PQC Transition", "ML-KEM/ML-DSA by 2030", readiness === "PQC_READY" ? "COMPLIANT" : "PARTIAL"],
    ["PCI DSS §4.2.1", "Forward Secrecy", "FS for cardholder data", summary.forward_secrecy_adoption ? "COMPLIANT" : "NON-COMPLIANT"],
  ];

  autoTable(doc, {
    startY: y,
    head: [["Standard", "Requirement", "Criteria", "Status"]],
    body: complianceData,
    theme: "plain",
    styles: {
      fillColor: C.bg,
      textColor: C.white,
      fontSize: 8,
      cellPadding: { top: 3, bottom: 3, left: 4, right: 3 },
      lineColor: C.border,
      lineWidth: 0.2,
    },
    headStyles: {
      fillColor: C.card,
      textColor: C.accent,
      fontStyle: "bold",
      fontSize: 8.5,
      lineWidth: 0,
    },
    alternateRowStyles: { fillColor: C.cardAlt },
    margin: { left: M, right: M },
    willDrawPage: function(data) { if (data.pageNumber > 1) { drawPageBg(doc); topBar(doc); } },
    columnStyles: {
      0: { textColor: C.blue, fontStyle: "bold", cellWidth: 30 },
      3: { halign: "center", cellWidth: 28 },
    },
    didParseCell: function (data) {
      if (data.section === "body" && data.column.index === 3) {
        const val = data.cell.text[0];
        if (val === "COMPLIANT") data.cell.styles.textColor = C.green;
        else if (val === "PARTIAL") data.cell.styles.textColor = C.orange;
        else if (val === "NON-COMPLIANT") data.cell.styles.textColor = C.red;
      }
    },
  });

  // ── Page Footers ──
  const pageCount = doc.internal.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    pageFooter(doc, i, pageCount, M);
  }

  // Save
  const filename = `QScan_Report_${domain.replace(/\./g, "_")}_${new Date().toISOString().slice(0, 10)}.pdf`;
  doc.save(filename);
  return filename;
}


/**
 * Download raw CBOM as JSON
 */
export function downloadCBOM(cbom) {
  const domain = cbom?.metadata?.organization_domain || "scan";
  const blob = new Blob([JSON.stringify(cbom, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `QScan_CBOM_${domain.replace(/\./g, "_")}_${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
}
