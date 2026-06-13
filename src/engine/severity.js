/**
 * Shared severity / risk-rating mapping.
 *
 * Centralizes the CVSS→FedRAMP thresholds and the universal severity
 * normalizer so every parser maps severity identically. Scanner-specific
 * integer scales (Nessus 0-4, Qualys 0-5) remain in their own parsers because
 * their numeric meanings differ; this module owns CVSS and free-text handling.
 */

// Lower number = higher risk. Used for sorting and consolidation.
const RISK_ORDER = { Critical: 0, High: 1, Moderate: 2, Low: 3, Informational: 4 };

/**
 * CVSS score (v2/v3 float) → FedRAMP risk rating.
 */
function mapCVSStoRisk(cvss) {
  const score = parseFloat(cvss);
  if (isNaN(score)) return 'Informational';
  if (score >= 9.0) return 'Critical';
  if (score >= 7.0) return 'High';
  if (score >= 4.0) return 'Moderate';
  if (score > 0) return 'Low';
  return 'Informational';
}

/**
 * Normalize any severity/risk string to a FedRAMP risk rating.
 * Handles: text labels (case-insensitive), numeric scanner scales (0-5),
 * CVSS floats, and special values like "Untriaged" or "None".
 */
function normalizeSeverity(rawSeverity) {
  if (rawSeverity === null || rawSeverity === undefined || rawSeverity === '') {
    return 'Informational';
  }
  const s = String(rawSeverity).toLowerCase().trim();

  // Text labels
  switch (s) {
    case 'critical': return 'Critical';
    case 'high': return 'High';
    case 'moderate':
    case 'medium':
    case 'med': return 'Moderate';
    case 'low': return 'Low';
    case 'informational':
    case 'info':
    case 'none':
    case '0': return 'Informational';
    // "Untriaged" — conservative assumption; assessor should review
    case 'untriaged':
    case 'needs review':
    case 'pending': return 'Moderate';
  }

  // Pure single-digit integer (scanner severity scale: 1–5 or 1–4)
  // Treated as a Qualys-style 5-level scale, the most common in CSV exports.
  if (/^\d$/.test(s)) {
    const n = parseInt(s, 10);
    if (n >= 5) return 'Critical';
    if (n === 4) return 'High';
    if (n === 3) return 'Moderate';
    if (n >= 1) return 'Low';
    return 'Informational';
  }

  // CVSS score (float or value > 5)
  return mapCVSStoRisk(s);
}

module.exports = { RISK_ORDER, mapCVSStoRisk, normalizeSeverity };
