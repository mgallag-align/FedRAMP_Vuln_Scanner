const { v4: uuidv4 } = require('uuid');
const { parseCSVSections } = require('./csv-sections');

// Known Rapid7 CSV header patterns
const RAPID7_HEADERS = ['asset ip address', 'vulnerability title'];

/**
 * CVSS score → FedRAMP risk rating
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
  // Qualys: 5=Critical, 4=High, 3=Moderate, 2-1=Low
  // Nessus: 4=Critical, 3=High, 2=Moderate, 1=Low
  // Treat as Qualys-style since 5-level scales are more common in CSV exports
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

/**
 * Detect CSV format by inspecting headers.
 *
 * Section-aware: multi-section files (title block + blank gap + findings table)
 * resolve to the findings section's headers, so detection and the field-mapper
 * dropdown see the real columns rather than title/metadata cells.
 *
 * Returns { type: 'rapid7'|'unknown', headers: string[], sectionWarning?: object }
 */
async function detectCSVFormat(csvContent) {
  const { headers, sectionWarning } = parseCSVSections(csvContent);

  if (headers.length === 0) {
    return { type: 'unknown', headers: [], sectionWarning };
  }

  const lowerHeaders = headers.map((h) => h.toLowerCase().trim());

  // Check for Rapid7 pattern
  const isRapid7 = RAPID7_HEADERS.every((rh) => lowerHeaders.includes(rh));
  if (isRapid7) {
    return { type: 'rapid7', headers, sectionWarning };
  }

  return { type: 'unknown', headers, sectionWarning };
}

/**
 * Apply a user-provided field mapping to already-parsed tabular rows and build
 * Canonical Finding Objects (CFOs).
 *
 * This is format-agnostic: `records` is an array of plain row objects keyed by
 * header name, so it serves CSV, XLSX/XLS, and JSON sources alike (the caller
 * extracts rows with the appropriate parser first).
 *
 * mapping: { asset_identifier: 'Column', weakness_name: 'Column', ... }
 */
function mapRowsToFindings(records, fileName, mapping, onProgress) {
  const findings = [];
  const total = records.length;

  for (let i = 0; i < total; i++) {
    const row = records[i];

    const rawSeverity = mapping.original_risk_rating ? row[mapping.original_risk_rating] : '';
    const severity = normalizeSeverity(rawSeverity);

    const scanTypeRaw = mapping.scan_type ? (row[mapping.scan_type] || '').toLowerCase() : '';
    const scanType =
      scanTypeRaw.includes('config') || scanTypeRaw.includes('compliance')
        ? 'CONFIG_FINDING'
        : 'VULNERABILITY';

    const cfo = {
      cfo_id: uuidv4(),
      scanner_source: `${fileName} | Generic CSV`,
      weakness_name: mapping.weakness_name ? row[mapping.weakness_name] || '' : '',
      weakness_description: mapping.weakness_description
        ? row[mapping.weakness_description] || ''
        : '',
      weakness_source_identifier: mapping.weakness_source_identifier
        ? row[mapping.weakness_source_identifier] || ''
        : '',
      asset_identifier: mapping.asset_identifier ? row[mapping.asset_identifier] || '' : '',
      original_detection_date: mapping.original_detection_date
        ? row[mapping.original_detection_date] || null
        : null,
      original_risk_rating: severity,
      scan_type: scanType,
      is_authenticated: null,
      iiw_match_status: null,
      vendor_dependency: false,
      vendor_name: '',
      hardening_benchmark: mapping.hardening_benchmark
        ? row[mapping.hardening_benchmark] || ''
        : '',
      compliance_result: null,
      compliance_actual_value: '',
      compliance_policy_value: '',
      assessor_comments: '',
      ret_id: null,
      mark_as_rcdt: false,
    };

    findings.push(cfo);
    if (onProgress && i % 100 === 0) onProgress((i / total) * 100);
  }

  if (onProgress) onProgress(100);
  return findings;
}

/**
 * Parse a generic CSV string using a user-provided field mapping.
 *
 * Section-aware: selects the findings table even when the file begins with a
 * title/summary block and blank separator rows, and skips blank rows within
 * the table so trailing findings are not dropped.
 */
async function parseGenericCSV(csvContent, fileName, mapping, onProgress) {
  const { rows: records } = parseCSVSections(csvContent);
  return mapRowsToFindings(records, fileName, mapping, onProgress);
}

module.exports = { parseGenericCSV, mapRowsToFindings, detectCSVFormat };
