const { parse: csvParse } = require('csv-parse/sync');
const { v4: uuidv4 } = require('uuid');

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
 * Detect CSV format by inspecting headers.
 * Returns { type: 'rapid7'|'unknown', headers: string[], mapping?: object }
 */
async function detectCSVFormat(csvContent) {
  const records = csvParse(csvContent, {
    columns: true,
    skip_empty_lines: true,
    to: 1, // just read first row to get headers
    relax_column_count: true,
  });

  if (records.length === 0) {
    // Try to get headers from first line
    const firstLine = csvContent.split('\n')[0] || '';
    const headers = firstLine.split(',').map((h) => h.trim().replace(/^"|"$/g, ''));
    return { type: 'unknown', headers };
  }

  const headers = Object.keys(records[0]);
  const lowerHeaders = headers.map((h) => h.toLowerCase().trim());

  // Check for Rapid7 pattern
  const isRapid7 = RAPID7_HEADERS.every((rh) => lowerHeaders.includes(rh));
  if (isRapid7) {
    return { type: 'rapid7', headers };
  }

  return { type: 'unknown', headers };
}

/**
 * Parse a generic CSV using a user-provided field mapping.
 * mapping: { asset_identifier: 'CSV Column', weakness_name: 'CSV Column', ... }
 */
async function parseGenericCSV(csvContent, fileName, mapping, onProgress) {
  const records = csvParse(csvContent, {
    columns: true,
    skip_empty_lines: true,
    relax_column_count: true,
  });

  const findings = [];
  const total = records.length;

  for (let i = 0; i < total; i++) {
    const row = records[i];

    const rawSeverity = mapping.original_risk_rating ? row[mapping.original_risk_rating] || '' : '';
    let severity = rawSeverity;
    // Try to interpret severity
    const sLower = rawSeverity.toLowerCase().trim();
    if (['critical', 'high', 'moderate', 'medium', 'low', 'informational', 'info'].includes(sLower)) {
      if (sLower === 'medium') severity = 'Moderate';
      else if (sLower === 'info') severity = 'Informational';
      else severity = sLower.charAt(0).toUpperCase() + sLower.slice(1);
    } else {
      // Try as CVSS
      severity = mapCVSStoRisk(rawSeverity);
    }

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

module.exports = { parseGenericCSV, detectCSVFormat };
