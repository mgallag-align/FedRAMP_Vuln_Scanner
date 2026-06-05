/**
 * Normalizer — ensures all CFOs have consistent field types and values.
 * Applied after parsing, before matching.
 */

function normalizeFindings(cfos) {
  return cfos
    .map((cfo) => ({
      ...cfo,
      // Trim string fields
      weakness_name: (cfo.weakness_name || '').trim(),
      weakness_description: (cfo.weakness_description || '').trim(),
      weakness_source_identifier: (cfo.weakness_source_identifier || '').trim(),
      asset_identifier: (cfo.asset_identifier || '').trim(),
      assessor_comments: (cfo.assessor_comments || '').trim(),
      hardening_benchmark: (cfo.hardening_benchmark || '').trim(),
      vendor_name: (cfo.vendor_name || '').trim(),

      // Normalize risk rating
      original_risk_rating: normalizeRiskRating(cfo.original_risk_rating),

      // Normalize scan type
      scan_type: normalizeScanType(cfo.scan_type),

      // Normalize date
      original_detection_date: normalizeDate(cfo.original_detection_date),

      // Ensure boolean defaults
      vendor_dependency: cfo.vendor_dependency === true,
      mark_as_rcdt: cfo.mark_as_rcdt === true,
    }))
    // Exclude informational findings from RET output (they are tracked for summary only)
    // Note: We keep them in the array for summary counting, but mark them
    ;
}

function normalizeRiskRating(rating) {
  if (!rating) return 'Informational';
  const r = String(rating).toLowerCase().trim();
  if (r === 'critical' || r === '4') return 'Critical';
  if (r === 'high' || r === '3') return 'High';
  if (r === 'moderate' || r === 'medium' || r === '2') return 'Moderate';
  if (r === 'low' || r === '1') return 'Low';
  return 'Informational';
}

function normalizeScanType(scanType) {
  if (!scanType) return 'VULNERABILITY';
  const s = String(scanType).toUpperCase().trim();
  if (s === 'CONFIG_FINDING' || s === 'CONFIG' || s === 'COMPLIANCE') return 'CONFIG_FINDING';
  return 'VULNERABILITY';
}

function normalizeDate(dateVal) {
  if (!dateVal) return null;
  try {
    const d = new Date(dateVal);
    if (isNaN(d.getTime())) return null;
    return d.toISOString().split('T')[0]; // YYYY-MM-DD
  } catch {
    return null;
  }
}

module.exports = { normalizeFindings };
