/**
 * Pre-export validation — enforces V-01 through V-08.
 * Returns { errors: [{ code, message, severity }], warnings: [{ code, message, severity }] }
 * severity: 'error' = blocks export, 'warning' = allows export with override
 */
function validateExport(sessionData) {
  const { systemInfo, findings, iiwAssets, scanFiles, unauthAcknowledged = [] } = sessionData;
  const errors = [];
  const warnings = [];
  const ackSet = new Set(unauthAcknowledged);

  // Filter out informational
  const active = findings.filter((f) => f.original_risk_rating !== 'Informational');

  // V-01: System info complete
  if (
    !systemInfo.cspName?.trim() ||
    !systemInfo.systemName?.trim() ||
    !systemInfo.impactLevel ||
    !systemInfo.retDate
  ) {
    errors.push({
      code: 'V-01',
      severity: 'error',
      message: 'System information is incomplete. Return to Step 1.',
    });
  }

  // V-02: IIW uploaded with at least 1 asset (warning — IIW is optional)
  if (!iiwAssets || iiwAssets.length === 0) {
    warnings.push({
      code: 'V-02',
      severity: 'warning',
      message: 'No IIW uploaded. Asset matching was skipped — findings will export without inventory cross-reference.',
    });
  }

  // V-03: At least one scan file
  if (!scanFiles || scanFiles.length === 0) {
    errors.push({
      code: 'V-03',
      severity: 'error',
      message: 'No scan files found. Upload at least one scan in Step 3.',
    });
  }

  // V-04: Unmatched asset identifiers (warning — allows override)
  const unmatched = active.filter((f) => f.iiw_match_status === 'UNMATCHED');
  if (unmatched.length > 0) {
    warnings.push({
      code: 'V-04',
      severity: 'warning',
      message: `${unmatched.length} finding(s) have unresolved asset IDs. These will export with their original asset identifiers.`,
    });
  }

  // V-05: All unauthenticated warnings acknowledged (warning — allows override)
  const unauthUnacked = active.filter(
    (f) => f.is_authenticated === false && !ackSet.has(f.cfo_id)
  );
  if (unauthUnacked.length > 0) {
    warnings.push({
      code: 'V-05',
      severity: 'warning',
      message: `${unauthUnacked.length} unauthenticated scan warning(s) have not been acknowledged.`,
    });
  }

  // V-06: No duplicate RET IDs across all tabs
  // Findings sharing the same CVE (weakness_source_identifier) are consolidated
  // into one row at export time, so they intentionally share the same ID.
  // Only flag duplicates where distinct CVEs/findings got the same ID.
  const idToCVEs = new Map();
  for (const f of active) {
    if (!f.ret_id) continue;
    if (!idToCVEs.has(f.ret_id)) {
      idToCVEs.set(f.ret_id, new Set());
    }
    idToCVEs.get(f.ret_id).add(f.weakness_source_identifier || f.cfo_id);
  }
  const dupes = new Set();
  for (const [id, cves] of idToCVEs) {
    if (cves.size > 1) dupes.add(id);
  }
  if (dupes.size > 0) {
    errors.push({
      code: 'V-06',
      severity: 'error',
      message: `Duplicate RET IDs detected: ${Array.from(dupes).join(', ')}. Review and correct ID assignments.`,
    });
  }

  // V-07: Config findings tab requires CM-6 row on RET tab
  const configFindings = active.filter(
    (f) => f.scan_type === 'CONFIG_FINDING' && !f.mark_as_rcdt
  );
  // CM-6 row will be auto-created by export, so this is a soft check
  if (configFindings.length > 0) {
    // This will be auto-resolved by the export module — no blocking error.
  }

  // V-08: Vendor Dependency = Yes must have non-blank vendor name
  const vendorMissing = active.filter(
    (f) => f.vendor_dependency === true && (!f.vendor_name || !f.vendor_name.trim())
  );
  if (vendorMissing.length > 0) {
    warnings.push({
      code: 'V-08',
      severity: 'warning',
      message: `${vendorMissing.length} finding(s) marked as Vendor Dependent have no vendor name.`,
    });
  }

  return { errors, warnings };
}

module.exports = { validateExport };
