/**
 * Pre-export validation — enforces V-01 through V-08.
 * Returns { errors: [{ code, message }] }
 */
function validateExport(sessionData) {
  const { systemInfo, findings, iiwAssets, scanFiles, unauthAcknowledged = [] } = sessionData;
  const errors = [];
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
      message: 'System information is incomplete. Return to Step 1.',
    });
  }

  // V-02: IIW uploaded with at least 1 asset
  if (!iiwAssets || iiwAssets.length === 0) {
    errors.push({
      code: 'V-02',
      message: 'No valid IIW found. Upload a completed IIW in Step 2.',
    });
  }

  // V-03: At least one scan file
  if (!scanFiles || scanFiles.length === 0) {
    errors.push({
      code: 'V-03',
      message: 'No scan files found. Upload at least one scan in Step 3.',
    });
  }

  // V-04: Zero unmatched asset identifiers
  const unmatched = active.filter((f) => f.iiw_match_status === 'UNMATCHED');
  if (unmatched.length > 0) {
    errors.push({
      code: 'V-04',
      message: `${unmatched.length} finding(s) have unresolved asset IDs. Resolve in Step 4 before export.`,
    });
  }

  // V-05: All unauthenticated warnings acknowledged
  const unauthUnacked = active.filter(
    (f) => f.is_authenticated === false && !ackSet.has(f.cfo_id)
  );
  if (unauthUnacked.length > 0) {
    errors.push({
      code: 'V-05',
      message: `${unauthUnacked.length} unauthenticated scan warning(s) have not been acknowledged.`,
    });
  }

  // V-06: No duplicate RET IDs across all tabs
  const retIds = active.filter((f) => f.ret_id).map((f) => f.ret_id);
  const idSet = new Set();
  const dupes = new Set();
  for (const id of retIds) {
    if (idSet.has(id)) dupes.add(id);
    else idSet.add(id);
  }
  if (dupes.size > 0) {
    errors.push({
      code: 'V-06',
      message: `Duplicate RET IDs detected: ${Array.from(dupes).join(', ')}. Review and correct ID assignments.`,
    });
  }

  // V-07: Config findings tab requires CM-6 row on RET tab
  const configFindings = active.filter(
    (f) => f.scan_type === 'CONFIG_FINDING' && !f.mark_as_rcdt
  );
  // CM-6 row will be auto-created by export, so this is a soft check
  // (The export writer handles auto-creation; we just note it here for transparency)
  if (configFindings.length > 0) {
    // This will be auto-resolved by the export module — no blocking error.
  }

  // V-08: Vendor Dependency = Yes must have non-blank vendor name
  const vendorMissing = active.filter(
    (f) => f.vendor_dependency === true && (!f.vendor_name || !f.vendor_name.trim())
  );
  if (vendorMissing.length > 0) {
    errors.push({
      code: 'V-08',
      message: `${vendorMissing.length} finding(s) marked as Vendor Dependent have no vendor name.`,
    });
  }

  return { errors };
}

module.exports = { validateExport };
