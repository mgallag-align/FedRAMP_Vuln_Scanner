/**
 * Rescan comparison utility.
 *
 * Scan files tagged isRescan=true contribute "rescan" findings.
 * All other scan files contribute "baseline" findings.
 *
 * Outcomes:
 *   Baseline finding present in rescan   → remains open (baseline version kept)
 *   Baseline finding absent from rescan  → mark_as_rcdt=true (corrected during testing)
 *   Rescan-only finding (new discovery)  → added as a new open finding
 *
 * Match key: norm(asset_identifier) | norm(weakness_source_identifier)
 * This is intentionally the same key used by deduplication, so per-asset
 * per-CVE tracking is preserved.
 */

function norm(s) {
  return String(s == null ? '' : s).toLowerCase().trim();
}

export function applyRescanComparison(findings, scanFiles) {
  const rescanFileIds = new Set(
    scanFiles.filter((sf) => sf.isRescan).map((sf) => sf.id)
  );

  if (rescanFileIds.size === 0) return findings;

  const baseline = findings.filter((f) => !rescanFileIds.has(f.scanner_file_id));
  const rescan = findings.filter((f) => rescanFileIds.has(f.scanner_file_id));

  // Build lookup of all keys present in rescan findings
  const rescanKeySet = new Set(
    rescan.map((f) => `${norm(f.asset_identifier)}|${norm(f.weakness_source_identifier)}`)
  );

  const result = [];
  const consumedKeys = new Set(); // rescan keys paired with a baseline finding

  for (const f of baseline) {
    const key = `${norm(f.asset_identifier)}|${norm(f.weakness_source_identifier)}`;
    if (rescanKeySet.has(key)) {
      consumedKeys.add(key); // still present in rescan → open
      result.push(f);
    } else {
      // Not found in rescan → corrected during testing
      result.push({
        ...f,
        mark_as_rcdt: true,
        _rcdt_reason: 'Not detected in rescan — likely remediated',
      });
    }
  }

  // Include rescan-only findings (new discoveries not in any baseline file)
  for (const f of rescan) {
    const key = `${norm(f.asset_identifier)}|${norm(f.weakness_source_identifier)}`;
    if (!consumedKeys.has(key)) {
      result.push(f);
    }
  }

  return result;
}

/** Count findings auto-marked RCDT by rescan comparison. */
export function countRescanRcdt(findings) {
  return findings.filter((f) => f.mark_as_rcdt && f._rcdt_reason).length;
}
