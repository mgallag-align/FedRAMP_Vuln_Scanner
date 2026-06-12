/**
 * Inventory coverage computation — browser-safe (no Node.js require).
 *
 * Coverage % = IIW assets touched by ≥1 matched finding / total IIW assets.
 * Auth % = (authenticatedHigh + authenticatedMedLow) / totalHosts.
 *
 * Both metrics are computed per-scanner and globally.
 */

/**
 * Compute auth% from an authSummary object (as stored on a scanFile).
 * Returns null when no host-level auth data is available (e.g. CSV exports).
 */
export function getAuthPercent(authSummary) {
  if (!authSummary || !authSummary.totalHosts) return null;
  const authed = (authSummary.authenticatedHigh || 0) + (authSummary.authenticatedMedLow || 0);
  return Math.round((authed / authSummary.totalHosts) * 100);
}

/**
 * Compute full coverage statistics from the post-match findings set.
 *
 * @param {object[]} findings   - CFOs with iiw_match_status populated (post-match)
 * @param {object[]} iiwAssets  - IIW asset list from Step 2
 * @param {object[]} scanFiles  - Scan file entries from the store
 * @returns {object|null}       - Coverage stats, or null when no IIW is loaded
 */
export function computeCoverage(findings, iiwAssets, scanFiles) {
  if (!iiwAssets || iiwAssets.length === 0) return null;

  const totalIIW = iiwAssets.length;

  // Per-scanner: Set of normalized IIW uniqueAssetIds covered by each file
  const perScannerMatched = new Map(); // fileId → Set<normalizedId>
  const globalMatched = new Set();

  for (const f of findings) {
    if (f.iiw_match_status !== 'MATCHED' || !f.asset_identifier) continue;

    // asset_identifier is the canonical IIW uniqueAssetId after matching.
    // After CVE consolidation in the exporter it may be newline-separated,
    // but at this point (pre-export, post-match) it is a single value.
    const ids = f.asset_identifier
      .split('\n')
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean);

    for (const id of ids) {
      globalMatched.add(id);
      if (f.scanner_file_id) {
        if (!perScannerMatched.has(f.scanner_file_id)) {
          perScannerMatched.set(f.scanner_file_id, new Set());
        }
        perScannerMatched.get(f.scanner_file_id).add(id);
      }
    }
  }

  const perScanner = (scanFiles || []).map((sf) => {
    const matched = perScannerMatched.get(sf.id) || new Set();
    return {
      fileId: sf.id,
      fileName: sf.name,
      scannerType: sf.scannerType || '',
      coveredAssets: matched.size,
      coveragePercent: Math.round((matched.size / totalIIW) * 100),
      authPercent: getAuthPercent(sf.authSummary),
      authSummary: sf.authSummary || null,
    };
  });

  // IIW assets not reached by any scanner
  const uncoveredList = iiwAssets
    .filter((a) => !globalMatched.has(a.uniqueAssetId.toLowerCase().trim()))
    .map((a) => ({
      uniqueAssetId: a.uniqueAssetId,
      ipAddress: a.ipAddress || '',
      dnsName: a.dnsName || '',
      assetType: a.assetType || '',
    }));

  return {
    totalIIW,
    coveredAssets: globalMatched.size,
    uncoveredAssets: uncoveredList.length,
    coveragePercent: Math.round((globalMatched.size / totalIIW) * 100),
    perScanner,
    uncoveredList,
    computedAt: new Date().toISOString(),
  };
}
