/**
 * Three-tier IIW asset matching algorithm.
 *
 * Tier 1: Exact match — CFO asset_identifier == IIW Unique Asset ID (Col B), case-insensitive, trimmed.
 * Tier 2: IP match — CFO asset_identifier matches IIW IPv4/IPv6 (Col C).
 * Tier 3: DNS match — CFO asset_identifier matches IIW DNS Name (Col F), strip http/https.
 *
 * If all tiers fail: iiw_match_status = UNMATCHED.
 */
function matchAssets(cfos, iiwAssets) {
  // Build lookup maps for fast matching
  const byId = new Map();    // lowercase unique asset id → asset
  const byIp = new Map();    // lowercase ip → asset
  const byDns = new Map();   // lowercase dns → asset

  for (const asset of iiwAssets) {
    const id = asset.uniqueAssetId.toLowerCase().trim();
    if (id && !byId.has(id)) byId.set(id, asset);

    const ip = (asset.ipAddress || '').toLowerCase().trim();
    if (ip && !byIp.has(ip)) byIp.set(ip, asset);

    const dns = (asset.dnsName || '').toLowerCase().trim().replace(/^https?:\/\//i, '');
    if (dns && !byDns.has(dns)) byDns.set(dns, asset);
  }

  return cfos.map((cfo) => {
    const identifier = (cfo.asset_identifier || '').toLowerCase().trim();
    const strippedIdentifier = identifier.replace(/^https?:\/\//i, '');

    let matched = null;

    // Tier 1: Exact match on Unique Asset ID
    if (byId.has(identifier)) {
      matched = byId.get(identifier);
    }
    // Tier 2: IP match
    else if (byIp.has(identifier)) {
      matched = byIp.get(identifier);
    }
    // Tier 3: DNS match
    else if (byDns.has(strippedIdentifier)) {
      matched = byDns.get(strippedIdentifier);
    }

    if (matched) {
      // Resolve asset identifier to the canonical IIW value
      const updatedCfo = {
        ...cfo,
        asset_identifier: matched.uniqueAssetId, // Canonical form from IIW Col B
        iiw_match_status: 'MATCHED',
        is_authenticated: matched.authenticatedScan, // true, false, or null
        _iiw_asset_type: matched.assetType,
      };

      // If authentication status is unknown (null), it's flagged
      // If unauthenticated, prepend warning to comments
      if (matched.authenticatedScan === false) {
        const prefix = '[UNAUTHENTICATED SCAN \u2014 findings may be incomplete for this asset]';
        if (!cfo.assessor_comments.includes(prefix)) {
          updatedCfo.assessor_comments = cfo.assessor_comments
            ? `${prefix} ${cfo.assessor_comments}`
            : prefix;
        }
      }

      return updatedCfo;
    }

    // No match found
    return {
      ...cfo,
      iiw_match_status: 'UNMATCHED',
      is_authenticated: null,
    };
  });
}

module.exports = { matchAssets };
