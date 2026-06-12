/**
 * Multi-tier IIW asset matching.
 *
 * Tier 1: Exact match — CFO asset_identifier == IIW Unique Asset ID (Col B).
 * Tier 2: Exact IP   — CFO asset_identifier == IIW IPv4/IPv6 (Col C).
 * Tier 3: Exact DNS  — CFO asset_identifier == IIW DNS Name (Col F), scheme-stripped.
 * Tier 4: Composite/tuple — the CFO or IIW identifier bundles several values
 *         (e.g. "host01, 10.0.0.1" or "host01 (10.0.0.1)"). Each token is
 *         matched against the exact indices.
 * Tier 5: Fuzzy/partial — hostname short-form (web01 ↔ web01.example.com) and
 *         substring containment for hostname-like identifiers.
 *
 * Tiers 4 and 5 collect every candidate IIW asset:
 *   - exactly one candidate  → MATCHED (canonicalized to the IIW asset)
 *   - more than one candidate → AMBIGUOUS (left for the assessor to resolve,
 *                               with the candidate list attached for the UI)
 *   - none                    → UNMATCHED
 *
 * Each matched CFO carries _match_tier (1-5) and _match_confidence
 * ('exact' | 'composite' | 'fuzzy') for transparency.
 */

const IP_RE = /^(?:\d{1,3}\.){3}\d{1,3}$|^[0-9a-f]*:[0-9a-f:]+$/i;
const FUZZY_NOTE = '[FUZZY ASSET MATCH — verify the resolved asset is correct]';

function norm(s) {
  return String(s == null ? '' : s).toLowerCase().trim();
}

function stripScheme(s) {
  return s.replace(/^https?:\/\//i, '');
}

function firstLabel(host) {
  return host.split('.')[0];
}

/**
 * Split a possibly-composite field into normalized, scheme-stripped tokens.
 * Delimiters: whitespace, comma, semicolon, pipe, slash, brackets, parentheses.
 */
function tokenize(value) {
  return norm(value)
    .split(/[\s,;|/()[\]]+/)
    .map((t) => stripScheme(t.trim()))
    .filter(Boolean);
}

function buildIndices(iiwAssets) {
  const byId = new Map(); // norm uniqueAssetId → asset
  const byIp = new Map(); // norm ip token → asset
  const byDns = new Map(); // norm dns token (scheme-stripped) → asset
  const tokenIndex = new Map(); // token → Map(normId → asset)
  const shortIndex = new Map(); // FQDN first-label → Map(normId → asset)

  const addToken = (map, key, asset) => {
    if (!key) return;
    if (!map.has(key)) map.set(key, new Map());
    map.get(key).set(norm(asset.uniqueAssetId), asset);
  };

  for (const asset of iiwAssets) {
    const id = norm(asset.uniqueAssetId);
    if (id && !byId.has(id)) byId.set(id, asset);

    for (const ipTok of tokenize(asset.ipAddress)) {
      if (!byIp.has(ipTok)) byIp.set(ipTok, asset);
    }
    for (const dnsTok of tokenize(asset.dnsName)) {
      if (!byDns.has(dnsTok)) byDns.set(dnsTok, asset);
    }

    // Token & short-label indices (for composite + fuzzy tiers)
    const allTokens = new Set([
      id,
      ...tokenize(asset.uniqueAssetId),
      ...tokenize(asset.ipAddress),
      ...tokenize(asset.dnsName),
    ]);
    for (const tok of allTokens) {
      addToken(tokenIndex, tok, asset);
      if (tok.includes('.') && !IP_RE.test(tok)) {
        const short = firstLabel(tok);
        if (short && short !== tok) addToken(shortIndex, short, asset);
      }
    }
  }

  return { byId, byIp, byDns, tokenIndex, shortIndex };
}

/**
 * Build the result CFO for a successful match — canonicalizes the asset
 * identifier to the IIW value and carries auth status forward.
 */
function applyMatch(cfo, asset, tier, confidence, extraNote) {
  const updated = {
    ...cfo,
    asset_identifier: asset.uniqueAssetId, // canonical IIW value (Col B)
    iiw_match_status: 'MATCHED',
    is_authenticated: asset.authenticatedScan, // true | false | null
    _iiw_asset_type: asset.assetType,
    _match_tier: tier,
    _match_confidence: confidence,
  };

  const notes = [];
  if (extraNote) notes.push(extraNote);
  if (asset.authenticatedScan === false) {
    notes.push('[UNAUTHENTICATED SCAN — findings may be incomplete for this asset]');
  }
  if (notes.length > 0) {
    const existing = cfo.assessor_comments || '';
    const prefix = notes.filter((n) => !existing.includes(n)).join(' ');
    if (prefix) updated.assessor_comments = existing ? `${prefix} ${existing}` : prefix;
  }

  return updated;
}

function toCandidate(asset) {
  return {
    uniqueAssetId: asset.uniqueAssetId,
    ipAddress: asset.ipAddress || '',
    dnsName: asset.dnsName || '',
    assetType: asset.assetType || '',
    authenticatedScan: asset.authenticatedScan,
  };
}

function ambiguous(cfo, candMap) {
  const candidates = Array.from(candMap.values()).slice(0, 10).map(toCandidate);
  const names = candidates.map((c) => c.uniqueAssetId).join(', ');
  const note = `[AMBIGUOUS ASSET MATCH — ${candMap.size} IIW candidates: ${names}]`;
  const existing = cfo.assessor_comments || '';
  return {
    ...cfo,
    iiw_match_status: 'AMBIGUOUS',
    is_authenticated: null,
    _iiw_candidates: candidates,
    assessor_comments: existing.includes('[AMBIGUOUS')
      ? existing
      : existing
      ? `${note} ${existing}`
      : note,
  };
}

function matchAssets(cfos, iiwAssets) {
  if (!iiwAssets || iiwAssets.length === 0) {
    return cfos.map((cfo) => ({ ...cfo, iiw_match_status: 'UNMATCHED', is_authenticated: null }));
  }

  const { byId, byIp, byDns, tokenIndex, shortIndex } = buildIndices(iiwAssets);

  return cfos.map((cfo) => {
    const identifier = norm(cfo.asset_identifier);
    if (!identifier) return { ...cfo, iiw_match_status: 'UNMATCHED', is_authenticated: null };
    const stripped = stripScheme(identifier);

    // ── Tier 1-3: exact ──
    if (byId.has(identifier)) return applyMatch(cfo, byId.get(identifier), 1, 'exact');
    if (byIp.has(identifier)) return applyMatch(cfo, byIp.get(identifier), 2, 'exact');
    if (byDns.has(stripped)) return applyMatch(cfo, byDns.get(stripped), 3, 'exact');

    const addCand = (map, asset) => map.set(norm(asset.uniqueAssetId), asset);

    // ── Tier 4: composite / tuple ──
    {
      const tokens = tokenize(cfo.asset_identifier);
      const cand = new Map();
      for (const t of tokens) {
        const d = stripScheme(t);
        if (byId.has(t)) addCand(cand, byId.get(t));
        else if (byIp.has(t)) addCand(cand, byIp.get(t));
        else if (byDns.has(d)) addCand(cand, byDns.get(d));
        else if (tokenIndex.has(t)) {
          for (const a of tokenIndex.get(t).values()) addCand(cand, a);
        }
      }
      if (cand.size === 1) return applyMatch(cfo, cand.values().next().value, 4, 'composite');
      if (cand.size > 1) return ambiguous(cfo, cand);
    }

    // ── Tier 5: fuzzy / partial (hostname-like identifiers only) ──
    if (!IP_RE.test(stripped)) {
      const cand = new Map();
      const short = firstLabel(stripped);

      // Hostname short-form, both directions
      if (shortIndex.has(short)) for (const a of shortIndex.get(short).values()) addCand(cand, a);
      if (byId.has(short)) addCand(cand, byId.get(short));
      if (byDns.has(short)) addCand(cand, byDns.get(short));

      // Substring containment over non-IP tokens
      if (stripped.length >= 4) {
        for (const [tok, assets] of tokenIndex) {
          if (tok.length < 4 || IP_RE.test(tok)) continue;
          if (tok.includes(stripped) || stripped.includes(tok)) {
            for (const a of assets.values()) addCand(cand, a);
          }
        }
      }

      if (cand.size === 1) {
        return applyMatch(cfo, cand.values().next().value, 5, 'fuzzy', FUZZY_NOTE);
      }
      if (cand.size > 1) return ambiguous(cfo, cand);
    }

    // ── No match ──
    return { ...cfo, iiw_match_status: 'UNMATCHED', is_authenticated: null };
  });
}

module.exports = { matchAssets };
