/**
 * Shared CVE consolidation + risk sorting.
 *
 * Both the ID generator and the RET exporter must group findings into rows
 * IDENTICALLY — IDs are assigned from the consolidated set and the exporter
 * writes rows from the same set, so any divergence would mis-label rows.
 * Keeping the grouping in one place prevents that drift.
 */

const { RISK_ORDER } = require('./severity');

/**
 * Sort findings by descending risk (Critical→Low), then weakness name.
 */
function sortByRisk(findings) {
  return [...findings].sort((a, b) => {
    const riskA = RISK_ORDER[a.original_risk_rating] ?? 4;
    const riskB = RISK_ORDER[b.original_risk_rating] ?? 4;
    if (riskA !== riskB) return riskA - riskB;
    return (a.weakness_name || '').localeCompare(b.weakness_name || '');
  });
}

/**
 * Consolidate findings so there is one row per CVE/weakness_source_identifier.
 * When multiple findings share the same CVE, the consolidated row uses:
 *   - Highest severity (Critical > High > Moderate > Low) as the base
 *   - Earliest detection date
 *   - Combined asset identifiers (deduplicated, newline-separated)
 *   - Merged scanner sources (deduplicated, '; '-separated)
 *   - First non-empty value for other text fields
 *   - Vendor dependency true if ANY finding in the group is vendor-dependent
 *
 * Findings without a weakness_source_identifier are passed through as-is
 * (one row each), since they cannot be safely grouped.
 */
function consolidateByCVE(findings) {
  const grouped = new Map();
  const noIdentifier = [];

  for (const cfo of findings) {
    const key = cfo.weakness_source_identifier;
    if (!key) {
      noIdentifier.push(cfo);
      continue;
    }
    if (!grouped.has(key)) grouped.set(key, []);
    grouped.get(key).push(cfo);
  }

  const consolidated = [];

  for (const [, group] of grouped) {
    // Highest-severity finding becomes the base
    group.sort((a, b) => {
      const riskA = RISK_ORDER[a.original_risk_rating] ?? 4;
      const riskB = RISK_ORDER[b.original_risk_rating] ?? 4;
      return riskA - riskB;
    });
    const base = { ...group[0] };

    // Merge asset identifiers (deduplicated; split pre-merged multi-value cells)
    const assetSet = new Set();
    for (const cfo of group) {
      if (cfo.asset_identifier) {
        cfo.asset_identifier.split('\n').forEach((a) => {
          const trimmed = a.trim();
          if (trimmed) assetSet.add(trimmed);
        });
      }
    }
    base.asset_identifier = Array.from(assetSet).join('\n');

    // Earliest detection date
    let earliest = null;
    for (const cfo of group) {
      if (cfo.original_detection_date) {
        const d = new Date(cfo.original_detection_date);
        if (!isNaN(d.getTime()) && (!earliest || d < earliest)) earliest = d;
      }
    }
    if (earliest) base.original_detection_date = earliest.toISOString().split('T')[0];

    // Merge scanner sources (deduplicated)
    const scannerSet = new Set();
    for (const cfo of group) {
      if (cfo.scanner_source) scannerSet.add(cfo.scanner_source);
    }
    if (scannerSet.size > 1) base.scanner_source = Array.from(scannerSet).join('; ');

    // Fill blank text fields from other group members
    for (const field of ['weakness_name', 'weakness_description', 'vendor_name']) {
      if (!base[field]) {
        for (const cfo of group) {
          if (cfo[field]) {
            base[field] = cfo[field];
            break;
          }
        }
      }
    }

    // Vendor dependency: true if any finding says true
    base.vendor_dependency = group.some((cfo) => cfo.vendor_dependency);

    consolidated.push(base);
  }

  return [...consolidated, ...noIdentifier];
}

module.exports = { RISK_ORDER, sortByRisk, consolidateByCVE };
