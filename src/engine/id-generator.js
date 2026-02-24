/**
 * RET ID Sequential Assignment.
 *
 * IDs are assigned per tab, sorted by:
 *   1. Descending risk rating (Critical → High → Moderate → Low)
 *   2. Alphabetically by weakness_name within same rating
 *
 * Format: [PREFIX]-[NNN] (zero-padded 3-digit sequence)
 * Sequence resets per tab.
 */

const RISK_ORDER = { Critical: 0, High: 1, Moderate: 2, Low: 3, Informational: 4 };

function sortFindings(findings) {
  return [...findings].sort((a, b) => {
    const riskA = RISK_ORDER[a.original_risk_rating] ?? 4;
    const riskB = RISK_ORDER[b.original_risk_rating] ?? 4;
    if (riskA !== riskB) return riskA - riskB;
    return (a.weakness_name || '').localeCompare(b.weakness_name || '');
  });
}

function generateIds(cfos, prefixConfig) {
  const { vulnPrefix = 'VS', configPrefix = 'CF', rcdtPrefix = 'RC' } = prefixConfig;

  // Filter out informational
  const active = cfos.filter((f) => f.original_risk_rating !== 'Informational');

  // Separate by destination
  const retFindings = active.filter((f) => f.scan_type === 'VULNERABILITY' && !f.mark_as_rcdt);
  const configFindings = active.filter((f) => f.scan_type === 'CONFIG_FINDING' && !f.mark_as_rcdt);
  const rcdtFindings = active.filter((f) => f.mark_as_rcdt);

  // Sort each group
  const sortedRET = sortFindings(retFindings);
  const sortedConfig = sortFindings(configFindings);
  const sortedRCDT = sortFindings(rcdtFindings);

  // Assign IDs
  const idMap = new Map();

  sortedRET.forEach((f, idx) => {
    idMap.set(f.cfo_id, `${vulnPrefix}-${String(idx + 1).padStart(3, '0')}`);
  });

  sortedConfig.forEach((f, idx) => {
    idMap.set(f.cfo_id, `${configPrefix}-${String(idx + 1).padStart(3, '0')}`);
  });

  sortedRCDT.forEach((f, idx) => {
    idMap.set(f.cfo_id, `${rcdtPrefix}-${String(idx + 1).padStart(3, '0')}`);
  });

  // Apply IDs back to all CFOs
  return cfos.map((f) => ({
    ...f,
    ret_id: idMap.get(f.cfo_id) || null,
  }));
}

module.exports = { generateIds };
