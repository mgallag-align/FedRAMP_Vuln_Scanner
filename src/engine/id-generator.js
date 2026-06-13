/**
 * RET ID Sequential Assignment.
 *
 * Findings are first consolidated by CVE (weakness_source_identifier) so that
 * each unique CVE gets one ID. IDs are assigned per tab, sorted by:
 *   1. Descending risk rating (Critical → High → Moderate → Low)
 *   2. Alphabetically by weakness_name within same rating
 *
 * Format: [PREFIX]-[NNN] (zero-padded 3-digit sequence)
 * Sequence resets per tab.
 *
 * The consolidation + sort are shared with the RET exporter (engine/consolidate)
 * so IDs are assigned to exactly the same row groups the exporter writes.
 */

const { sortByRisk, consolidateByCVE } = require('./consolidate');

function generateIds(cfos, prefixConfig) {
  const { vulnPrefix = 'VS', configPrefix = 'CF', rcdtPrefix = 'RC' } = prefixConfig;

  // Filter out informational
  const active = cfos.filter((f) => f.original_risk_rating !== 'Informational');

  // Separate by destination
  const retFindings = active.filter((f) => f.scan_type === 'VULNERABILITY' && !f.mark_as_rcdt);
  const configFindings = active.filter((f) => f.scan_type === 'CONFIG_FINDING' && !f.mark_as_rcdt);
  const rcdtFindings = active.filter((f) => f.mark_as_rcdt);

  // Consolidate by CVE then sort each group (same logic the exporter uses)
  const sortedRET = sortByRisk(consolidateByCVE(retFindings));
  const sortedConfig = sortByRisk(consolidateByCVE(configFindings));
  const sortedRCDT = sortByRisk(consolidateByCVE(rcdtFindings));

  // Assign IDs — one per consolidated CVE
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

  // For consolidated CVEs, all findings sharing the same CVE get the same ID
  // Build a CVE→ID lookup from the representatives
  const cveIdMap = new Map();
  for (const f of [...sortedRET, ...sortedConfig, ...sortedRCDT]) {
    if (f.weakness_source_identifier && idMap.has(f.cfo_id)) {
      cveIdMap.set(f.weakness_source_identifier, idMap.get(f.cfo_id));
    }
  }

  // Apply IDs back to all CFOs
  return cfos.map((f) => ({
    ...f,
    ret_id: idMap.get(f.cfo_id) || cveIdMap.get(f.weakness_source_identifier) || null,
  }));
}

module.exports = { generateIds };
