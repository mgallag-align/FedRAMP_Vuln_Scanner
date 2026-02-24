/**
 * Classify CFOs into their destination tabs:
 *   - VULNERABILITY → Risk Exposure Table tab
 *   - CONFIG_FINDING → Configuration Findings tab
 *   - CORRECTED_DURING_TESTING → RCDT tab (assessor marks this in Review UI)
 *
 * Classification is primarily set by the parser based on scan content.
 * The assessor can override by checking "Mark as RCDT" in Step 4.
 */
function classifyFindings(cfos) {
  return cfos.map((cfo) => {
    // If assessor marked as RCDT, that takes precedence
    if (cfo.mark_as_rcdt) {
      return { ...cfo, _destination: 'RCDT' };
    }

    // Otherwise, use scan_type
    if (cfo.scan_type === 'CONFIG_FINDING') {
      return { ...cfo, _destination: 'CONFIG' };
    }

    return { ...cfo, _destination: 'RET' };
  });
}

module.exports = { classifyFindings };
