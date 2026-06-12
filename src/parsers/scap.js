const xml2js = require('xml2js');
const { v4: uuidv4 } = require('uuid');

/**
 * XCCDF result status → scan_type and pass/fail
 */
function mapXCCDFResult(result) {
  if (!result) return { pass: false };
  const r = result.toLowerCase();
  if (r === 'pass') return { pass: true };
  if (r === 'fail' || r === 'error' || r === 'unknown') return { pass: false };
  return { pass: true }; // notapplicable, notchecked, etc.
}

/**
 * XCCDF severity → FedRAMP risk rating
 */
function mapXCCDFSeverity(severity) {
  if (!severity) return 'Moderate';
  const s = severity.toLowerCase();
  if (s === 'critical') return 'Critical';
  if (s === 'high') return 'High';
  if (s === 'medium' || s === 'moderate') return 'Moderate';
  if (s === 'low') return 'Low';
  if (s === 'info' || s === 'informational') return 'Informational';
  return 'Moderate';
}

/**
 * Parse SCAP/XCCDF/STIG XML into CFOs.
 * Handles both <Benchmark> (full XCCDF) and <TestResult> structures.
 */
async function parseSCAP(xmlContent, fileName, onProgress) {
  const parser = new xml2js.Parser({
    explicitArray: false,
    mergeAttrs: true,
    tagNameProcessors: [xml2js.processors.stripPrefix],
  });
  const result = await parser.parseStringPromise(xmlContent);

  const findings = [];

  // Try to find the benchmark and test results
  let testResults = [];
  let ruleMap = new Map(); // ruleId → rule metadata
  let benchmarkTitle = '';

  // <Benchmark> structure
  const benchmark = result.Benchmark;
  if (benchmark) {
    benchmarkTitle = benchmark.title || benchmark.id || '';

    // Build rule map from Group/Rule structure
    const groups = benchmark.Group
      ? Array.isArray(benchmark.Group)
        ? benchmark.Group
        : [benchmark.Group]
      : [];
    for (const group of groups) {
      const rules = group.Rule
        ? Array.isArray(group.Rule)
          ? group.Rule
          : [group.Rule]
        : [];
      for (const rule of rules) {
        const ruleId = rule.id || '';
        ruleMap.set(ruleId, {
          title: rule.title || '',
          description:
            typeof rule.description === 'string'
              ? rule.description
              : rule.description?._ || '',
          severity: rule.severity || 'medium',
          fixtext: rule.fixtext?._ || rule.fixtext || '',
        });
      }
    }

    // TestResult
    const tr = benchmark.TestResult;
    if (tr) {
      const ruleResults = tr['rule-result']
        ? Array.isArray(tr['rule-result'])
          ? tr['rule-result']
          : [tr['rule-result']]
        : [];
      testResults = ruleResults;
    }
  }

  // Standalone <TestResult>
  if (!benchmark && result.TestResult) {
    const tr = result.TestResult;
    const ruleResults = tr['rule-result']
      ? Array.isArray(tr['rule-result'])
        ? tr['rule-result']
        : [tr['rule-result']]
      : [];
    testResults = ruleResults;
  }

  // Determine target (asset) from TestResult
  let targetAsset = '';
  const tr = benchmark?.TestResult || result.TestResult;
  if (tr) {
    targetAsset = tr.target || tr['target-address'] || '';
    if (typeof targetAsset === 'object') targetAsset = targetAsset._ || '';
  }

  const total = testResults.length;

  for (let i = 0; i < total; i++) {
    const rr = testResults[i];
    const ruleId = rr.idref || rr.id || '';
    const resultStatus = rr.result || '';
    const { pass } = mapXCCDFResult(resultStatus);

    // Only include failed checks as findings
    if (pass) continue;

    const ruleMeta = ruleMap.get(ruleId) || {};
    const severity = mapXCCDFSeverity(rr.severity || ruleMeta.severity);

    const cfo = {
      cfo_id: uuidv4(),
      scanner_source: `${fileName} | SCAP/XCCDF`,
      weakness_name: ruleMeta.title || ruleId,
      weakness_description: ruleMeta.description || ruleMeta.fixtext || '',
      weakness_source_identifier: ruleId,
      asset_identifier: targetAsset,
      original_detection_date: tr?.['end-time'] || tr?.['start-time'] || null,
      original_risk_rating: severity,
      scan_type: 'CONFIG_FINDING',
      is_authenticated: null,
      iiw_match_status: null,
      vendor_dependency: false,
      vendor_name: '',
      hardening_benchmark: benchmarkTitle || fileName,
      compliance_result: resultStatus ? resultStatus.toUpperCase() : 'FAILED',
      compliance_actual_value: '',
      compliance_policy_value: '',
      assessor_comments: '',
      ret_id: null,
      mark_as_rcdt: false,
    };

    findings.push(cfo);
    if (onProgress && i % 50 === 0) onProgress((i / total) * 100);
  }

  if (onProgress) onProgress(100);
  return findings;
}

module.exports = { parseSCAP };
