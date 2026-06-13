const xml2js = require('xml2js');
const { parse: csvParse } = require('csv-parse/sync');
const { v4: uuidv4 } = require('uuid');
const { mapCVSStoRisk } = require('../engine/severity');

/**
 * Parse Rapid7 InsightVM CSV export into CFOs.
 * Expected headers include: 'Asset IP Address', 'Vulnerability Title', etc.
 */
async function parseRapid7CSV(csvContent, fileName, onProgress) {
  const records = csvParse(csvContent, {
    columns: true,
    skip_empty_lines: true,
    relax_column_count: true,
  });

  const findings = [];
  const total = records.length;

  for (let i = 0; i < total; i++) {
    const row = records[i];
    const assetIp = row['Asset IP Address'] || row['IP Address'] || row['Asset'] || '';
    const vulnTitle = row['Vulnerability Title'] || row['Title'] || '';
    const description = row['Description'] || row['Vulnerability Description'] || '';
    const vulnId = row['Vulnerability ID'] || row['CVE'] || row['Plugin ID'] || '';
    const cvss = row['CVSS Score'] || row['CVSS v3 Score'] || row['Risk Score'] || '0';
    const date = row['Scan Date'] || row['Published Date'] || row['Date'] || null;

    const cfo = {
      cfo_id: uuidv4(),
      scanner_source: `${fileName} | Rapid7 InsightVM`,
      weakness_name: vulnTitle,
      weakness_description: description,
      weakness_source_identifier: vulnId,
      asset_identifier: assetIp,
      original_detection_date: date,
      original_risk_rating: mapCVSStoRisk(cvss),
      scan_type: 'VULNERABILITY',
      is_authenticated: null,
      iiw_match_status: null,
      vendor_dependency: false,
      vendor_name: '',
      hardening_benchmark: '',
      compliance_result: null,
      compliance_actual_value: '',
      compliance_policy_value: '',
      assessor_comments: '',
      ret_id: null,
      mark_as_rcdt: false,
    };

    findings.push(cfo);
    if (onProgress && i % 100 === 0) onProgress((i / total) * 100);
  }

  if (onProgress) onProgress(100);
  return findings;
}

/**
 * Parse Rapid7 InsightVM XML export into CFOs.
 */
async function parseRapid7XML(xmlContent, fileName, onProgress) {
  const parser = new xml2js.Parser({ explicitArray: false, mergeAttrs: true });
  const result = await parser.parseStringPromise(xmlContent);

  const findings = [];
  const authStatusByHost = new Map(); // address → true/false/null
  // NexposeReport structure
  const nodes = result.NexposeReport?.nodes?.node;
  if (!nodes) return { findings, authStatusByHost };

  const nodeList = Array.isArray(nodes) ? nodes : [nodes];
  const total = nodeList.length;

  // ── Scan-level metadata ──
  // Tier 3: Check scan template name for credential indicators
  const scanConfig = result.NexposeReport?.scans?.scan;
  const scanList = scanConfig ? (Array.isArray(scanConfig) ? scanConfig : [scanConfig]) : [];
  const hasCredentialConfig = scanList.some((s) => s?.credentials?.credential != null);
  let scanTemplateName = '';
  for (const s of scanList) {
    const tmpl = s?.['scan-template'] || s?.template || s?.name || '';
    if (tmpl) { scanTemplateName = tmpl; break; }
  }
  const templateSuggestsAuth = /full.?audit|credential|authenticated/i.test(scanTemplateName);
  const templateSuggestsUnauth = /discovery|unauthenticated|external/i.test(scanTemplateName);

  for (let n = 0; n < total; n++) {
    const node = nodeList[n];
    const assetId = node.address || node.name || '';

    // ── Multi-layer credential detection (per-node) ──
    // Tier 1 (Primary): <credentials> block with success attribute on node
    // Tier 2 (Secondary): Result code distribution (local checks vs version-only)
    // Tier 3 (Tertiary): Scan template name + credential config
    let nodeAuthenticated = null;
    let authConfidence = 'manual';
    let authEvidence = [];
    let authAttempted = false;

    // Tier 1: Direct credential status on node
    const nodeStatus = (node.status || '').toLowerCase();
    if (nodeStatus.includes('credential') && nodeStatus.includes('pass')) {
      nodeAuthenticated = true;
      authConfidence = 'high';
      authEvidence.push('<node> status: credentialed check passed');
    } else if (nodeStatus.includes('credential') && nodeStatus.includes('fail')) {
      nodeAuthenticated = false;
      authAttempted = true;
      authConfidence = 'high';
      authEvidence.push('<node> status: credentialed check failed');
    }

    // Check <credentials> block (can be nested under node or node.credentials)
    if (nodeAuthenticated === null) {
      const creds = node.credentials?.credential || node.credential;
      if (creds) {
        authAttempted = true;
        const credList = Array.isArray(creds) ? creds : [creds];
        let anySuccess = false;
        let anyFail = false;
        for (const cred of credList) {
          const cs = (typeof cred === 'object' ? (cred.success || cred.status || '') : '').toString().toLowerCase();
          if (cs === 'true' || cs === 'success' || cs === 'pass') anySuccess = true;
          if (cs === 'false' || cs === 'fail' || cs === 'failure') anyFail = true;
        }
        if (anySuccess) {
          nodeAuthenticated = true;
          authConfidence = 'high';
          authEvidence.push(`<credentials> block: success=${anySuccess}`);
        } else if (anyFail) {
          nodeAuthenticated = false;
          authConfidence = 'high';
          authEvidence.push('<credentials> block: all credentials failed');
        } else {
          authEvidence.push('<credentials> block present but no explicit status');
        }
      }
    }

    // Tier 2: Analyze result code distribution (ve/vp = local checks, vv = version-only)
    const tests = node.tests?.test;
    const testList = tests ? (Array.isArray(tests) ? tests : [tests]) : [];

    if (nodeAuthenticated === null && testList.length > 0) {
      let localCheckCount = 0;  // ve (vulnerable exploited), vp (vulnerable policy)
      let versionCheckCount = 0; // vv (vulnerable version)
      let totalChecks = 0;

      for (const test of testList) {
        const status = (test.status || test.key || '').toLowerCase();
        totalChecks++;
        if (status === 've' || status === 'vp' || status.includes('local') || status.includes('policy')) {
          localCheckCount++;
        } else if (status === 'vv' || status.includes('version')) {
          versionCheckCount++;
        }
      }

      // Significant proportion of local checks implies authenticated scan
      if (totalChecks > 0 && localCheckCount > 0) {
        const localRatio = localCheckCount / totalChecks;
        if (localRatio > 0.1) {
          nodeAuthenticated = true;
          authConfidence = 'medium';
          authEvidence.push(`Result code analysis: ${localCheckCount}/${totalChecks} local checks (${(localRatio * 100).toFixed(0)}%) — implies credentialed`);
        }
      }

      if (nodeAuthenticated === null && totalChecks > 0 && versionCheckCount === totalChecks) {
        nodeAuthenticated = false;
        authConfidence = 'low';
        authEvidence.push(`Result code analysis: ${versionCheckCount}/${totalChecks} version-only checks — likely unauthenticated`);
      }
    }

    // Tier 3: Scan template and credential config fallback
    if (nodeAuthenticated === null) {
      if (hasCredentialConfig) {
        authAttempted = true;
        authEvidence.push('Scan credentials configured but per-node status unavailable');
      }
      if (scanTemplateName) {
        if (templateSuggestsAuth) {
          if (nodeAuthenticated === null) {
            nodeAuthenticated = true;
            authConfidence = 'low';
          }
          authEvidence.push(`Scan template "${scanTemplateName}" suggests authenticated scan`);
        } else if (templateSuggestsUnauth) {
          if (nodeAuthenticated === null) {
            nodeAuthenticated = false;
            authConfidence = 'low';
          }
          authEvidence.push(`Scan template "${scanTemplateName}" suggests unauthenticated scan`);
        }
      }
    }

    if (authEvidence.length === 0) {
      authEvidence.push('No credential indicators found (<credentials> block, result codes, scan template)');
    }

    authStatusByHost.set(assetId, {
      authenticated: nodeAuthenticated,
      confidence: authConfidence,
      evidence: authEvidence.join('; '),
      attempted: authAttempted,
      manualReviewRequired: nodeAuthenticated === null,
    });

    if (!tests) continue;

    for (const test of testList) {
      const cfo = {
        cfo_id: uuidv4(),
        scanner_source: `${fileName} | Rapid7 InsightVM`,
        weakness_name: test.name || test.id || '',
        weakness_description: test.description || '',
        weakness_source_identifier: test.id || '',
        asset_identifier: assetId,
        original_detection_date: null,
        original_risk_rating: mapCVSStoRisk(test.cvssScore || '0'),
        scan_type: 'VULNERABILITY',
        is_authenticated: nodeAuthenticated,
        _auth_confidence: authConfidence,
        iiw_match_status: null,
        vendor_dependency: false,
        vendor_name: '',
        hardening_benchmark: '',
        compliance_result: null,
        compliance_actual_value: '',
        compliance_policy_value: '',
        assessor_comments: '',
        ret_id: null,
        mark_as_rcdt: false,
      };
      findings.push(cfo);
    }
    if (onProgress) onProgress(((n + 1) / total) * 100);
  }

  return { findings, authStatusByHost };
}

async function parseRapid7(content, fileName, onProgress, format) {
  if (format === 'csv') {
    // CSV export has no per-host auth info
    const findings = await parseRapid7CSV(content, fileName, onProgress);
    return { findings, authStatusByHost: new Map() };
  }
  return parseRapid7XML(content, fileName, onProgress);
}

module.exports = { parseRapid7 };
