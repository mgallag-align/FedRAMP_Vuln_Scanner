const xml2js = require('xml2js');
const { v4: uuidv4 } = require('uuid');

/**
 * Qualys severity → FedRAMP risk rating
 * 5 = Critical, 4 = High, 3 = Moderate, 1-2 = Low, 0 = Informational
 */
function mapQualysSeverity(severity) {
  const sev = parseInt(severity, 10);
  if (sev >= 5) return 'Critical';
  if (sev === 4) return 'High';
  if (sev === 3) return 'Moderate';
  if (sev >= 1) return 'Low';
  return 'Informational';
}

/**
 * Parse Qualys XML scan output into CFOs.
 * Supports both <SCAN> and <QualysGuardEnterpriseQualityReport> formats.
 */
async function parseQualys(xmlContent, fileName, onProgress) {
  const parser = new xml2js.Parser({ explicitArray: false, mergeAttrs: true });
  const result = await parser.parseStringPromise(xmlContent);

  const findings = [];
  const authStatusByHost = new Map(); // hostname → true/false/null

  // Try to find vulnerability data in various Qualys XML structures
  let hosts = [];

  if (result.SCAN && result.SCAN.IP) {
    hosts = Array.isArray(result.SCAN.IP) ? result.SCAN.IP : [result.SCAN.IP];
  } else if (result.HOST_LIST_OUTPUT && result.HOST_LIST_OUTPUT.RESPONSE) {
    const resp = result.HOST_LIST_OUTPUT.RESPONSE;
    hosts = resp.HOST_LIST?.HOST ? (Array.isArray(resp.HOST_LIST.HOST) ? resp.HOST_LIST.HOST : [resp.HOST_LIST.HOST]) : [];
  }

  // Alternate: ASSET_DATA_REPORT format
  if (hosts.length === 0 && result.ASSET_DATA_REPORT) {
    const hostList = result.ASSET_DATA_REPORT.HOST_LIST;
    if (hostList?.HOST) {
      hosts = Array.isArray(hostList.HOST) ? hostList.HOST : [hostList.HOST];
    }
  }

  const totalHosts = hosts.length;

  for (let h = 0; h < totalHosts; h++) {
    const host = hosts[h];
    const assetId = host.value || host.IP || host.ip || host.NAME || '';

    let vulns = [];
    // Various Qualys structures for vulnerabilities
    if (host.VULNS?.CAT) {
      const cats = Array.isArray(host.VULNS.CAT) ? host.VULNS.CAT : [host.VULNS.CAT];
      for (const cat of cats) {
        const items = cat.VULN ? (Array.isArray(cat.VULN) ? cat.VULN : [cat.VULN]) : [];
        vulns.push(...items);
      }
    }
    if (host.DETECTION_LIST?.DETECTION) {
      const dets = Array.isArray(host.DETECTION_LIST.DETECTION)
        ? host.DETECTION_LIST.DETECTION
        : [host.DETECTION_LIST.DETECTION];
      vulns.push(...dets);
    }

    // ── Multi-layer credential detection (per-host) ──
    // Auth success QIDs: 70028 (Windows Auth — parse RESULT text), 150007 (WAS Auth Success), 150094 (WAS Selenium Success)
    // Auth failure QIDs: 105015 (Auth Failure), 105315 (Web Auth Failed), 150008 (WAS Auth Failed), 150095 (WAS Selenium Failed)
    // HTTP auth: 86762 (HTTP Auth Attempted)
    let hostAuthenticated = null;
    let authConfidence = 'manual';
    let authEvidence = [];
    let authAttempted = false;

    // Collect QID presence for auth detection
    const authQIDs = new Set();
    for (const vuln of vulns) {
      const qid = String(vuln.QID || vuln.qid || '');
      if (['70028', '86762', '105015', '105186', '105315', '150007', '150008', '150094', '150095'].includes(qid)) {
        authQIDs.add(qid);

        const output = vuln.RESULT || vuln.result || vuln.DIAGNOSIS || vuln.diagnosis || '';

        // QID 70028: Windows Authentication Method — must parse RESULT text
        if (qid === '70028') {
          authAttempted = true;
          if (/Authentication\s+Successful/i.test(output) || /success/i.test(output)) {
            hostAuthenticated = true;
            authConfidence = 'high';
            authEvidence.push('QID 70028 (Windows Auth): Authentication Successful');
          } else if (/Authentication\s+Failed/i.test(output) || /fail/i.test(output)) {
            hostAuthenticated = false;
            authConfidence = 'high';
            authEvidence.push('QID 70028 (Windows Auth): Authentication Failed');
          }
        }

        // Auth failure indicators
        if (qid === '105015') {
          hostAuthenticated = false;
          authAttempted = true;
          authConfidence = authConfidence === 'manual' ? 'high' : authConfidence;
          authEvidence.push('QID 105015 (Authentication Failure) present');
        }
        if (qid === '105315') {
          hostAuthenticated = false;
          authAttempted = true;
          authConfidence = authConfidence === 'manual' ? 'high' : authConfidence;
          authEvidence.push('QID 105315 (Web Authentication Failed) present');
        }
        if (qid === '150008') {
          hostAuthenticated = false;
          authAttempted = true;
          authConfidence = authConfidence === 'manual' ? 'high' : authConfidence;
          authEvidence.push('QID 150008 (WAS Authentication Failed) present');
        }
        if (qid === '150095') {
          hostAuthenticated = false;
          authAttempted = true;
          authConfidence = authConfidence === 'manual' ? 'high' : authConfidence;
          authEvidence.push('QID 150095 (WAS Selenium Auth Failed) present');
        }

        // Auth success indicators (only set if not already determined)
        if (qid === '150007' && hostAuthenticated === null) {
          hostAuthenticated = true;
          authAttempted = true;
          authConfidence = authConfidence === 'manual' ? 'high' : authConfidence;
          authEvidence.push('QID 150007 (WAS Authentication Successful) present');
        }
        if (qid === '150094' && hostAuthenticated === null) {
          hostAuthenticated = true;
          authAttempted = true;
          authConfidence = authConfidence === 'manual' ? 'high' : authConfidence;
          authEvidence.push('QID 150094 (WAS Selenium Auth Successful) present');
        }

        // QID 105186: Host-Based Auth — secondary check
        if (qid === '105186') {
          authAttempted = true;
          if (/success/i.test(output)) {
            if (hostAuthenticated === null) {
              hostAuthenticated = true;
              authConfidence = authConfidence === 'manual' ? 'medium' : authConfidence;
            }
            authEvidence.push('QID 105186 (Host-Based Auth): success');
          } else if (/fail/i.test(output)) {
            if (hostAuthenticated === null) {
              hostAuthenticated = false;
              authConfidence = authConfidence === 'manual' ? 'medium' : authConfidence;
            }
            authEvidence.push('QID 105186 (Host-Based Auth): failure');
          }
        }

        // QID 86762: HTTP Auth attempted
        if (qid === '86762') {
          authAttempted = true;
          authEvidence.push('QID 86762 (HTTP Auth Method) present — auth attempted');
        }
      }
    }

    // Secondary: Check for APPENDIX/AUTH_STATS block (if present in parsed XML)
    if (hostAuthenticated === null && host.AUTH_STATS) {
      const stats = host.AUTH_STATS;
      const passed = stats.PASSED || stats.passed;
      const failed = stats.FAILED || stats.failed;
      if (passed && !failed) {
        hostAuthenticated = true;
        authConfidence = 'medium';
        authEvidence.push('AUTH_STATS block: PASSED');
      } else if (failed) {
        hostAuthenticated = false;
        authConfidence = 'medium';
        authEvidence.push('AUTH_STATS block: FAILED');
      }
    }

    if (authEvidence.length === 0) {
      authEvidence.push('No auth QIDs found (70028, 105015, 105186, 105315, 86762, 150007/150008, 150094/150095)');
    }

    authStatusByHost.set(assetId, {
      authenticated: hostAuthenticated,
      confidence: authConfidence,
      evidence: authEvidence.join('; '),
      attempted: authAttempted,
      manualReviewRequired: hostAuthenticated === null,
    });

    for (const vuln of vulns) {
      const severity = mapQualysSeverity(vuln.SEVERITY || vuln.severity || '0');
      const qid = vuln.QID || vuln.qid || '';
      const title = vuln.TITLE || vuln.title || vuln.VULN_TITLE || '';
      const description = vuln.RESULT || vuln.result || vuln.DIAGNOSIS || vuln.diagnosis || '';

      const cfo = {
        cfo_id: uuidv4(),
        scanner_source: `${fileName} | Qualys`,
        weakness_name: title,
        weakness_description: description,
        weakness_source_identifier: qid ? `QID-${qid}` : '',
        asset_identifier: assetId,
        original_detection_date: vuln.FIRST_FOUND || vuln.first_found || vuln.LAST_SCAN_DATETIME || null,
        original_risk_rating: severity,
        scan_type: 'VULNERABILITY',
        is_authenticated: hostAuthenticated,
        _auth_confidence: authConfidence,
        iiw_match_status: null,
        vendor_dependency: false,
        vendor_name: '',
        hardening_benchmark: '',
        assessor_comments: '',
        ret_id: null,
        mark_as_rcdt: false,
      };

      findings.push(cfo);
    }

    if (onProgress) onProgress(((h + 1) / totalHosts) * 100);
  }

  return { findings, authStatusByHost };
}

module.exports = { parseQualys };
