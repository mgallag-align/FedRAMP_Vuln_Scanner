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
        is_authenticated: null,
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

  return findings;
}

module.exports = { parseQualys };
