const { v4: uuidv4 } = require('uuid');

/**
 * CVSS score → FedRAMP risk rating
 */
function mapCVSStoRisk(cvss) {
  const score = parseFloat(cvss);
  if (isNaN(score)) return 'Informational';
  if (score >= 9.0) return 'Critical';
  if (score >= 7.0) return 'High';
  if (score >= 4.0) return 'Moderate';
  if (score > 0) return 'Low';
  return 'Informational';
}

/**
 * Map Prisma Cloud / Twistlock severity string to FedRAMP rating
 */
function mapPrismaSeverity(severity) {
  if (!severity) return 'Informational';
  const s = severity.toLowerCase();
  if (s === 'critical') return 'Critical';
  if (s === 'high') return 'High';
  if (s === 'medium' || s === 'moderate') return 'Moderate';
  if (s === 'low') return 'Low';
  return 'Informational';
}

/**
 * Parse Prisma Cloud / Twistlock JSON output into CFOs.
 * Expects JSON with 'results' or 'vulnerabilities' array at root.
 */
async function parsePrisma(json, fileName, onProgress) {
  const findings = [];

  // Prisma/Twistlock structures
  let vulns = json.results || json.vulnerabilities || [];
  if (!Array.isArray(vulns)) vulns = [vulns];

  // Handle nested structure: results[].vulnerabilities[]
  const flatVulns = [];
  for (const item of vulns) {
    if (item.vulnerabilities && Array.isArray(item.vulnerabilities)) {
      // Container image result with nested vulns
      const imageId = item.id || item.imageName || item._id || '';
      for (const v of item.vulnerabilities) {
        flatVulns.push({ ...v, _assetId: imageId });
      }
    } else {
      flatVulns.push(item);
    }
  }

  const total = flatVulns.length;

  for (let i = 0; i < total; i++) {
    const vuln = flatVulns[i];

    const cveId = vuln.cve || vuln.cveID || vuln.id || '';
    const severity = vuln.severity
      ? mapPrismaSeverity(vuln.severity)
      : mapCVSStoRisk(vuln.cvss || vuln.cvssScore || '0');

    const cfo = {
      cfo_id: uuidv4(),
      scanner_source: `${fileName} | Prisma Cloud`,
      weakness_name: vuln.title || vuln.packageName || cveId || 'Unknown Vulnerability',
      weakness_description: vuln.description || vuln.desc || '',
      weakness_source_identifier: cveId,
      asset_identifier: vuln._assetId || vuln.host || vuln.hostname || vuln.image || vuln.packageName || '',
      original_detection_date: vuln.discoveredDate || vuln.published || null,
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
    if (onProgress && i % 100 === 0) onProgress((i / total) * 100);
  }

  if (onProgress) onProgress(100);
  return findings;
}

module.exports = { parsePrisma };
