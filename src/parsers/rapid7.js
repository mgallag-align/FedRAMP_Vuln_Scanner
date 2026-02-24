const xml2js = require('xml2js');
const { parse: csvParse } = require('csv-parse/sync');
const { v4: uuidv4 } = require('uuid');

/**
 * CVSS v3 score → FedRAMP risk rating
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
  // NexposeReport structure
  const nodes = result.NexposeReport?.nodes?.node;
  if (!nodes) return findings;

  const nodeList = Array.isArray(nodes) ? nodes : [nodes];
  const total = nodeList.length;

  for (let n = 0; n < total; n++) {
    const node = nodeList[n];
    const assetId = node.address || node.name || '';
    const tests = node.tests?.test;
    if (!tests) continue;

    const testList = Array.isArray(tests) ? tests : [tests];
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
    if (onProgress) onProgress(((n + 1) / total) * 100);
  }

  return findings;
}

async function parseRapid7(content, fileName, onProgress, format) {
  if (format === 'csv') {
    return parseRapid7CSV(content, fileName, onProgress);
  }
  return parseRapid7XML(content, fileName, onProgress);
}

module.exports = { parseRapid7 };
