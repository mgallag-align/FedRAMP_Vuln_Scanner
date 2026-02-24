const { parseNessus } = require('./nessus');
const { parseQualys } = require('./qualys');
const { parseRapid7 } = require('./rapid7');
const { parsePrisma } = require('./prisma');
const { parseSCAP } = require('./scap');
const { parseGenericCSV, detectCSVFormat } = require('./generic-csv');

/**
 * Detect scanner type from file content and extension, then parse.
 * Returns { scannerType, findings[], authWarning, error?, needsMapping?, csvHeaders? }
 */
async function detectAndParse(contentBuffer, fileName, onProgress) {
  const ext = fileName.toLowerCase().split('.').pop();
  const content = contentBuffer.toString('utf-8');

  // ── .nessus files → always Tenable Nessus ──
  if (ext === 'nessus') {
    if (!content.includes('<NessusClientData_v2')) {
      return { error: `Could not parse ${fileName} — file may be corrupt or truncated.`, findings: [], scannerType: null };
    }
    const findings = await parseNessus(content, fileName, onProgress);
    return { scannerType: 'Tenable Nessus', findings, authWarning: false };
  }

  // ── .xml files → Qualys, SCAP/XCCDF, or Rapid7 ──
  if (ext === 'xml') {
    // Qualys detection
    if (content.includes('<SCAN') || content.includes('<QualysGuardEnterpriseQualityReport')) {
      const findings = await parseQualys(content, fileName, onProgress);
      return { scannerType: 'Qualys', findings, authWarning: false };
    }

    // SCAP / XCCDF detection
    if (content.includes('xccdf') || content.includes('<Benchmark') || content.includes('<TestResult')) {
      const findings = await parseSCAP(content, fileName, onProgress);
      return { scannerType: 'SCAP/XCCDF', findings, authWarning: false };
    }

    // Rapid7 XML detection
    if (content.includes('<NexposeReport') || content.includes('<VulnerabilityDefinitions')) {
      const findings = await parseRapid7(content, fileName, onProgress, 'xml');
      return { scannerType: 'Rapid7 InsightVM', findings, authWarning: false };
    }

    // Nessus XML without .nessus extension
    if (content.includes('<NessusClientData_v2')) {
      const findings = await parseNessus(content, fileName, onProgress);
      return { scannerType: 'Tenable Nessus', findings, authWarning: false };
    }

    return { error: `Could not parse ${fileName} — unrecognized XML format.`, findings: [], scannerType: null };
  }

  // ── .json files → Prisma Cloud / Twistlock ──
  if (ext === 'json') {
    try {
      const json = JSON.parse(content);
      if (json.results || json.vulnerabilities) {
        const findings = await parsePrisma(json, fileName, onProgress);
        return { scannerType: 'Prisma Cloud', findings, authWarning: false };
      }
      return { error: `Could not parse ${fileName} — JSON does not match known scanner format.`, findings: [], scannerType: null };
    } catch {
      return { error: `Could not parse ${fileName} — invalid JSON.`, findings: [], scannerType: null };
    }
  }

  // ── .csv files → Rapid7 or Generic CSV ──
  if (ext === 'csv') {
    const detection = await detectCSVFormat(content);

    if (detection.type === 'rapid7') {
      const findings = await parseRapid7(content, fileName, onProgress, 'csv');
      return { scannerType: 'Rapid7 InsightVM', findings, authWarning: false };
    }

    if (detection.type === 'unknown') {
      // Need manual field mapping
      return {
        error: `Unknown CSV format for ${fileName}. Manual field mapping required.`,
        findings: [],
        scannerType: null,
        needsMapping: true,
        csvHeaders: detection.headers,
      };
    }

    // Attempt generic parse with auto-detected mapping
    const findings = await parseGenericCSV(content, fileName, detection.mapping, onProgress);
    return { scannerType: 'Generic CSV', findings, authWarning: false };
  }

  return { error: `Unsupported file type: ${ext}`, findings: [], scannerType: null };
}

module.exports = { detectAndParse };
