const { parseNessus } = require('./nessus');
const { parseQualys } = require('./qualys');
const { parseRapid7 } = require('./rapid7');
const { parsePrisma } = require('./prisma');
const { parseSCAP } = require('./scap');
const { parseGenericCSV, detectCSVFormat } = require('./generic-csv');

/**
 * Detect scanner type from file content and extension, then parse.
 * Returns { scannerType, findings[], authWarning, authDetails?, error?, needsMapping?, csvHeaders? }
 *
 * authWarning: true if scan auth status is unknown or any hosts were unauthenticated
 * authDetails: optional string with specifics (e.g., "3 of 10 hosts unauthenticated")
 */
async function detectAndParse(contentBuffer, fileName, onProgress) {
  const ext = fileName.toLowerCase().split('.').pop();
  let content = contentBuffer.toString('utf-8');
  // Strip UTF-8 BOM if present
  if (content.charCodeAt(0) === 0xFEFF) content = content.slice(1);

  // ── .nessus files → always Tenable Nessus ──
  if (ext === 'nessus') {
    if (!content.includes('<NessusClientData_v2')) {
      return { error: `Could not parse ${fileName} — file may be corrupt or truncated.`, findings: [], scannerType: null };
    }
    return handleNessusResult(await parseNessus(content, fileName, onProgress));
  }

  // ── .xml files → Qualys, SCAP/XCCDF, or Rapid7 ──
  if (ext === 'xml') {
    // Qualys detection
    if (content.includes('<SCAN') || content.includes('<QualysGuardEnterpriseQualityReport')) {
      const qualysResult = await parseQualys(content, fileName, onProgress);
      return handleQualysResult(qualysResult);
    }

    // SCAP / XCCDF detection — SCAP benchmarks are agent-based (authenticated by nature)
    if (content.includes('xccdf') || content.includes('<Benchmark') || content.includes('<TestResult')) {
      const findings = await parseSCAP(content, fileName, onProgress);
      return {
        scannerType: 'SCAP/XCCDF',
        findings,
        authWarning: false,
        authDetails: 'Authenticated — SCAP/XCCDF benchmarks execute locally on the host (agent-based)',
        authField: 'N/A (inherently authenticated — agent runs on target host)',
      };
    }

    // Rapid7 XML detection
    if (content.includes('<NexposeReport') || content.includes('<VulnerabilityDefinitions')) {
      const rapid7Result = await parseRapid7(content, fileName, onProgress, 'xml');
      return handleRapid7Result(rapid7Result, 'xml');
    }

    // Nessus XML without .nessus extension
    if (content.includes('<NessusClientData_v2')) {
      return handleNessusResult(await parseNessus(content, fileName, onProgress));
    }

    return { error: `Could not parse ${fileName} — unrecognized XML format.`, findings: [], scannerType: null };
  }

  // ── .json files → Prisma Cloud / Twistlock ──
  if (ext === 'json') {
    try {
      const json = JSON.parse(content);
      if (json.results || json.vulnerabilities) {
        const findings = await parsePrisma(json, fileName, onProgress);
        return {
          scannerType: 'Prisma Cloud',
          findings,
          authWarning: false,
          authDetails: 'Authenticated — Prisma Cloud/Twistlock performs agent-based container image scanning',
          authField: 'N/A (inherently authenticated — agent scans container images directly)',
        };
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
      const rapid7Result = await parseRapid7(content, fileName, onProgress, 'csv');
      return handleRapid7Result(rapid7Result, 'csv');
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
    return {
      scannerType: 'Generic CSV',
      findings,
      authWarning: true,
      authDetails: 'Authentication status unknown — CSV export does not contain credential check fields',
      authField: 'No standard auth indicator field available in CSV format',
    };
  }

  return { error: `Unsupported file type: ${ext}`, findings: [], scannerType: null };
}

/**
 * Compute auth summary from a structured authStatusByHost map.
 * Each entry is { authenticated, confidence, evidence, attempted, manualReviewRequired }.
 * Returns { authWarning, authDetails, authField, authSummary }.
 */
function computeAuthSummary(authStatusByHost, scannerType, authFieldLabel) {
  const totalHosts = authStatusByHost.size;
  let authHighCount = 0;
  let authMedLowCount = 0;
  let unauthCount = 0;
  let manualCount = 0;
  const manualReviewHosts = [];
  const hostDetails = [];

  for (const [host, status] of authStatusByHost) {
    const entry = {
      host,
      authenticated: status.authenticated,
      confidence: status.confidence,
      evidence: status.evidence,
      manualReviewRequired: status.manualReviewRequired,
    };
    hostDetails.push(entry);

    if (status.authenticated === true) {
      if (status.confidence === 'high') authHighCount++;
      else authMedLowCount++;
    } else if (status.authenticated === false) {
      unauthCount++;
    } else {
      manualCount++;
      manualReviewHosts.push(host);
    }
  }

  let authWarning = false;
  let authDetails = '';

  if (unauthCount > 0) {
    authWarning = true;
    authDetails = `${unauthCount} of ${totalHosts} host(s) unauthenticated`;
  }
  if (manualCount > 0) {
    authWarning = true;
    const manualMsg = `${manualCount} host(s) require manual review`;
    authDetails = authDetails ? `${authDetails}; ${manualMsg}` : manualMsg;
  }
  if (!authWarning && authHighCount > 0) {
    authDetails = `All ${totalHosts} host(s) authenticated (${authHighCount} high confidence`;
    if (authMedLowCount > 0) authDetails += `, ${authMedLowCount} medium/low confidence`;
    authDetails += ')';
  }

  const authSummary = {
    totalHosts,
    authenticatedHigh: authHighCount,
    authenticatedMedLow: authMedLowCount,
    unauthenticated: unauthCount,
    manualReview: manualCount,
    manualReviewHosts,
    hostDetails,
    compliant: unauthCount === 0 && manualCount === 0,
  };

  return {
    authWarning,
    authDetails,
    authField: authFieldLabel,
    authSummary,
  };
}

/**
 * Process Nessus parser result and compute auth warning from per-host credential checks.
 * Multi-layer detection:
 *   Tier 1: Credentialed_Scan tag in <HostProperties>
 *   Tier 2: Plugin 19506 (Nessus Scan Information) → "Credentialed checks : yes/no"
 *   Tier 3: Failure plugins 21745 (Auth Failure), 104410 (Credential Status Failure), 110385 (Auth Success)
 */
function handleNessusResult(nessusResult) {
  const { findings, authStatusByHost } = nessusResult;
  const authInfo = computeAuthSummary(
    authStatusByHost,
    'Tenable Nessus',
    'Tier 1: Credentialed_Scan tag (HostProperties) | Tier 2: Plugin 19506 ("Credentialed checks : yes/no") | Tier 3: Plugins 21745/104410/110385'
  );

  return {
    scannerType: 'Tenable Nessus',
    findings,
    ...authInfo,
  };
}

/**
 * Process Qualys parser result and compute auth warning from per-host credential checks.
 * Multi-layer detection:
 *   QID 70028 (Windows Auth — parse RESULT for success/failure)
 *   QID 105015 (Auth Failure), QID 105315 (Web Auth Failed)
 *   QID 150007/150008 (WAS Auth Success/Failure)
 *   QID 150094/150095 (WAS Selenium Auth Success/Failure)
 *   QID 105186 (Host-Based Auth), QID 86762 (HTTP Auth Attempted)
 *   AUTH_STATS block (if present)
 */
function handleQualysResult(qualysResult) {
  const { findings, authStatusByHost } = qualysResult;
  const authInfo = computeAuthSummary(
    authStatusByHost,
    'Qualys',
    'QID 70028 (Windows Auth) | QID 105015 (Auth Failure) | QID 105315 (Web Auth Failed) | QID 150007/150008 (WAS Auth) | QID 150094/150095 (WAS Selenium) | QID 105186 (Host-Based Auth) | QID 86762 (HTTP Auth)'
  );

  return {
    scannerType: 'Qualys',
    findings,
    ...authInfo,
  };
}

/**
 * Process Rapid7 parser result and compute auth warning from per-node credential status.
 * Multi-layer detection:
 *   Tier 1: <credentials> block with success attribute per node
 *   Tier 2: Result code distribution (ve/vp local checks vs vv version-only)
 *   Tier 3: Scan template name + credential configuration
 */
function handleRapid7Result(rapid7Result, format) {
  const { findings, authStatusByHost } = rapid7Result;

  if (format === 'csv') {
    return {
      scannerType: 'Rapid7 InsightVM',
      findings,
      authWarning: true,
      authDetails: 'Authentication status unknown — not available in Rapid7 CSV export',
      authField: 'No auth indicator field in Rapid7 CSV format (use XML export for credential status)',
      authSummary: {
        totalHosts: 0,
        authenticatedHigh: 0,
        authenticatedMedLow: 0,
        unauthenticated: 0,
        manualReview: 0,
        manualReviewHosts: [],
        hostDetails: [],
        compliant: false,
      },
    };
  }

  const authInfo = computeAuthSummary(
    authStatusByHost,
    'Rapid7 InsightVM',
    'Tier 1: <node> credential/status attributes | Tier 2: Result code distribution (ve/vp vs vv) | Tier 3: Scan template name + credential config'
  );

  return {
    scannerType: 'Rapid7 InsightVM',
    findings,
    ...authInfo,
  };
}

module.exports = { detectAndParse };
