const xml2js = require('xml2js');
const { v4: uuidv4 } = require('uuid');

/**
 * Severity int → FedRAMP risk rating
 * 0 = Informational, 1 = Low, 2 = Moderate, 3 = High, 4 = Critical
 */
function mapNessusSeverity(severity) {
  const sev = parseInt(severity, 10);
  switch (sev) {
    case 4: return 'Critical';
    case 3: return 'High';
    case 2: return 'Moderate';
    case 1: return 'Low';
    case 0:
    default:
      return 'Informational';
  }
}

/**
 * Parse a Tenable Nessus .nessus XML file into CFOs.
 */
async function parseNessus(xmlContent, fileName, onProgress) {
  const parser = new xml2js.Parser({ explicitArray: false, mergeAttrs: true });
  const result = await parser.parseStringPromise(xmlContent);

  const findings = [];
  const root = result.NessusClientData_v2;
  if (!root || !root.Report) return findings;

  const report = root.Report;
  let hosts = report.ReportHost;
  if (!hosts) return findings;
  if (!Array.isArray(hosts)) hosts = [hosts];

  // Extract scan start time from preferences if available
  let scanDate = null;
  try {
    const prefs = root.Policy?.Preferences?.ServerPreferences?.preference;
    if (Array.isArray(prefs)) {
      const startPref = prefs.find((p) => p.name === 'scan_start_time' || p.name === 'HOST_START_TIMESTAMP');
      if (startPref) scanDate = startPref.value;
    }
  } catch {
    // ignore
  }

  const totalHosts = hosts.length;

  for (let h = 0; h < totalHosts; h++) {
    const host = hosts[h];
    const assetId = host.name || '';

    // Check for host start time
    let hostDate = scanDate;
    if (host.HostProperties?.tag) {
      const tags = Array.isArray(host.HostProperties.tag)
        ? host.HostProperties.tag
        : [host.HostProperties.tag];
      const startTag = tags.find((t) => t.name === 'HOST_START');
      if (startTag) hostDate = startTag._ || startTag;
    }

    let items = host.ReportItem;
    if (!items) continue;
    if (!Array.isArray(items)) items = [items];

    for (const item of items) {
      const severity = mapNessusSeverity(item.severity);

      // Determine scan_type: compliance items are CONFIG_FINDING
      const isCompliance =
        item['cm:compliance-check-name'] ||
        item.compliance ||
        (item.pluginFamily && item.pluginFamily.toLowerCase().includes('compliance'));
      const scanType = isCompliance ? 'CONFIG_FINDING' : 'VULNERABILITY';

      const cfo = {
        cfo_id: uuidv4(),
        scanner_source: `${fileName} | Tenable Nessus`,
        weakness_name: item.plugin_name || item.pluginName || '',
        weakness_description: item.description || '',
        weakness_source_identifier: item.pluginID || '',
        asset_identifier: assetId,
        original_detection_date: hostDate ? parseNessusDate(hostDate) : null,
        original_risk_rating: severity,
        scan_type: scanType,
        is_authenticated: null, // Determined later by IIW match
        iiw_match_status: null,
        vendor_dependency: false,
        vendor_name: '',
        hardening_benchmark: isCompliance ? (item['cm:compliance-check-name'] || '') : '',
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

function parseNessusDate(dateStr) {
  if (!dateStr) return null;
  try {
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return null;
    return d.toISOString().split('T')[0];
  } catch {
    return null;
  }
}

module.exports = { parseNessus };
