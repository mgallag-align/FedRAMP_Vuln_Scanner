/* eslint-disable */
// Comprehensive QA harness — run with: node qa-harness.js
// Tests pure engine logic, parsers, ESM renderer utils (via babel), and a full export round-trip.

const path = require('path');
const fs = require('fs');
const os = require('os');
const babel = require('@babel/core');
const Module = require('module');

// ── Tiny assert framework ──
let pass = 0, fail = 0;
const failures = [];
function ok(cond, name) {
  if (cond) { pass++; }
  else { fail++; failures.push(name); console.log('  ✗ ' + name); }
}
function eq(a, b, name) { ok(JSON.stringify(a) === JSON.stringify(b), `${name} (got ${JSON.stringify(a)}, want ${JSON.stringify(b)})`); }
function section(t) { console.log('\n=== ' + t + ' ==='); }

// ── Load an ESM file as CommonJS via babel ──
function loadESM(relPath) {
  const full = path.join(__dirname, relPath);
  const src = fs.readFileSync(full, 'utf8');
  const { code } = babel.transformSync(src, {
    presets: [['@babel/preset-env', { targets: { node: 'current' } }]],
    filename: full,
  });
  const m = new Module(full, module);
  m.filename = full;
  m.paths = Module._nodeModulePaths(path.dirname(full));
  m._compile(code, full);
  return m.exports;
}

const { matchAssets } = require('./src/engine/matcher');
const { classifyFindings } = require('./src/engine/classifier');
const { validateExport } = require('./src/engine/validator');
const { generateIds } = require('./src/engine/id-generator');
const { mapRowsToFindings, detectCSVFormat } = require('./src/parsers/generic-csv');
const { parseNessus } = require('./src/parsers/nessus');
const { exportRET } = require('./src/export/ret-writer');
const rescan = loadESM('src/renderer/utils/rescan.js');
const coverage = loadESM('src/renderer/utils/coverage.js');

function cfo(over = {}) {
  return {
    cfo_id: Math.random().toString(36).slice(2),
    scanner_source: 'f | X', weakness_name: 'W', weakness_description: '',
    weakness_source_identifier: 'CVE-1', asset_identifier: 'host', original_detection_date: '2026-01-01',
    original_risk_rating: 'High', scan_type: 'VULNERABILITY', is_authenticated: null,
    iiw_match_status: null, vendor_dependency: false, vendor_name: '', hardening_benchmark: '',
    compliance_result: null, assessor_comments: '', ret_id: null, mark_as_rcdt: false, ...over,
  };
}

// ═══════════════════════════════════════════════════════════════
section('matcher.js — 5-tier asset matching');
{
  const iiw = [
    { uniqueAssetId: 'ASSET-01', ipAddress: '10.0.0.1', dnsName: 'web01.example.com', assetType: 'Server', authenticatedScan: true },
    { uniqueAssetId: 'ASSET-10', ipAddress: '10.0.0.10', dnsName: 'web10.example.com', assetType: 'Server', authenticatedScan: false },
    { uniqueAssetId: 'DB-01', ipAddress: '10.0.0.5, 10.0.0.6', dnsName: 'db01.example.com', assetType: 'DB', authenticatedScan: true },
  ];
  const m = (id) => matchAssets([cfo({ asset_identifier: id })], iiw)[0];

  let r = m('ASSET-01'); ok(r.iiw_match_status === 'MATCHED' && r._match_tier === 1, 'T1 exact ID');
  ok(r.is_authenticated === true, 'T1 carries auth=true');
  r = m('10.0.0.1'); ok(r.iiw_match_status === 'MATCHED' && r._match_tier === 2, 'T2 exact IP');
  r = m('https://web01.example.com'); ok(r.iiw_match_status === 'MATCHED' && r._match_tier === 3, 'T3 DNS scheme-strip');
  r = m('web01'); ok(r.iiw_match_status === 'MATCHED' && r._match_tier === 5, 'T5 fuzzy short-form');
  ok((r.assessor_comments || '').includes('FUZZY'), 'T5 adds FUZZY note');
  r = m('host01, 10.0.0.1'); ok(r.iiw_match_status === 'MATCHED' && r._match_tier === 4, 'T4 composite single → matched');
  // composite producing 2 distinct candidates → AMBIGUOUS
  r = m('10.0.0.1 10.0.0.10'); ok(r.iiw_match_status === 'AMBIGUOUS' && r._iiw_candidates.length === 2, 'T4 composite multi → AMBIGUOUS');
  // IP prefix non-collision
  r = m('10.0.0.1'); ok(r.asset_identifier === 'ASSET-01', 'IP 10.0.0.1 does NOT collide with 10.0.0.10');
  // composite IIW IP field (multi-IP) indexed
  r = m('10.0.0.6'); ok(r.iiw_match_status === 'MATCHED' && r.asset_identifier === 'DB-01', 'multi-IP IIW field tokenized');
  // unauth note
  r = m('ASSET-10'); ok(r.is_authenticated === false && (r.assessor_comments||'').includes('UNAUTHENTICATED'), 'unauth note added');
  // no match
  r = m('totally-unknown-xyz'); ok(r.iiw_match_status === 'UNMATCHED', 'no match → UNMATCHED');
  // empty id
  r = m(''); ok(r.iiw_match_status === 'UNMATCHED', 'empty id → UNMATCHED');
  // no IIW
  r = matchAssets([cfo()], [])[0]; ok(r.iiw_match_status === 'UNMATCHED' && r.is_authenticated === null, 'no IIW → all UNMATCHED');
}

// ═══════════════════════════════════════════════════════════════
section('rescan.js — baseline vs rescan comparison');
{
  const files = [
    { id: 'base', isRescan: false },
    { id: 'rescan', isRescan: true },
  ];
  // base has CVE-1@hostA (still open), CVE-2@hostA (remediated)
  // rescan has CVE-1@hostA (still present), CVE-3@hostB (new)
  const findings = [
    cfo({ cfo_id: 'b1', scanner_file_id: 'base', asset_identifier: 'hostA', weakness_source_identifier: 'CVE-1' }),
    cfo({ cfo_id: 'b2', scanner_file_id: 'base', asset_identifier: 'hostA', weakness_source_identifier: 'CVE-2' }),
    cfo({ cfo_id: 'r1', scanner_file_id: 'rescan', asset_identifier: 'hostA', weakness_source_identifier: 'CVE-1' }),
    cfo({ cfo_id: 'r3', scanner_file_id: 'rescan', asset_identifier: 'hostB', weakness_source_identifier: 'CVE-3' }),
  ];
  const out = rescan.applyRescanComparison(findings, files);
  const byId = Object.fromEntries(out.map(f => [f.cfo_id, f]));
  ok(byId['b1'] && !byId['b1'].mark_as_rcdt, 'baseline still-present finding stays open');
  ok(byId['b2'] && byId['b2'].mark_as_rcdt && byId['b2']._rcdt_reason, 'baseline remediated → auto-RCDT');
  ok(!byId['r1'], 'rescan duplicate of open finding dropped');
  ok(byId['r3'] && !byId['r3'].mark_as_rcdt, 'rescan-only new finding included & open');
  eq(out.length, 3, 'rescan output count');
  eq(rescan.countRescanRcdt(out), 1, 'countRescanRcdt');
  // no rescan files → unchanged
  const noRescan = rescan.applyRescanComparison(findings, [{ id: 'base', isRescan: false }, { id: 'rescan', isRescan: false }]);
  eq(noRescan.length, 4, 'no rescan flag → unchanged');
}

// ═══════════════════════════════════════════════════════════════
section('generic-csv — normalizeSeverity (via mapRowsToFindings)');
{
  const map = { asset_identifier: 'a', weakness_name: 'w', original_risk_rating: 's' };
  const sev = (s) => mapRowsToFindings([{ a: 'h', w: 'x', s }], 'f', map)[0].original_risk_rating;
  eq(sev('Critical'), 'Critical', 'text Critical');
  eq(sev('medium'), 'Moderate', 'medium → Moderate');
  eq(sev('MED'), 'Moderate', 'MED → Moderate');
  eq(sev('info'), 'Informational', 'info → Informational');
  eq(sev('none'), 'Informational', 'none → Informational');
  eq(sev('Untriaged'), 'Moderate', 'Untriaged → Moderate');
  eq(sev('5'), 'Critical', 'numeric 5 → Critical');
  eq(sev('4'), 'High', 'numeric 4 → High');
  eq(sev('1'), 'Low', 'numeric 1 → Low');
  eq(sev('0'), 'Informational', 'numeric 0 → Informational');
  eq(sev('9.8'), 'Critical', 'CVSS 9.8 → Critical');
  eq(sev('7.5'), 'High', 'CVSS 7.5 → High');
  eq(sev('5.5'), 'Moderate', 'CVSS 5.5 → Moderate');
  eq(sev(''), 'Informational', 'empty → Informational');
  // scan_type routing
  const ct = mapRowsToFindings([{ a:'h', w:'x', s:'High', t:'Compliance' }], 'f', { ...map, scan_type: 't' })[0];
  eq(ct.scan_type, 'CONFIG_FINDING', 'scan_type compliance → CONFIG_FINDING');
  // compliance fields present in CFO
  ok('compliance_result' in ct && 'compliance_actual_value' in ct, 'generic CFO has compliance fields');
}

// ═══════════════════════════════════════════════════════════════
section('classifier.js');
{
  eq(classifyFindings([cfo()])[0]._destination, 'RET', 'VULN → RET');
  eq(classifyFindings([cfo({ scan_type: 'CONFIG_FINDING' })])[0]._destination, 'CONFIG', 'CONFIG → CONFIG');
  eq(classifyFindings([cfo({ scan_type: 'CONFIG_FINDING', mark_as_rcdt: true })])[0]._destination, 'RCDT', 'RCDT precedence');
}

// ═══════════════════════════════════════════════════════════════
section('id-generator.js');
{
  const ids = generateIds([
    cfo({ cfo_id: 'a', weakness_source_identifier: 'CVE-A', original_risk_rating: 'Low' }),
    cfo({ cfo_id: 'b', weakness_source_identifier: 'CVE-B', original_risk_rating: 'Critical' }),
    cfo({ cfo_id: 'c', scan_type: 'CONFIG_FINDING', weakness_source_identifier: 'CF-1' }),
    cfo({ cfo_id: 'd', mark_as_rcdt: true, weakness_source_identifier: 'CVE-D' }),
  ], { vulnPrefix: 'VS', configPrefix: 'CF', rcdtPrefix: 'RC' });
  const byId = Object.fromEntries(ids.map(f => [f.cfo_id, f.ret_id]));
  eq(byId['b'], 'VS-001', 'Critical vuln gets VS-001 (sorted first)');
  eq(byId['a'], 'VS-002', 'Low vuln gets VS-002');
  eq(byId['c'], 'CF-001', 'config gets CF-001');
  eq(byId['d'], 'RC-001', 'rcdt gets RC-001');
}

// ═══════════════════════════════════════════════════════════════
section('validator.js');
{
  const base = {
    systemInfo: { cspName: 'C', systemName: 'S', impactLevel: 'Moderate', retDate: '2026-01-01' },
    findings: [cfo()], iiwAssets: [{ uniqueAssetId: 'X' }], scanFiles: [{ id: '1' }], unauthAcknowledged: [],
  };
  let v = validateExport(base); eq(v.errors.length, 0, 'valid session → no errors');
  v = validateExport({ ...base, systemInfo: {} }); ok(v.errors.some(e => e.code === 'V-01'), 'V-01 missing sysinfo');
  v = validateExport({ ...base, scanFiles: [] }); ok(v.errors.some(e => e.code === 'V-03'), 'V-03 no scan files');
  v = validateExport({ ...base, findings: [cfo({ iiw_match_status: 'UNMATCHED' })] }); ok(v.warnings.some(w => w.code === 'V-04'), 'V-04 unmatched warning');
  v = validateExport({ ...base, findings: [cfo({ iiw_match_status: 'AMBIGUOUS' })] }); ok(v.warnings.some(w => w.code === 'V-04b'), 'V-04b ambiguous warning');
  v = validateExport({ ...base, findings: [cfo({ cfo_id:'x', ret_id: 'VS-001', weakness_source_identifier: 'CVE-1' }), cfo({ cfo_id:'y', ret_id: 'VS-001', weakness_source_identifier: 'CVE-2' })] });
  ok(v.errors.some(e => e.code === 'V-06'), 'V-06 duplicate RET IDs');
}

// ═══════════════════════════════════════════════════════════════
section('coverage.js');
{
  eq(coverage.getAuthPercent({ totalHosts: 4, authenticatedHigh: 2, authenticatedMedLow: 1 }), 75, 'auth% 75');
  eq(coverage.getAuthPercent(null), null, 'auth% null when no summary');
  const iiw = [{ uniqueAssetId: 'A' }, { uniqueAssetId: 'B' }, { uniqueAssetId: 'C' }];
  const findings = [
    cfo({ iiw_match_status: 'MATCHED', asset_identifier: 'A', scanner_file_id: 'f1' }),
    cfo({ iiw_match_status: 'MATCHED', asset_identifier: 'B', scanner_file_id: 'f1' }),
    cfo({ iiw_match_status: 'UNMATCHED', asset_identifier: 'Z', scanner_file_id: 'f1' }),
  ];
  const cov = coverage.computeCoverage(findings, iiw, [{ id: 'f1', name: 'scan1', scannerType: 'Nessus' }]);
  eq(cov.coveredAssets, 2, 'coverage covered=2');
  eq(cov.coveragePercent, 67, 'coverage 67%');
  eq(cov.uncoveredList.length, 1, 'one uncovered (C)');
  eq(cov.perScanner[0].coveredAssets, 2, 'per-scanner covered=2');
  eq(coverage.computeCoverage(findings, [], []), null, 'no IIW → null');
}

// ═══════════════════════════════════════════════════════════════
section('nessus.js — compliance extraction (async)');
async function nessusTests() {
  const xml = `<?xml version="1.0"?>
  <NessusClientData_v2><Report name="r"><ReportHost name="host-a">
    <HostProperties><tag name="Credentialed_Scan">true</tag><tag name="HOST_START">Mon Jan 5 10:00:00 2026</tag></HostProperties>
    <ReportItem pluginID="100" pluginName="CIS Benchmark 1.1" severity="0" pluginFamily="Policy Compliance"
      cm:compliance-check-name="Ensure password length" cm:compliance-result="FAILED"
      cm:compliance-actual-value="8" cm:compliance-policy-value="14" cm:compliance-info="Set min length"></ReportItem>
    <ReportItem pluginID="101" pluginName="CIS Benchmark 1.2" severity="0" pluginFamily="Policy Compliance"
      cm:compliance-check-name="Ensure audit enabled" cm:compliance-result="PASSED"></ReportItem>
    <ReportItem pluginID="200" pluginName="OpenSSL Vuln" severity="3"></ReportItem>
  </ReportHost></Report></NessusClientData_v2>`;
  const { findings } = await parseNessus(xml, 'scan.nessus');
  const failed = findings.find(f => f.weakness_source_identifier === '100');
  const passed = findings.find(f => f.weakness_source_identifier === '101');
  const vuln = findings.find(f => f.weakness_source_identifier === '200');
  ok(failed.scan_type === 'CONFIG_FINDING', 'compliance item → CONFIG_FINDING');
  ok(failed.compliance_result === 'FAILED', 'compliance_result=FAILED');
  eq(failed.original_risk_rating, 'Moderate', 'FAILED sev0 promoted to Moderate');
  eq(failed.weakness_name, 'Ensure password length', 'weakness_name = check name');
  eq(failed.hardening_benchmark, 'CIS Benchmark 1.1', 'hardening_benchmark = plugin_name');
  ok((failed.assessor_comments||'').includes('Actual: 8') && failed.assessor_comments.includes('Expected: 14'), 'comments have actual/expected');
  eq(failed.weakness_description, 'Set min length', 'description from compliance-info');
  eq(passed.original_risk_rating, 'Informational', 'PASSED → Informational');
  ok(failed.is_authenticated === true, 'host auth detected from Credentialed_Scan tag');
  eq(vuln.scan_type, 'VULNERABILITY', 'non-compliance item → VULNERABILITY');
  eq(vuln.original_risk_rating, 'High', 'vuln severity 3 → High');
}

// ═══════════════════════════════════════════════════════════════
section('ret-writer.js — full export round-trip (async)');
async function exportTests() {
  const ExcelJS = require('exceljs');
  const tmp = path.join(os.tmpdir(), `qa-ret-${Date.now()}.xlsx`);
  const sessionData = {
    systemInfo: { cspName: 'CSP', systemName: 'Sys', impactLevel: 'Moderate', retDate: '2026-01-01', vulnPrefix:'VS', configPrefix:'CF', rcdtPrefix:'RC' },
    findings: [
      cfo({ cfo_id:'v1', ret_id: 'VS-001', weakness_source_identifier: 'CVE-100', asset_identifier: 'A', original_risk_rating: 'High' }),
      cfo({ cfo_id:'c1', ret_id: 'CF-001', scan_type: 'CONFIG_FINDING', weakness_source_identifier: 'CF-X',
            asset_identifier: 'B', hardening_benchmark: 'CIS 1.1', compliance_result: 'FAILED', assessor_comments: 'Actual: 8 | Expected: 14' }),
      cfo({ cfo_id:'r1', ret_id: 'RC-001', mark_as_rcdt: true, _rcdt_reason: 'Not in rescan', weakness_source_identifier: 'CVE-200', asset_identifier: 'C' }),
    ],
    iiwAssets: [{ uniqueAssetId: 'A', ipAddress:'', dnsName:'', assetType:'' }, { uniqueAssetId: 'D', ipAddress:'', dnsName:'', assetType:'' }],
    scanFiles: [{ id: 'f1', name: 'scan1', scannerType: 'Nessus', detectorType: 'Infrastructure' }],
    coverage: { totalIIW: 2, coveredAssets: 1, uncoveredAssets: 1, coveragePercent: 50,
      perScanner: [{ fileId:'f1', fileName:'scan1', scannerType:'Nessus', coveredAssets:1, coveragePercent:50, authPercent:100 }],
      uncoveredList: [{ uniqueAssetId:'D', ipAddress:'', dnsName:'', assetType:'' }], computedAt: new Date().toISOString() },
  };
  await exportRET(sessionData, tmp);
  ok(fs.existsSync(tmp), 'export file created');

  const wb = new ExcelJS.Workbook();
  await wb.xlsx.readFile(tmp);
  const ret = wb.getWorksheet('Risk Exposure Table');
  const cfgSheet = wb.getWorksheet('Configuration Findings');
  const rcdtSheet = wb.getWorksheet('Risks Corrected During Testing');
  const covSheet = wb.getWorksheet('Scan Coverage Summary');
  ok(ret && cfgSheet && rcdtSheet, 'core sheets exist');
  ok(covSheet, 'coverage sheet exists');

  // RET row 8: the vuln
  ok(ret.getCell('C8').value === 'RA-5', 'RET control = RA-5');
  ok(ret.getCell('B8').value === 'VS-001', 'RET id = VS-001');
  // CM-6 reference row should follow the vuln (row 9) since config findings exist
  let cm6Found = false;
  ret.eachRow((row) => { if (row.getCell(3).value === 'CM-6') cm6Found = true; });
  ok(cm6Found, 'CM-6 reference row auto-created on RET tab');

  // Config sheet: control CM-6, hardening benchmark in S, compliance tag in comments
  ok(cfgSheet.getCell('C8').value === 'CM-6', 'Config control = CM-6');
  eq(cfgSheet.getCell('S8').value, 'CIS 1.1', 'Config S col = hardening benchmark');
  ok(String(cfgSheet.getCell('R8').value).includes('[FAILED]'), 'Config comments has [FAILED] tag');

  // RCDT sheet: NA fields
  ok(rcdtSheet.getCell('C8').value === 'RA-5', 'RCDT vuln control RA-5');
  ok(rcdtSheet.getCell('J8').value === 'Not Applicable', 'RCDT vendor dep = Not Applicable');

  // Coverage sheet content
  ok(String(covSheet.getCell('B4').value).includes('50%'), 'coverage sheet shows 50%');
  fs.unlinkSync(tmp);
}

// ═══════════════════════════════════════════════════════════════
section('main-process modules load');
{
  const mods = ['./src/parsers/index','./src/parsers/nessus','./src/parsers/qualys','./src/parsers/scap',
    './src/parsers/rapid7','./src/parsers/prisma','./src/parsers/generic-csv','./src/parsers/universal-parser',
    './src/parsers/csv-sections','./src/parsers/iiw','./src/export/ret-writer','./src/engine/matcher',
    './src/engine/classifier','./src/engine/validator','./src/engine/id-generator','./src/engine/normalizer'];
  let allOk = true;
  for (const m of mods) { try { require(m); } catch (e) { allOk = false; console.log('  ✗ load ' + m + ': ' + e.message); } }
  ok(allOk, 'all main-process modules load');
}

(async () => {
  try { await nessusTests(); } catch (e) { fail++; failures.push('nessus threw: ' + e.message); console.log(e); }
  try { await exportTests(); } catch (e) { fail++; failures.push('export threw: ' + e.message); console.log(e); }
  console.log(`\n${'='.repeat(50)}\nRESULTS: ${pass} passed, ${fail} failed`);
  if (fail > 0) { console.log('FAILURES:\n  - ' + failures.join('\n  - ')); process.exit(1); }
  else console.log('ALL TESTS PASSED ✓');
})();
