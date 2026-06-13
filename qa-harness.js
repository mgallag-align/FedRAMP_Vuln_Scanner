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
const { parseQualys } = require('./src/parsers/qualys');
const { parseSCAP } = require('./src/parsers/scap');
const { parseRapid7 } = require('./src/parsers/rapid7');
const { parsePrisma } = require('./src/parsers/prisma');
const { parseIIW } = require('./src/parsers/iiw');
const { exportRET } = require('./src/export/ret-writer');
const { mapCVSStoRisk, normalizeSeverity, RISK_ORDER } = require('./src/engine/severity');
const { sortByRisk, consolidateByCVE } = require('./src/engine/consolidate');
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
section('severity.js — shared mappers');
{
  eq(mapCVSStoRisk('9.8'), 'Critical', 'CVSS 9.8 → Critical');
  eq(mapCVSStoRisk('0'), 'Informational', 'CVSS 0 → Informational');
  eq(mapCVSStoRisk('abc'), 'Informational', 'CVSS NaN → Informational');
  eq(normalizeSeverity('Untriaged'), 'Moderate', 'normalizeSeverity Untriaged');
  eq(normalizeSeverity('5'), 'Critical', 'normalizeSeverity numeric 5');
  eq(RISK_ORDER.Critical, 0, 'RISK_ORDER Critical=0');
  // generic-csv must use the shared normalizer (same result through both paths)
  const viaCsv = mapRowsToFindings([{ a:'h', w:'x', s:'Untriaged' }], 'f', { asset_identifier:'a', weakness_name:'w', original_risk_rating:'s' })[0];
  eq(viaCsv.original_risk_rating, 'Moderate', 'generic-csv routes through shared normalizeSeverity');
}

// ═══════════════════════════════════════════════════════════════
section('consolidate.js — id-generator & exporter group identically');
{
  // Two findings, same CVE, different assets → ONE consolidated row.
  const findings = [
    cfo({ cfo_id:'a', weakness_source_identifier:'CVE-9', asset_identifier:'h1', original_risk_rating:'Moderate' }),
    cfo({ cfo_id:'b', weakness_source_identifier:'CVE-9', asset_identifier:'h2', original_risk_rating:'Critical' }),
    cfo({ cfo_id:'c', weakness_source_identifier:'CVE-8', asset_identifier:'h3', original_risk_rating:'Low' }),
  ];
  const consolidated = consolidateByCVE(findings);
  eq(consolidated.length, 2, 'two CVEs → two consolidated rows');
  const cve9 = consolidated.find(f => f.weakness_source_identifier === 'CVE-9');
  eq(cve9.original_risk_rating, 'Critical', 'consolidated row takes highest severity');
  ok(cve9.asset_identifier.includes('h1') && cve9.asset_identifier.includes('h2'), 'assets merged');

  // Parity: every CVE that the exporter consolidates must receive exactly one
  // ID from the generator, and all findings of that CVE share it.
  const withIds = generateIds(findings, { vulnPrefix:'VS', configPrefix:'CF', rcdtPrefix:'RC' });
  const idA = withIds.find(f => f.cfo_id === 'a').ret_id;
  const idB = withIds.find(f => f.cfo_id === 'b').ret_id;
  ok(idA && idA === idB, 'same-CVE findings share one RET ID (generator↔exporter parity)');
  const idC = withIds.find(f => f.cfo_id === 'c').ret_id;
  ok(idC && idC !== idA, 'different CVE gets a different ID');
  // Critical CVE-9 sorts before Low CVE-8 → VS-001 vs VS-002
  eq(idA, 'VS-001', 'highest-severity CVE gets VS-001');
  eq(idC, 'VS-002', 'lower-severity CVE gets VS-002');
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

// ═══════════════════════════════════════════════════════════════
section('iiw.js — header detection & robustness (async)');
async function iiwTests() {
  const ExcelJS = require('exceljs');

  // Build an IIW with columns in NON-legacy positions and an extra guidance row,
  // to prove header-detection resolves columns by label, not by fixed position.
  async function buildIIW(rows, headerAt = 3) {
    const wb = new ExcelJS.Workbook();
    const ws = wb.addWorksheet('Inventory');
    ws.getRow(1).getCell(1).value = 'FedRAMP Integrated Inventory Workbook';
    ws.getRow(2).getCell(1).value = 'Guidance row';
    // Header row at headerAt — columns deliberately at A/B/C/D/E (not B/C/F/I/M)
    const hdr = ws.getRow(headerAt);
    hdr.getCell(1).value = 'Unique Asset Identifier';
    hdr.getCell(2).value = 'IPv4 or IPv6 Address';
    hdr.getCell(3).value = 'DNS Name or URL';
    hdr.getCell(4).value = 'Authenticated Scan';
    hdr.getCell(5).value = 'Asset Type';
    rows.forEach((r, i) => {
      const row = ws.getRow(headerAt + 1 + i);
      row.getCell(1).value = r.id;
      row.getCell(2).value = r.ip;
      row.getCell(3).value = r.dns;
      row.getCell(4).value = r.auth;
      row.getCell(5).value = r.type;
    });
    const tmp = path.join(os.tmpdir(), `qa-iiw-${Date.now()}-${Math.random().toString(36).slice(2)}.xlsx`);
    await wb.xlsx.writeFile(tmp);
    return tmp;
  }

  const f1 = await buildIIW([
    { id: 'WEB-01', ip: '10.1.1.1', dns: 'web01.example.com', auth: 'Yes', type: 'Server' },
    { id: 'DB-01', ip: '10.1.1.2', dns: 'db01.example.com', auth: 'No', type: 'Database' },
  ]);
  let res = await parseIIW(f1);
  eq(res.assets.length, 2, 'IIW: parsed 2 assets from non-legacy column layout');
  eq(res.assets[0].uniqueAssetId, 'WEB-01', 'IIW: correct asset id by header');
  eq(res.assets[0].ipAddress, '10.1.1.1', 'IIW: correct IP by header (not fixed col C)');
  eq(res.assets[0].authenticatedScan, true, 'IIW: auth Yes→true by header (not fixed col I)');
  eq(res.assets[1].authenticatedScan, false, 'IIW: auth No→false');
  eq(res.assets[0].assetType, 'Server', 'IIW: asset type by header');
  fs.unlinkSync(f1);

  // Duplicate id → warned + first wins
  const f2 = await buildIIW([
    { id: 'DUP', ip: '1.1.1.1', dns: '', auth: 'Yes', type: '' },
    { id: 'dup', ip: '2.2.2.2', dns: '', auth: 'No', type: '' },
  ]);
  res = await parseIIW(f2);
  eq(res.assets.length, 1, 'IIW: duplicate id collapsed to 1');
  ok(res.warnings.some(w => w.includes('Duplicate')), 'IIW: duplicate warning emitted');
  fs.unlinkSync(f2);

  // No recognizable header → legacy fallback with warning
  const wb = new ExcelJS.Workbook();
  const ws = wb.addWorksheet('Inventory');
  for (let r = 1; r <= 5; r++) ws.getRow(r).getCell(1).value = `meta ${r}`;
  ws.getRow(6).getCell(2).value = 'LEGACY-01'; // col B
  ws.getRow(6).getCell(3).value = '10.0.0.9';  // col C
  ws.getRow(6).getCell(9).value = 'Yes';       // col I
  const f3 = path.join(os.tmpdir(), `qa-iiw-legacy-${Date.now()}.xlsx`);
  await wb.xlsx.writeFile(f3);
  res = await parseIIW(f3);
  eq(res.assets.length, 1, 'IIW: legacy fallback parses col B/C/I');
  eq(res.assets[0].uniqueAssetId, 'LEGACY-01', 'IIW: legacy fallback reads col B');
  ok(res.warnings.some(w => w.toLowerCase().includes('legacy')), 'IIW: legacy fallback warning');
  fs.unlinkSync(f3);
}

// ═══════════════════════════════════════════════════════════════
section('other parsers — qualys / scap / rapid7 / prisma (async)');
async function otherParserTests() {
  // Qualys
  const qualysXml = `<?xml version="1.0"?><SCAN><IP value="10.0.0.5" name="h">
    <VULNS><CAT><VULN><QID>38173</QID><TITLE>SSL Weak</TITLE><SEVERITY>4</SEVERITY><DIAGNOSIS>weak</DIAGNOSIS></VULN></CAT></VULNS>
    </IP></SCAN>`;
  let r = await parseQualys(qualysXml, 'q.xml');
  eq(r.findings.length, 1, 'qualys: 1 finding');
  eq(r.findings[0].original_risk_rating, 'High', 'qualys: severity 4 → High');
  eq(r.findings[0].weakness_source_identifier, 'QID-38173', 'qualys: QID id');
  ok('compliance_result' in r.findings[0], 'qualys: CFO has compliance fields');

  // SCAP/XCCDF — only failed rules become findings
  const scapXml = `<?xml version="1.0"?><Benchmark id="xccdf_bench" title="CIS RHEL8">
    <Group><Rule id="rule-1" severity="high"><title>Disable telnet</title><description>desc</description></Rule></Group>
    <TestResult><rule-result idref="rule-1"><result>fail</result></rule-result>
    <rule-result idref="rule-2"><result>pass</result></rule-result></TestResult></Benchmark>`;
  const scap = await parseSCAP(scapXml, 's.xml');
  eq(scap.length, 1, 'scap: only failed rule becomes a finding');
  eq(scap[0].scan_type, 'CONFIG_FINDING', 'scap: CONFIG_FINDING');
  eq(scap[0].original_risk_rating, 'High', 'scap: severity high');
  eq(scap[0].hardening_benchmark, 'CIS RHEL8', 'scap: benchmark title captured');
  ok(scap[0].compliance_result, 'scap: compliance_result set');

  // Rapid7 CSV (public API: parseRapid7 with format='csv')
  const r7res = await parseRapid7(
    'Asset IP Address,Vulnerability Title,CVSS Score,Vulnerability ID\n10.0.0.7,Old OpenSSH,7.5,CVE-2020-1\n',
    'r7.csv', null, 'csv');
  const r7 = r7res.findings;
  eq(r7.length, 1, 'rapid7: 1 finding');
  eq(r7[0].original_risk_rating, 'High', 'rapid7: CVSS 7.5 → High (shared mapper)');
  eq(r7[0].asset_identifier, '10.0.0.7', 'rapid7: asset ip');
  ok('compliance_result' in r7[0], 'rapid7: CFO has compliance fields');

  // Prisma JSON
  const prisma = await parsePrisma(
    { results: [{ id: 'img:1', vulnerabilities: [{ cve: 'CVE-2021-2', severity: 'critical', description: 'd', title: 'pkg flaw' }] }] },
    'p.json');
  eq(prisma.length, 1, 'prisma: 1 finding');
  eq(prisma[0].original_risk_rating, 'Critical', 'prisma: severity critical');
  eq(prisma[0].weakness_source_identifier, 'CVE-2021-2', 'prisma: cve id');
  ok('compliance_result' in prisma[0], 'prisma: CFO has compliance fields');
}

(async () => {
  try { await nessusTests(); } catch (e) { fail++; failures.push('nessus threw: ' + e.message); console.log(e); }
  try { await exportTests(); } catch (e) { fail++; failures.push('export threw: ' + e.message); console.log(e); }
  try { await iiwTests(); } catch (e) { fail++; failures.push('iiw threw: ' + e.message); console.log(e); }
  try { await otherParserTests(); } catch (e) { fail++; failures.push('other-parsers threw: ' + e.message); console.log(e); }
  console.log(`\n${'='.repeat(50)}\nRESULTS: ${pass} passed, ${fail} failed`);
  if (fail > 0) { console.log('FAILURES:\n  - ' + failures.join('\n  - ')); process.exit(1); }
  else console.log('ALL TESTS PASSED ✓');
})();
