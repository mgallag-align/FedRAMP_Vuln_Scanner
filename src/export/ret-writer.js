const ExcelJS = require('exceljs');
const path = require('path');
const { classifyFindings } = require('../engine/classifier');

const RISK_ORDER = { Critical: 0, High: 1, Moderate: 2, Low: 3 };

/**
 * Export populated RET XLSX workbook.
 *
 * Uses the FedRAMP RET v2.5 template as a base if available,
 * otherwise creates the structure from scratch.
 *
 * Tab structure:
 *   - Risk Exposure Table (rows 1-7 header, data from row 8)
 *   - Configuration Findings (same + Col S: Hardening Benchmark)
 *   - Risks Corrected During Testing
 *   - PL-2 Findings (preserved blank with headers)
 */
async function exportRET(sessionData, outputPath, onProgress) {
  const { systemInfo, findings, iiwAssets, scanFiles, coverage } = sessionData;

  // Build file ID → detector type lookup from scan files
  const detectorTypeMap = new Map();
  if (scanFiles) {
    for (const sf of scanFiles) {
      if (sf.detectorType) {
        detectorTypeMap.set(sf.id, sf.detectorType);
      }
    }
  }

  // Classify findings
  const classified = classifyFindings(
    findings.filter((f) => f.original_risk_rating !== 'Informational')
  );

  const retFindings = sortByRisk(consolidateByCVE(classified.filter((f) => f._destination === 'RET')));
  const configFindings = sortByRisk(consolidateByCVE(classified.filter((f) => f._destination === 'CONFIG')));
  const rcdtFindings = sortByRisk(consolidateByCVE(classified.filter((f) => f._destination === 'RCDT')));

  // Try to load template, fall back to creating new workbook
  const workbook = new ExcelJS.Workbook();
  let templateLoaded = false;

  try {
    const templatePath = path.join(__dirname, '..', '..', 'assets', 'RET_template.xlsx');
    await workbook.xlsx.readFile(templatePath);
    templateLoaded = true;
  } catch {
    // Template not found — create from scratch
  }

  if (onProgress) onProgress(10);

  // ═══════════════════════════════════════════
  // Risk Exposure Table Tab
  // ═══════════════════════════════════════════
  let retSheet = templateLoaded
    ? workbook.getWorksheet('Risk Exposure Table')
    : null;

  if (!retSheet) {
    retSheet = workbook.addWorksheet('Risk Exposure Table');
    buildRETHeaders(retSheet, systemInfo);
  } else {
    // Update metadata rows with session info
    writeMetadataRows(retSheet, systemInfo);
  }

  // Write RET data starting at row 8
  let retRow = 8;
  for (const cfo of retFindings) {
    writeRETRow(retSheet, retRow, cfo, systemInfo, detectorTypeMap);
    retRow++;
  }

  // Auto-create CM-6 row if config findings exist
  if (configFindings.length > 0) {
    writeCM6Row(retSheet, retRow, systemInfo);
    retRow++;
  }

  if (onProgress) onProgress(40);

  // ═══════════════════════════════════════════
  // Configuration Findings Tab
  // ═══════════════════════════════════════════
  let configSheet = templateLoaded
    ? workbook.getWorksheet('Configuration Findings')
    : null;

  if (!configSheet) {
    configSheet = workbook.addWorksheet('Configuration Findings');
    buildConfigHeaders(configSheet, systemInfo);
  } else {
    writeMetadataRows(configSheet, systemInfo);
  }

  let configRow = 8;
  for (const cfo of configFindings) {
    writeConfigRow(configSheet, configRow, cfo, systemInfo, detectorTypeMap);
    configRow++;
  }

  if (onProgress) onProgress(60);

  // ═══════════════════════════════════════════
  // RCDT Tab
  // ═══════════════════════════════════════════
  let rcdtSheet = templateLoaded
    ? workbook.getWorksheet('Risks Corrected During Testing')
    : null;

  if (!rcdtSheet) {
    rcdtSheet = workbook.addWorksheet('Risks Corrected During Testing');
    buildRCDTHeaders(rcdtSheet, systemInfo);
  } else {
    writeMetadataRows(rcdtSheet, systemInfo);
  }

  let rcdtRow = 8;
  for (const cfo of rcdtFindings) {
    writeRCDTRow(rcdtSheet, rcdtRow, cfo, systemInfo, detectorTypeMap);
    rcdtRow++;
  }

  if (onProgress) onProgress(80);

  // ═══════════════════════════════════════════
  // PL-2 Findings Tab (preserved blank)
  // ═══════════════════════════════════════════
  if (!templateLoaded || !workbook.getWorksheet('PL-2 Findings')) {
    const pl2Sheet = workbook.addWorksheet('PL-2 Findings');
    buildPL2Headers(pl2Sheet, systemInfo);
  }

  // ═══════════════════════════════════════════
  // Scan Coverage Summary Tab (optional — only when IIW was uploaded)
  // ═══════════════════════════════════════════
  if (coverage && coverage.totalIIW > 0) {
    const existing = workbook.getWorksheet('Scan Coverage Summary');
    if (existing) workbook.removeWorksheet(existing.id);
    writeCoverageSummarySheet(workbook, coverage, systemInfo);
  }

  if (onProgress) onProgress(95);

  // Write to file
  await workbook.xlsx.writeFile(outputPath);

  if (onProgress) onProgress(100);
}

// ═══════════════════════════════════════════
// Header builders (for when no template exists)
// ═══════════════════════════════════════════

function buildRETHeaders(sheet, systemInfo) {
  // Row 1: Metadata
  sheet.getCell('A1').value = systemInfo.cspName;
  sheet.getCell('B1').value = systemInfo.systemName;
  sheet.getCell('C1').value = systemInfo.impactLevel;
  sheet.getCell('D1').value = formatDateForExcel(systemInfo.retDate);

  // Row 4: Column headers
  const headers = [
    '', // A: empty (row number area)
    'RET / POA&M ID',     // B
    'Controls',            // C
    'Weakness Name',       // D
    'Weakness Description', // E
    'Weakness Detector Source', // F
    'Weakness Source Identifier', // G
    'Asset Identifier',    // H
    'Original Detection Date', // I
    'Vendor Dependency',   // J
    'Vendor Dependent Product Name', // K
    'Original Risk Rating', // L
    'Adjusted Risk Rating', // M
    'Risk Adjustment',     // N
    'False Positive',      // O
    'Operational Requirement', // P
    'Deviation Rationale', // Q
    'Comments',            // R
  ];

  const headerRow = sheet.getRow(4);
  headers.forEach((h, idx) => {
    headerRow.getCell(idx + 1).value = h;
  });

  // Style header row
  headerRow.eachCell((cell) => {
    cell.font = { bold: true, color: { argb: 'FFFFFFFF' } };
    cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF003366' } };
    cell.alignment = { horizontal: 'center', wrapText: true };
  });

  // Row 5: Guidance
  sheet.getRow(5).getCell(1).value = 'Guidance';
  // Row 6: Examples
  sheet.getRow(6).getCell(1).value = 'Examples';
  // Row 7: Mandatory/Situational
  sheet.getRow(7).getCell(1).value = 'Mandatory/Situational';

  // Set column widths
  sheet.columns = [
    { width: 5 },   // A
    { width: 15 },  // B: RET ID
    { width: 12 },  // C: Controls
    { width: 30 },  // D: Weakness Name
    { width: 50 },  // E: Description
    { width: 20 },  // F: Detector Source
    { width: 22 },  // G: Source ID
    { width: 25 },  // H: Asset ID
    { width: 18 },  // I: Detection Date
    { width: 16 },  // J: Vendor Dep
    { width: 25 },  // K: Vendor Name
    { width: 18 },  // L: Original Risk
    { width: 18 },  // M: Adjusted Risk
    { width: 18 },  // N: Risk Adjustment
    { width: 15 },  // O: False Positive
    { width: 22 },  // P: Op Requirement
    { width: 25 },  // Q: Deviation
    { width: 35 },  // R: Comments
  ];
}

function buildConfigHeaders(sheet, systemInfo) {
  buildRETHeaders(sheet, systemInfo);
  // Add Column S: Hardening Benchmark Name
  sheet.getRow(4).getCell(19).value = 'Hardening Benchmark Name';
  sheet.getRow(4).getCell(19).font = { bold: true, color: { argb: 'FFFFFFFF' } };
  sheet.getRow(4).getCell(19).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF003366' } };
  sheet.getColumn(19).width = 30;
}

function buildRCDTHeaders(sheet, systemInfo) {
  buildRETHeaders(sheet, systemInfo);
}

function buildPL2Headers(sheet, systemInfo) {
  sheet.getCell('A1').value = systemInfo.cspName;
  sheet.getCell('B1').value = systemInfo.systemName;
  sheet.getCell('C1').value = systemInfo.impactLevel;
  sheet.getCell('D1').value = formatDateForExcel(systemInfo.retDate);

  const headerRow = sheet.getRow(4);
  headerRow.getCell(1).value = '';
  headerRow.getCell(2).value = 'PL-2 Finding ID';
  headerRow.getCell(3).value = 'Controls';
  headerRow.getCell(4).value = 'Weakness Name';
  headerRow.getCell(5).value = 'Weakness Description';
  headerRow.eachCell((cell) => {
    cell.font = { bold: true, color: { argb: 'FFFFFFFF' } };
    cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF003366' } };
  });
}

// ═══════════════════════════════════════════
// Row writers
// ═══════════════════════════════════════════

function writeMetadataRows(sheet, systemInfo) {
  sheet.getCell('A1').value = systemInfo.cspName;
  sheet.getCell('B1').value = systemInfo.systemName;
  sheet.getCell('C1').value = systemInfo.impactLevel;
  sheet.getCell('D1').value = formatDateForExcel(systemInfo.retDate);
}

function writeRETRow(sheet, rowNum, cfo, systemInfo, detectorTypeMap) {
  const row = sheet.getRow(rowNum);

  // Col B: RET / POA&M ID
  row.getCell(2).value = cfo.ret_id || '';
  // Col C: Controls — RA-5 for all scan-derived vulnerabilities
  row.getCell(3).value = 'RA-5';
  // Col D: Weakness Name (truncate to 255 chars)
  row.getCell(4).value = (cfo.weakness_name || '').substring(0, 255);
  // Col E: Weakness Description (full text)
  row.getCell(5).value = cfo.weakness_description || '';
  row.getCell(5).alignment = { wrapText: true };
  // Col F: Weakness Detector Source — user-selected scan type, fallback to scanner name
  const detectorType = detectorTypeMap && cfo.scanner_file_id
    ? detectorTypeMap.get(cfo.scanner_file_id) || ''
    : '';
  row.getCell(6).value = detectorType || extractScannerName(cfo.scanner_source);
  // Col G: Weakness Source Identifier (blank if none, NOT N/A)
  row.getCell(7).value = cfo.weakness_source_identifier || '';
  // Col H: Asset Identifier
  row.getCell(8).value = cfo.asset_identifier || '';
  row.getCell(8).alignment = { wrapText: true };
  // Col I: Original Detection Date (as Excel date)
  if (cfo.original_detection_date) {
    row.getCell(9).value = new Date(cfo.original_detection_date);
    row.getCell(9).numFmt = 'MM/DD/YYYY';
  }
  // Col J: Vendor Dependency
  row.getCell(10).value = cfo.vendor_dependency ? 'Yes' : 'No';
  // Col K: Vendor Dependent Product Name (blank unless vendor dep = Yes)
  row.getCell(11).value = cfo.vendor_dependency ? (cfo.vendor_name || '') : '';
  // Col L: Original Risk Rating
  row.getCell(12).value = cfo.original_risk_rating || '';
  // Col M: Adjusted Risk Rating — LEAVE BLANK
  row.getCell(13).value = '';
  // Col N: Risk Adjustment — LEAVE BLANK
  row.getCell(14).value = '';
  // Col O: False Positive — NOT APPLICABLE, greyed out on RET tab
  row.getCell(15).value = '';
  row.getCell(15).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFD9D9D9' } };
  // Col P: Operational Requirement — LEAVE BLANK
  row.getCell(16).value = '';
  // Col Q: Deviation Rationale — LEAVE BLANK
  row.getCell(17).value = '';
  // Col R: Comments
  row.getCell(18).value = cfo.assessor_comments || '';
  row.getCell(18).alignment = { wrapText: true };
}

function writeCM6Row(sheet, rowNum, systemInfo) {
  const row = sheet.getRow(rowNum);
  row.getCell(2).value = 'CM-6-001'; // CM-6 reference row
  row.getCell(3).value = 'CM-6';
  row.getCell(4).value = 'Configuration Findings \u2014 See Configuration Findings Tab';
  row.getCell(5).value =
    'One or more configuration findings were identified during assessment. Refer to the Configuration Findings tab for individual items.';
  row.getCell(5).alignment = { wrapText: true };
  row.getCell(6).value = '';
  row.getCell(7).value = '';
  row.getCell(8).value = 'Multiple \u2014 See Configuration Findings Tab';
  row.getCell(10).value = 'No';
  row.getCell(12).value = 'Moderate'; // Default risk for CM-6 reference
  // Leave adjustment fields blank
  row.getCell(15).value = '';
  row.getCell(15).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFD9D9D9' } };
}

function writeConfigRow(sheet, rowNum, cfo, systemInfo, detectorTypeMap) {
  // Same as RET row plus Column S
  writeRETRow(sheet, rowNum, cfo, systemInfo, detectorTypeMap);
  const row = sheet.getRow(rowNum);
  // Override controls to CM-6 for config findings
  row.getCell(3).value = 'CM-6';
  // Col S: Hardening Benchmark Name
  row.getCell(19).value = cfo.hardening_benchmark || '';
  // False Positive is NOT greyed out on Config Findings tab
  row.getCell(15).fill = null;
}

function writeRCDTRow(sheet, rowNum, cfo, systemInfo, detectorTypeMap) {
  const row = sheet.getRow(rowNum);

  // Same core fields as RET
  row.getCell(2).value = cfo.ret_id || '';
  row.getCell(3).value = cfo.scan_type === 'CONFIG_FINDING' ? 'CM-6' : 'RA-5';
  row.getCell(4).value = (cfo.weakness_name || '').substring(0, 255);
  row.getCell(5).value = cfo.weakness_description || '';
  row.getCell(5).alignment = { wrapText: true };
  // Col F: Weakness Detector Source — user-selected scan type, fallback to scanner name
  const detectorType = detectorTypeMap && cfo.scanner_file_id
    ? detectorTypeMap.get(cfo.scanner_file_id) || ''
    : '';
  row.getCell(6).value = detectorType || extractScannerName(cfo.scanner_source);
  row.getCell(7).value = cfo.weakness_source_identifier || '';
  row.getCell(8).value = cfo.asset_identifier || '';
  row.getCell(8).alignment = { wrapText: true };
  if (cfo.original_detection_date) {
    row.getCell(9).value = new Date(cfo.original_detection_date);
    row.getCell(9).numFmt = 'MM/DD/YYYY';
  }
  // RCDT-specific: Vendor Dependency = Not Applicable
  row.getCell(10).value = 'Not Applicable';
  row.getCell(11).value = '';
  row.getCell(12).value = cfo.original_risk_rating || '';
  // RCDT: Adjusted Risk Rating = Not Applicable
  row.getCell(13).value = 'Not Applicable';
  // RCDT: Risk Adjustment = Not Applicable
  row.getCell(14).value = 'Not Applicable';
  // False Positive — IS active on RCDT tab
  row.getCell(15).value = cfo.false_positive ? 'Yes' : '';
  // RCDT: Operational Requirement = Not Applicable
  row.getCell(16).value = 'Not Applicable';
  // RCDT: Deviation Rationale = Not Applicable
  row.getCell(17).value = 'Not Applicable';
  // Comments
  row.getCell(18).value = cfo.assessor_comments || '';
  row.getCell(18).alignment = { wrapText: true };
}

// ═══════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════

function sortByRisk(findings) {
  return [...findings].sort((a, b) => {
    const riskA = RISK_ORDER[a.original_risk_rating] ?? 4;
    const riskB = RISK_ORDER[b.original_risk_rating] ?? 4;
    if (riskA !== riskB) return riskA - riskB;
    return (a.weakness_name || '').localeCompare(b.weakness_name || '');
  });
}

/**
 * Consolidate findings so there is one row per CVE/weakness_source_identifier.
 * All affected asset identifiers are merged into a single newline-separated string.
 * When multiple findings share the same CVE, the consolidated row uses:
 *   - Highest severity (Critical > High > Moderate > Low)
 *   - Earliest detection date
 *   - Combined asset identifiers (deduplicated, newline-separated)
 *   - First non-empty value for other fields (weakness_name, description, etc.)
 *
 * Findings without a weakness_source_identifier are passed through as-is (one row each).
 */
function consolidateByCVE(findings) {
  const grouped = new Map();
  const noIdentifier = [];

  for (const cfo of findings) {
    const key = cfo.weakness_source_identifier;
    if (!key) {
      noIdentifier.push(cfo);
      continue;
    }
    if (!grouped.has(key)) {
      grouped.set(key, []);
    }
    grouped.get(key).push(cfo);
  }

  const consolidated = [];

  for (const [, group] of grouped) {
    // Start with the highest-severity finding as the base
    group.sort((a, b) => {
      const riskA = RISK_ORDER[a.original_risk_rating] ?? 4;
      const riskB = RISK_ORDER[b.original_risk_rating] ?? 4;
      return riskA - riskB;
    });
    const base = { ...group[0] };

    // Merge asset identifiers (deduplicated)
    const assetSet = new Set();
    for (const cfo of group) {
      if (cfo.asset_identifier) {
        // Split in case an asset_identifier already contains multiple values
        cfo.asset_identifier.split('\n').forEach((a) => {
          const trimmed = a.trim();
          if (trimmed) assetSet.add(trimmed);
        });
      }
    }
    base.asset_identifier = Array.from(assetSet).join('\n');

    // Use earliest detection date
    let earliest = null;
    for (const cfo of group) {
      if (cfo.original_detection_date) {
        const d = new Date(cfo.original_detection_date);
        if (!isNaN(d.getTime()) && (!earliest || d < earliest)) {
          earliest = d;
        }
      }
    }
    if (earliest) {
      base.original_detection_date = earliest.toISOString().split('T')[0];
    }

    // Merge scanner sources (deduplicated)
    const scannerSet = new Set();
    for (const cfo of group) {
      if (cfo.scanner_source) scannerSet.add(cfo.scanner_source);
    }
    if (scannerSet.size > 1) {
      base.scanner_source = Array.from(scannerSet).join('; ');
    }

    // Fill in any blank fields from other group members
    for (const field of ['weakness_name', 'weakness_description', 'vendor_name']) {
      if (!base[field]) {
        for (const cfo of group) {
          if (cfo[field]) {
            base[field] = cfo[field];
            break;
          }
        }
      }
    }

    // Vendor dependency: true if any finding says true
    base.vendor_dependency = group.some((cfo) => cfo.vendor_dependency);

    consolidated.push(base);
  }

  return [...consolidated, ...noIdentifier];
}

/**
 * Extract just the scanner product name from scanner_source.
 * e.g., "scan.nessus | Tenable Nessus" → "Tenable Nessus"
 */
function extractScannerName(source) {
  if (!source) return '';
  const parts = source.split('|');
  return parts.length > 1 ? parts[1].trim() : parts[0].trim();
}

/**
 * Format date string for Excel metadata.
 * Input: YYYY-MM-DD → Output: Date object for Excel
 */
function formatDateForExcel(dateStr) {
  if (!dateStr) return '';
  try {
    const d = new Date(dateStr + 'T00:00:00');
    if (isNaN(d.getTime())) return dateStr;
    return d;
  } catch {
    return dateStr;
  }
}

/**
 * Write a "Scan Coverage Summary" sheet to the workbook.
 * Documents authenticated% and inventory coverage% for each scanner,
 * plus a list of IIW assets not reached by any scan — FedRAMP expects
 * assessors to account for all inventory assets.
 */
function writeCoverageSummarySheet(workbook, coverage, systemInfo) {
  const sheet = workbook.addWorksheet('Scan Coverage Summary');

  const hdrFill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF003366' } };
  const hdrFont = { bold: true, color: { argb: 'FFFFFFFF' } };
  const sectionFill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFD9E1F2' } };

  // Row 1: System metadata
  sheet.getCell('A1').value = systemInfo.cspName || '';
  sheet.getCell('B1').value = systemInfo.systemName || '';
  sheet.getCell('C1').value = systemInfo.impactLevel || '';
  sheet.getCell('D1').value = formatDateForExcel(systemInfo.retDate);

  // Row 2: Generated timestamp
  sheet.getCell('A2').value = `Generated: ${new Date(coverage.computedAt || Date.now()).toLocaleString()}`;
  sheet.getCell('A2').font = { italic: true, color: { argb: 'FF666666' } };

  // Row 4: Global summary
  sheet.getCell('A4').value = 'Global Coverage Summary';
  sheet.getCell('A4').font = { bold: true };
  sheet.getCell('A4').fill = sectionFill;
  sheet.getCell('B4').value = `${coverage.coveragePercent}% — ${coverage.coveredAssets} of ${coverage.totalIIW} IIW assets covered`;

  // Row 6: Per-scanner table header
  const colHdrs = ['Scanner File', 'Scanner Type', 'Authenticated%', 'Coverage%', 'Assets Covered', 'Total IIW Assets'];
  const headerRow = sheet.getRow(6);
  colHdrs.forEach((h, i) => {
    const cell = headerRow.getCell(i + 1);
    cell.value = h;
    cell.font = hdrFont;
    cell.fill = hdrFill;
    cell.alignment = { horizontal: 'center' };
  });

  // Per-scanner data rows
  let r = 7;
  for (const ps of (coverage.perScanner || [])) {
    const row = sheet.getRow(r);
    row.getCell(1).value = ps.fileName || '';
    row.getCell(2).value = ps.scannerType || '';
    row.getCell(3).value = ps.authPercent !== null ? `${ps.authPercent}%` : 'N/A';
    row.getCell(4).value = `${ps.coveragePercent}%`;
    row.getCell(5).value = ps.coveredAssets;
    row.getCell(6).value = coverage.totalIIW;
    row.commit();
    r++;
  }

  // Uncovered assets section
  if (coverage.uncoveredList && coverage.uncoveredList.length > 0) {
    r += 1;
    const secRow = sheet.getRow(r);
    secRow.getCell(1).value = `IIW Assets Not Covered by Any Scanner (${coverage.uncoveredList.length})`;
    secRow.getCell(1).font = { bold: true };
    secRow.getCell(1).fill = sectionFill;
    r++;

    const uncHdr = sheet.getRow(r);
    ['Unique Asset ID', 'IP Address', 'DNS Name', 'Asset Type'].forEach((h, i) => {
      const cell = uncHdr.getCell(i + 1);
      cell.value = h;
      cell.font = hdrFont;
      cell.fill = hdrFill;
    });
    r++;

    for (const a of coverage.uncoveredList) {
      const row = sheet.getRow(r);
      row.getCell(1).value = a.uniqueAssetId || '';
      row.getCell(2).value = a.ipAddress || '';
      row.getCell(3).value = a.dnsName || '';
      row.getCell(4).value = a.assetType || '';
      row.commit();
      r++;
    }
  }

  // Column widths
  sheet.getColumn(1).width = 40;
  sheet.getColumn(2).width = 22;
  sheet.getColumn(3).width = 18;
  sheet.getColumn(4).width = 18;
  sheet.getColumn(5).width = 18;
  sheet.getColumn(6).width = 18;
}

module.exports = { exportRET };
