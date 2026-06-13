const ExcelJS = require('exceljs');

/**
 * Parse the Integrated Inventory Workbook (IIW / SSP Appendix M).
 *
 * The FedRAMP IIW template historically places data on the 'Inventory' sheet
 * with column B = Unique Asset Identifier, C = IP, F = DNS, I = Authenticated,
 * M = Asset Type, and 5 header/guidance rows before the data. CSPs reorder and
 * relabel columns and template versions shift, so this parser DETECTS the
 * header row and resolves each column by matching its label, falling back to
 * the legacy fixed positions only when no header row can be found.
 *
 * Because the IIW drives all asset matching, mis-reading a column would put
 * wrong asset data into a federal deliverable — so a column resolved by
 * fallback (not by header) is surfaced as a warning.
 */

// Header label matchers (lowercased substring/keyword tests) for each field.
const COLUMN_MATCHERS = {
  uniqueAssetId: (h) =>
    (h.includes('unique') && (h.includes('asset') || h.includes('identifier'))) ||
    h === 'unique asset identifier' ||
    h.includes('asset id'),
  ipAddress: (h) =>
    h.includes('ipv4') || h.includes('ipv6') || h === 'ip address' ||
    (h.includes('ip') && h.includes('address')),
  dnsName: (h) =>
    h.includes('dns') || h.includes('netbios') || (h.includes('host') && h.includes('name')) ||
    h.includes('url'),
  authenticatedScan: (h) =>
    h.includes('authenticated') || (h.includes('auth') && h.includes('scan')),
  assetType: (h) =>
    h === 'asset type' || (h.includes('asset') && h.includes('type')) ||
    h.includes('function') || h.includes('hardware/software'),
};

// Legacy fixed column positions (1-based) used as a fallback.
const LEGACY_COLS = {
  uniqueAssetId: 2, // B
  ipAddress: 3, // C
  dnsName: 6, // F
  authenticatedScan: 9, // I
  assetType: 13, // M
};

/**
 * Scan the first `maxRows` rows for the one that best matches IIW column
 * headers. Returns { headerRow, columnMap } where columnMap maps each field
 * to a 1-based column index (or null if that field's header wasn't found).
 */
function detectHeaderRow(sheet, maxRows = 10) {
  let best = null;
  const limit = Math.min(maxRows, sheet.rowCount);

  for (let rowNum = 1; rowNum <= limit; rowNum++) {
    const row = sheet.getRow(rowNum);
    const map = { uniqueAssetId: null, ipAddress: null, dnsName: null, authenticatedScan: null, assetType: null };
    let matched = 0;

    for (let col = 1; col <= sheet.columnCount; col++) {
      const raw = getCellValue(row, col).trim().toLowerCase();
      if (!raw) continue;
      for (const [field, matcher] of Object.entries(COLUMN_MATCHERS)) {
        if (map[field] === null && matcher(raw)) {
          map[field] = col;
          matched++;
          break;
        }
      }
    }

    // A real header row matches the primary key plus at least one other field.
    if (map.uniqueAssetId !== null && matched >= 2) {
      if (!best || matched > best.matched) best = { headerRow: rowNum, columnMap: map, matched };
    }
  }

  return best;
}

/**
 * Parse the Integrated Inventory Workbook into a normalized asset list.
 */
async function parseIIW(filePath, onProgress) {
  const workbook = new ExcelJS.Workbook();
  await workbook.xlsx.readFile(filePath);

  // Find Inventory sheet (case-insensitive), fall back to the first sheet.
  let sheet = null;
  workbook.eachSheet((ws) => {
    if (ws.name.toLowerCase().includes('inventory')) sheet = ws;
  });
  if (!sheet) sheet = workbook.worksheets[0];
  if (!sheet) return { error: 'IIW workbook has no worksheets.', assets: [] };

  const assets = [];
  const totalRows = sheet.rowCount;
  const seenIds = new Set();
  const warnings = [];

  // Resolve columns by header, else fall back to the legacy fixed layout.
  const detected = detectHeaderRow(sheet);
  let columnMap;
  let dataStartRow;

  if (detected) {
    columnMap = { ...detected.columnMap };
    dataStartRow = detected.headerRow + 1;
    // Backfill any field whose header wasn't found, and warn about it.
    for (const [field, col] of Object.entries(LEGACY_COLS)) {
      if (columnMap[field] == null) {
        columnMap[field] = col;
        if (field === 'uniqueAssetId' || field === 'authenticatedScan') {
          warnings.push(
            `Could not find a "${field}" column header — assuming the legacy position (column ${colLetter(col)}). Verify the resolved data is correct.`
          );
        }
      }
    }
  } else {
    columnMap = { ...LEGACY_COLS };
    dataStartRow = 6;
    warnings.push(
      'No recognizable IIW header row was found — falling back to the legacy fixed column layout (B/C/F/I/M, data from row 6). Verify the parsed assets are correct.'
    );
  }

  for (let rowNum = dataStartRow; rowNum <= totalRows; rowNum++) {
    const row = sheet.getRow(rowNum);

    const colId = getCellValue(row, columnMap.uniqueAssetId);
    const colIp = getCellValue(row, columnMap.ipAddress);
    const colDns = getCellValue(row, columnMap.dnsName);
    const colAuth = getCellValue(row, columnMap.authenticatedScan);
    const colType = getCellValue(row, columnMap.assetType);

    // Skip rows where Unique Asset Identifier is blank
    if (!colId || !colId.trim()) {
      if (colIp || colDns) {
        warnings.push(`Row ${rowNum}: Unique Asset Identifier is blank — skipped.`);
      }
      continue;
    }

    const uniqueAssetId = colId.trim();

    // Duplicate detection (case-insensitive)
    if (seenIds.has(uniqueAssetId.toLowerCase())) {
      warnings.push(`Row ${rowNum}: Duplicate Unique Asset Identifier "${uniqueAssetId}" — using first occurrence.`);
      continue;
    }
    seenIds.add(uniqueAssetId.toLowerCase());

    // Authenticated scan field → true / false / null
    let authenticated = null;
    if (colAuth) {
      const authVal = colAuth.trim().toLowerCase();
      if (authVal === 'yes' || authVal === 'true') authenticated = true;
      else if (authVal === 'no' || authVal === 'false') authenticated = false;
    }

    assets.push({
      uniqueAssetId,
      ipAddress: colIp ? colIp.trim() : '',
      dnsName: colDns ? colDns.trim().replace(/^https?:\/\//i, '') : '',
      authenticatedScan: authenticated,
      assetType: colType ? colType.trim() : '',
      rowNumber: rowNum,
    });

    if (onProgress && rowNum % 50 === 0) {
      onProgress(((rowNum - dataStartRow + 1) / (totalRows - dataStartRow + 1)) * 100);
    }
  }

  if (onProgress) onProgress(100);

  return { assets, warnings };
}

/**
 * Convert a 1-based column index to its Excel letter (1→A, 2→B, 27→AA).
 */
function colLetter(col) {
  let s = '';
  let n = col;
  while (n > 0) {
    const rem = (n - 1) % 26;
    s = String.fromCharCode(65 + rem) + s;
    n = Math.floor((n - 1) / 26);
  }
  return s;
}

/**
 * Get cell value as a string, handling various ExcelJS cell types.
 */
function getCellValue(row, colNum) {
  if (colNum == null) return '';
  const cell = row.getCell(colNum);
  if (!cell || cell.value === null || cell.value === undefined) return '';

  if (typeof cell.value === 'object') {
    // Rich text
    if (cell.value.richText) {
      return cell.value.richText.map((rt) => rt.text).join('');
    }
    // Hyperlink
    if (cell.value.text) return cell.value.text;
    // Formula
    if (cell.value.result !== undefined) return String(cell.value.result);
    return String(cell.value);
  }

  return String(cell.value);
}

module.exports = { parseIIW };
