const ExcelJS = require('exceljs');

/**
 * Parse the Integrated Inventory Workbook (IIW / SSP Appendix M).
 *
 * IIW structure:
 *   Sheet: 'Inventory'
 *   Rows 1-5: header/guidance rows (skip)
 *   Row 6+: data rows
 *
 * Columns:
 *   B: UNIQUE ASSET IDENTIFIER (primary lookup key)
 *   C: IPv4 or IPv6 Address (secondary match)
 *   F: DNS Name or URL (tertiary match)
 *   I: Authenticated Scan (YES/NO)
 *   M: Asset Type (context)
 */
async function parseIIW(filePath, onProgress) {
  const workbook = new ExcelJS.Workbook();
  await workbook.xlsx.readFile(filePath);

  // Find Inventory sheet (case-insensitive)
  let sheet = null;
  workbook.eachSheet((ws) => {
    if (ws.name.toLowerCase().includes('inventory')) {
      sheet = ws;
    }
  });

  if (!sheet) {
    // Fallback: use first sheet
    sheet = workbook.worksheets[0];
  }

  if (!sheet) {
    return { error: 'IIW workbook has no worksheets.', assets: [] };
  }

  const assets = [];
  const totalRows = sheet.rowCount;
  const seenIds = new Set();
  const warnings = [];

  // Data starts at row 6 (skip rows 1-5 header/guidance)
  for (let rowNum = 6; rowNum <= totalRows; rowNum++) {
    const row = sheet.getRow(rowNum);

    // Column B = Unique Asset Identifier
    const colB = getCellValue(row, 2);
    // Column C = IPv4/IPv6
    const colC = getCellValue(row, 3);
    // Column F = DNS Name or URL
    const colF = getCellValue(row, 6);
    // Column I = Authenticated Scan
    const colI = getCellValue(row, 9);
    // Column M = Asset Type
    const colM = getCellValue(row, 13);

    // Skip rows where Unique Asset Identifier is blank
    if (!colB || !colB.trim()) {
      if (colC || colF) {
        warnings.push(`Row ${rowNum}: Unique Asset Identifier (Col B) is blank — skipped.`);
      }
      continue;
    }

    const uniqueAssetId = colB.trim();

    // Check for duplicates
    if (seenIds.has(uniqueAssetId.toLowerCase())) {
      warnings.push(`Row ${rowNum}: Duplicate Unique Asset Identifier "${uniqueAssetId}" — using first occurrence.`);
      continue;
    }
    seenIds.add(uniqueAssetId.toLowerCase());

    // Parse authenticated scan field
    let authenticated = null;
    if (colI) {
      const authVal = colI.trim().toLowerCase();
      if (authVal === 'yes') authenticated = true;
      else if (authVal === 'no') authenticated = false;
      // else null (unknown)
    }

    assets.push({
      uniqueAssetId,
      ipAddress: colC ? colC.trim() : '',
      dnsName: colF ? colF.trim().replace(/^https?:\/\//i, '') : '',
      authenticatedScan: authenticated,
      assetType: colM ? colM.trim() : '',
      rowNumber: rowNum,
    });

    if (onProgress && rowNum % 50 === 0) {
      onProgress(((rowNum - 5) / (totalRows - 5)) * 100);
    }
  }

  if (onProgress) onProgress(100);

  return { assets, warnings };
}

/**
 * Get cell value as a string, handling various ExcelJS cell types.
 */
function getCellValue(row, colNum) {
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
