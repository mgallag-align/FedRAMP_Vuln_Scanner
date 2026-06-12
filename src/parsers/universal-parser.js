const ExcelJS = require('exceljs');
const { parseCSVSections, selectBestSection } = require('./csv-sections');

/**
 * Universal file parser for the Vulnerability Mapper.
 * Supports CSV, XLSX/XLS, and JSON files.
 * Returns extracted headers and row data for the mapping UI.
 */

/**
 * Parse a file and return its headers and rows.
 * @param {Buffer} contentBuffer - Raw file content
 * @param {string} fileName - Original file name (for extension detection)
 * @returns {Promise<{ headers: string[], rows: object[], totalRows: number }>}
 */
async function parseUniversalFile(contentBuffer, fileName) {
  const ext = fileName.toLowerCase().split('.').pop();

  switch (ext) {
    case 'csv':
      return parseCSV(contentBuffer.toString('utf-8'));
    case 'xlsx':
    case 'xls':
      return parseExcel(contentBuffer);
    case 'json':
      return parseJSON(contentBuffer.toString('utf-8'));
    default:
      throw new Error(`Unsupported file format: .${ext}. Supported: .csv, .xlsx, .xls, .json`);
  }
}

/**
 * Parse CSV content and return headers + rows.
 *
 * Section-aware: multi-section files (e.g. Qualys CSV with a title block, a
 * blank separator, then the findings table) are split on blank rows and the
 * findings section is selected automatically. Blank rows within that section
 * are skipped so trailing data is never dropped.
 */
function parseCSV(content) {
  const { headers, rows, totalRows, sectionWarning } = parseCSVSections(content);
  return { headers, rows, totalRows, sectionWarning };
}

/**
 * Convert an ExcelJS cell value to a plain string, handling rich text,
 * dates, formulas, and hyperlink objects.
 */
function cellToString(value) {
  if (value == null) return '';
  if (typeof value === 'object') {
    if (value.richText) return value.richText.map((rt) => rt.text).join('');
    if (value instanceof Date) return value.toISOString().split('T')[0];
    if (value.text != null) return String(value.text); // hyperlink
    if (value.result != null) return String(value.result); // formula
    if (value.error != null) return String(value.error);
    return '';
  }
  return String(value);
}

/**
 * Parse Excel (XLSX/XLS) content and return headers + rows.
 * Uses the first worksheet by default.
 *
 * Section-aware: the worksheet is read into raw rows (blank rows preserved)
 * and the findings section is selected automatically — handling exports that
 * begin with a title/summary block followed by a blank gap and the real table.
 */
async function parseExcel(contentBuffer) {
  const workbook = new ExcelJS.Workbook();
  await workbook.xlsx.load(contentBuffer);

  const worksheet = workbook.worksheets[0];
  if (!worksheet || worksheet.rowCount === 0) {
    throw new Error('Excel file has no data or worksheets.');
  }

  // Build raw array-of-arrays, preserving blank rows so section breaks are
  // detectable. Determine the max column count across the sheet.
  const colCount = worksheet.columnCount;
  const rawRows = [];
  for (let rowNum = 1; rowNum <= worksheet.rowCount; rowNum++) {
    const row = worksheet.getRow(rowNum);
    const cells = [];
    for (let c = 1; c <= colCount; c++) {
      cells.push(cellToString(row.getCell(c).value).trim());
    }
    rawRows.push(cells);
  }

  const { headers, rows, totalRows, sectionWarning } = selectBestSection(rawRows);

  if (headers.length === 0) {
    throw new Error('No headers found in the Excel file.');
  }

  return { headers, rows, totalRows, sectionWarning };
}

/**
 * Parse JSON content and return headers + rows.
 * Supports: array of objects, or object with an array property.
 */
function parseJSON(content) {
  const json = JSON.parse(content);
  let dataArray;

  if (Array.isArray(json)) {
    dataArray = json;
  } else if (typeof json === 'object' && json !== null) {
    // Find the first array property
    const arrayKey = Object.keys(json).find((k) => Array.isArray(json[k]));
    if (arrayKey) {
      dataArray = json[arrayKey];
    } else {
      // Wrap single object in array
      dataArray = [json];
    }
  } else {
    throw new Error('JSON file must contain an array or object with an array property.');
  }

  if (dataArray.length === 0) {
    return { headers: [], rows: [], totalRows: 0 };
  }

  // Collect all unique keys across all objects for headers
  const headerSet = new Set();
  dataArray.forEach((item) => {
    if (typeof item === 'object' && item !== null) {
      Object.keys(item).forEach((k) => headerSet.add(k));
    }
  });

  const headers = Array.from(headerSet);

  // Normalize rows — flatten nested objects to strings
  const rows = dataArray
    .filter((item) => typeof item === 'object' && item !== null)
    .map((item) => {
      const row = {};
      headers.forEach((h) => {
        const val = item[h];
        if (val === null || val === undefined) {
          row[h] = '';
        } else if (typeof val === 'object') {
          row[h] = JSON.stringify(val);
        } else {
          row[h] = String(val);
        }
      });
      return row;
    });

  return {
    headers,
    rows,
    totalRows: rows.length,
  };
}

/**
 * Apply a field mapping to parsed rows and produce FedRAMP-standardized output.
 * @param {object[]} rows - Parsed data rows
 * @param {object} mapping - { targetField: sourceField, ... }
 * @param {object} defaults - Default values for unmapped required fields
 * @returns {object[]} Transformed rows matching FedRAMP RET schema
 */
function applyMapping(rows, mapping, defaults = {}) {
  const FEDRAMP_DEFAULTS = {
    vulnerability_id: '',
    source_of_discovery: '',
    cvss_score: '',
    affected_inventory: '',
    weakness_name: '',
    weakness_description: '',
    weakness_source_identifier: '',
    original_risk_rating: 'Informational',
    original_detection_date: '',
    remediation_plan: '',
    scheduled_completion_date: '',
    milestone_changes: '',
    vendor_dependency: 'No',
    vendor_name: '',
    last_vendor_check_in: '',
    risk_adjustment: 'No',
    false_positive: 'No',
    operational_requirement: 'No',
    deviation_request: '',
    supporting_documents: '',
    comments: '',
    auto_approve_status: '',
  };

  return rows.map((row) => {
    const mapped = { ...FEDRAMP_DEFAULTS, ...defaults };

    Object.entries(mapping).forEach(([targetField, sourceField]) => {
      if (sourceField && row[sourceField] !== undefined) {
        mapped[targetField] = row[sourceField] || mapped[targetField];
      }
    });

    // Normalize risk rating if present
    if (mapped.original_risk_rating) {
      mapped.original_risk_rating = normalizeRiskRating(mapped.original_risk_rating);
    }

    return mapped;
  });
}

/**
 * Normalize severity/risk strings to FedRAMP standard values.
 */
function normalizeRiskRating(raw) {
  const lower = String(raw).toLowerCase().trim();
  const ratingMap = {
    critical: 'Critical',
    crit: 'Critical',
    high: 'High',
    moderate: 'Moderate',
    medium: 'Moderate',
    med: 'Moderate',
    low: 'Low',
    informational: 'Informational',
    info: 'Informational',
    none: 'Informational',
  };

  if (ratingMap[lower]) return ratingMap[lower];

  // Try as CVSS score
  const score = parseFloat(raw);
  if (!isNaN(score)) {
    if (score >= 9.0) return 'Critical';
    if (score >= 7.0) return 'High';
    if (score >= 4.0) return 'Moderate';
    if (score > 0) return 'Low';
    return 'Informational';
  }

  return raw; // Return as-is if unrecognized
}

module.exports = { parseUniversalFile, applyMapping };
