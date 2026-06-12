const { parse: csvParse } = require('csv-parse/sync');

/**
 * Section-aware CSV/tabular parsing.
 *
 * Many real-world scan exports (notably Qualys CSV/agent-scan reports) are
 * *multi-section* files: a title/summary block at the top, one or more blank
 * separator rows, then the real findings table with its own header row —
 * sometimes followed by further blank rows and additional blocks.
 *
 * A naive `columns: true` parse locks onto the FIRST non-empty row as the
 * header for the whole file, so:
 *   - The field-mapper dropdown shows title/metadata cells instead of real
 *     column names.
 *   - Every row after the first blank gap is misaligned or silently dropped.
 *
 * This module splits a file into sections on blank rows, scores each section's
 * header against known finding-column keywords, and selects the section that
 * best represents a findings table. Blank rows *within* the chosen section are
 * skipped gracefully so trailing data is never lost.
 */

function stripBOM(str) {
  return str && str.charCodeAt(0) === 0xfeff ? str.slice(1) : str;
}

// Header keywords that indicate a row is the header of a findings/results table.
const FINDING_HEADER_KEYWORDS = [
  // asset / host columns
  'ip', 'ipv4', 'ipv6', 'dns', 'host', 'hostname', 'asset', 'fqdn', 'netbios', 'target',
  // identifier columns
  'qid', 'cve', 'plugin', 'plugin id', 'plugin name', 'bugtraq', 'bid',
  // weakness columns
  'title', 'vuln', 'vulnerability', 'weakness', 'finding', 'name', 'threat',
  // risk columns
  'severity', 'risk', 'cvss', 'criticality', 'rating', 'level',
  // network / status columns
  'port', 'protocol', 'status', 'category', 'type',
  // dates / detail
  'first found', 'last found', 'first detected', 'detection', 'detected',
  'description', 'solution', 'results', 'diagnosis', 'synopsis',
];

/**
 * True when every cell in a row is null/empty/whitespace.
 */
function isBlankRow(row) {
  return !row || row.every((cell) => cell == null || String(cell).trim() === '');
}

/**
 * Produce a list of unique, non-empty header names. Empty cells become
 * Column_N, and duplicates are suffixed (_2, _3, ...) so they can be used as
 * object keys without collisions (Qualys reports frequently repeat blank
 * header cells).
 */
function makeUniqueHeaders(rawHeaders) {
  const seen = new Map();
  return rawHeaders.map((h, idx) => {
    let name = h == null ? '' : String(h).trim();
    if (name === '') name = `Column_${idx + 1}`;
    if (seen.has(name)) {
      const count = seen.get(name) + 1;
      seen.set(name, count);
      return `${name}_${count}`;
    }
    seen.set(name, 1);
    return name;
  });
}

/**
 * Score a header row by how many finding-related keywords it contains.
 * Higher = more likely to be the real findings table header.
 */
function scoreHeader(headers) {
  const lower = headers.map((h) => h.toLowerCase().trim());
  let score = 0;
  for (const kw of FINDING_HEADER_KEYWORDS) {
    if (lower.some((h) => h === kw || h.includes(kw))) score += 1;
  }
  return score;
}

/**
 * A normalized key for a row, used to detect repeated header rows (some
 * exports repeat the header block per host/page).
 */
function rowKey(row) {
  return row.map((c) => (c == null ? '' : String(c).trim().toLowerCase())).join('');
}

/**
 * Count the number of blank-separated, non-blank runs ("blocks") in the file.
 * Used only for the informational multi-section warning.
 */
function countBlocks(rawRows) {
  let blocks = 0;
  let inBlock = false;
  for (const row of rawRows) {
    if (isBlankRow(row)) {
      inBlock = false;
    } else if (!inBlock) {
      blocks += 1;
      inBlock = true;
    }
  }
  return blocks;
}

/**
 * Given an array-of-arrays (raw rows, blank rows included), locate the findings
 * header row and return everything after it as data — treating blank rows and
 * repeated header rows as noise rather than hard section boundaries.
 *
 * This is the key to correct blank-row handling: a blank row *within* a
 * findings table must NOT cause subsequent rows to be dropped. Only the
 * leading title/summary block (before the findings header) is excluded.
 *
 * @param {Array<Array<*>>} rawRows
 * @returns {{ headers: string[], rows: object[], totalRows: number,
 *             sections: object[], sectionWarning: object|null }}
 */
function selectBestSection(rawRows) {
  // 1. Choose the header row: the non-blank row with the highest finding-keyword
  //    score. Ties resolve to the earliest row. Falls back to the first
  //    non-blank row when nothing scores (ordinary single-table CSV).
  let headerIdx = -1;
  let headerScore = -1;
  let firstNonBlankIdx = -1;
  for (let i = 0; i < rawRows.length; i++) {
    if (isBlankRow(rawRows[i])) continue;
    if (firstNonBlankIdx === -1) firstNonBlankIdx = i;
    const score = scoreHeader(makeUniqueHeaders(rawRows[i]));
    if (score > headerScore) {
      headerScore = score;
      headerIdx = i;
    }
  }

  if (headerIdx === -1) {
    return { headers: [], rows: [], totalRows: 0, sections: [], sectionWarning: null };
  }

  // If no row carried any finding keywords, treat the file as an ordinary table
  // whose header is the first non-blank row.
  if (headerScore <= 0) headerIdx = firstNonBlankIdx;

  const headers = makeUniqueHeaders(rawRows[headerIdx]);
  const headerKey = rowKey(rawRows[headerIdx]);

  // 2. Everything after the header row that is non-blank is data. Blank rows are
  //    skipped (not treated as terminators); rows identical to the header are
  //    repeated header blocks and are skipped too.
  const rows = [];
  let innerBlankRows = 0;
  let repeatedHeaders = 0;
  for (let i = headerIdx + 1; i < rawRows.length; i++) {
    const raw = rawRows[i];
    if (isBlankRow(raw)) {
      innerBlankRows += 1;
      continue;
    }
    if (rowKey(raw) === headerKey) {
      repeatedHeaders += 1;
      continue;
    }
    const obj = {};
    headers.forEach((h, idx) => {
      const v = raw[idx];
      obj[h] = v == null ? '' : String(v).trim();
    });
    rows.push(obj);
  }

  // 3. Build an informational warning when the file had a leading block before
  //    the findings header, inner blank rows, or repeated headers — so the
  //    assessor can confirm the right data was captured.
  const blocks = countBlocks(rawRows);
  const leadingRowsSkipped = rawRows
    .slice(0, headerIdx)
    .filter((r) => !isBlankRow(r)).length;

  const sections = [
    {
      startLine: headerIdx + 1, // 1-based
      columns: headers.length,
      rows: rows.length,
      score: Math.max(headerScore, 0),
      selected: true,
      headerPreview: headers.slice(0, 8),
    },
  ];

  let sectionWarning = null;
  if (blocks > 1 || innerBlankRows > 0 || leadingRowsSkipped > 0 || repeatedHeaders > 0) {
    const parts = [];
    parts.push(
      `Using the findings table starting at line ${headerIdx + 1} ` +
        `(${rows.length} rows, ${headers.length} columns).`
    );
    if (leadingRowsSkipped > 0) {
      parts.push(`Skipped ${leadingRowsSkipped} title/summary row(s) above it.`);
    }
    if (innerBlankRows > 0) {
      parts.push(`Bridged ${innerBlankRows} blank row(s) inside the table (no data lost).`);
    }
    if (repeatedHeaders > 0) {
      parts.push(`Skipped ${repeatedHeaders} repeated header row(s).`);
    }
    sectionWarning = { message: parts.join(' '), sections };
  }

  return {
    headers,
    rows,
    totalRows: rows.length,
    sections,
    sectionWarning,
  };
}

/**
 * Parse a CSV string with section awareness.
 * @param {string} content
 * @returns {{ headers, rows, totalRows, sections, sectionWarning }}
 */
function parseCSVSections(content) {
  const rawRows = csvParse(stripBOM(content), {
    columns: false,
    skip_empty_lines: false, // keep blanks so section breaks are detectable
    relax_column_count: true,
    relax_quotes: true,
  });
  return selectBestSection(rawRows);
}

module.exports = {
  parseCSVSections,
  selectBestSection,
  isBlankRow,
  makeUniqueHeaders,
  scoreHeader,
};
