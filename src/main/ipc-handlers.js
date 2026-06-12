const { ipcMain, dialog, BrowserWindow } = require('electron');
const fs = require('fs');
const path = require('path');
const { detectAndParse } = require('../parsers/index');
const { mapRowsToFindings } = require('../parsers/generic-csv');
const { parseIIW } = require('../parsers/iiw');
const { parseUniversalFile, applyMapping } = require('../parsers/universal-parser');
const { matchAssets } = require('../engine/matcher');
const { generateIds } = require('../engine/id-generator');
const { validateExport } = require('../engine/validator');
const { exportRET } = require('../export/ret-writer');
const { logParseError, getLogPath } = require('./error-log');

function sendProgress(message, percent) {
  const windows = BrowserWindow.getAllWindows();
  if (windows.length > 0) {
    windows[0].webContents.send('progress', { message, percent });
  }
}

function registerIpcHandlers() {
  // Read a text file
  ipcMain.handle('file:read', async (event, filePath) => {
    return fs.readFileSync(filePath, 'utf-8');
  });

  // Read a binary file and return as Buffer
  ipcMain.handle('file:read-binary', async (event, filePath) => {
    return fs.readFileSync(filePath);
  });

  // Open file dialog
  ipcMain.handle('dialog:open-file', async (event, options) => {
    const result = await dialog.showOpenDialog({
      properties: ['openFile', ...(options.multiple ? ['multiSelections'] : [])],
      filters: options.filters || [],
    });
    if (result.canceled) return null;
    return result.filePaths;
  });

  // Save file dialog
  ipcMain.handle('dialog:save-file', async (event, options) => {
    const result = await dialog.showSaveDialog({
      defaultPath: options.defaultPath || 'RET_Export.xlsx',
      filters: [{ name: 'Excel Workbook', extensions: ['xlsx'] }],
    });
    if (result.canceled) return null;
    return result.filePath;
  });

  // Parse a scan file — runs detection + parsing
  ipcMain.handle('parse:scan-file', async (event, filePath, fileName) => {
    try {
      sendProgress(`Parsing ${fileName}...`, 0);
      const content = fs.readFileSync(filePath);
      const result = await detectAndParse(content, fileName, (pct) => {
        sendProgress(`Parsing ${fileName}...`, pct);
      });
      // Log structured failures returned by the parsers (non-throwing path).
      if (result && result.error && !result.needsMapping) {
        const logPath = logParseError({
          fileName,
          stage: 'detectAndParse',
          error: result.errorDetail || result.error,
        });
        result.logPath = logPath;
      }
      sendProgress(`Parsed ${fileName}: ${(result.findings || []).length} findings`, 100);
      return result;
    } catch (err) {
      const ext = (fileName || '').toLowerCase().split('.').pop();
      const logPath = logParseError({ fileName, stage: 'parse:scan-file', error: err });
      return {
        error: `Could not parse ${fileName} — the file may be corrupt or truncated.`,
        errorDetail: err && err.stack ? err.stack : String(err && err.message || err),
        recoverable: ['csv', 'xls', 'xlsx', 'json'].includes(ext),
        logPath,
        findings: [],
        scannerType: null,
      };
    }
  });

  // Parse IIW
  ipcMain.handle('parse:iiw', async (event, filePath) => {
    try {
      sendProgress('Parsing IIW...', 0);
      const result = await parseIIW(filePath, (pct) => {
        sendProgress('Parsing IIW...', pct);
      });
      sendProgress(`IIW parsed: ${result.assets.length} assets`, 100);
      return result;
    } catch (err) {
      return { error: err.message, assets: [] };
    }
  });

  // Match assets against IIW
  ipcMain.handle('engine:match-assets', async (event, cfos, iiwAssets) => {
    return matchAssets(cfos, iiwAssets);
  });

  // Generate RET IDs
  ipcMain.handle('engine:generate-ids', async (event, cfos, prefixConfig) => {
    return generateIds(cfos, prefixConfig);
  });

  // Validate before export
  ipcMain.handle('engine:validate', async (event, sessionData) => {
    return validateExport(sessionData);
  });

  // Export RET XLSX
  ipcMain.handle('export:ret', async (event, sessionData, outputPath) => {
    try {
      sendProgress('Exporting RET workbook...', 0);
      await exportRET(sessionData, outputPath, (pct) => {
        sendProgress('Exporting RET workbook...', pct);
      });
      sendProgress('Export complete.', 100);
      return { success: true, path: outputPath };
    } catch (err) {
      return { success: false, error: err.message };
    }
  });

  // Parse a scan file with a user-provided field mapping (for unknown tabular
  // formats — CSV, XLSX/XLS, or JSON). Rows are extracted by the universal
  // parser, then mapped to CFOs, so a single path serves every tabular source.
  ipcMain.handle('parse:scan-file-with-mapping', async (event, filePath, fileName, mapping) => {
    try {
      sendProgress(`Parsing ${fileName} with mapping...`, 0);
      const content = fs.readFileSync(filePath);
      const { rows } = await parseUniversalFile(content, fileName);
      const findings = mapRowsToFindings(rows, fileName, mapping, (pct) => {
        sendProgress(`Parsing ${fileName}...`, pct);
      });
      sendProgress(`Parsed ${fileName}: ${findings.length} findings`, 100);
      return { scannerType: 'Mapped Import', findings, authWarning: false };
    } catch (err) {
      const logPath = logParseError({ fileName, stage: 'parse:scan-file-with-mapping', error: err });
      return {
        error: `Could not apply mapping to ${fileName} — ${err.message}`,
        errorDetail: err && err.stack ? err.stack : String(err && err.message || err),
        logPath,
        findings: [],
        scannerType: null,
      };
    }
  });

  // ── Universal Mapper: Parse file and extract headers + rows ──
  ipcMain.handle('mapper:parse-file', async (event, filePath, fileName) => {
    try {
      sendProgress(`Reading ${fileName}...`, 0);
      const content = fs.readFileSync(filePath);
      sendProgress(`Parsing ${fileName}...`, 30);
      const result = await parseUniversalFile(content, fileName);
      sendProgress(`Parsed ${fileName}: ${result.totalRows} rows`, 100);
      return result;
    } catch (err) {
      const logPath = logParseError({ fileName, stage: 'mapper:parse-file', error: err });
      return { error: err.message, errorDetail: err && err.stack, logPath, headers: [], rows: [], totalRows: 0 };
    }
  });

  // ── Return the path to the local parse-error log (for bug reports) ──
  ipcMain.handle('log:get-parse-log-path', async () => {
    try {
      return { path: getLogPath() };
    } catch (err) {
      return { path: null, error: err.message };
    }
  });

  // ── Universal Mapper: Apply mapping and transform data ──
  ipcMain.handle('mapper:apply-mapping', async (event, rows, mapping, defaults) => {
    try {
      return { rows: applyMapping(rows, mapping, defaults) };
    } catch (err) {
      return { error: err.message, rows: [] };
    }
  });

  // ── Universal Mapper: Export mapped data as CSV ──
  ipcMain.handle('mapper:export-csv', async (event, mappedRows, outputPath) => {
    try {
      if (!mappedRows || mappedRows.length === 0) {
        return { success: false, error: 'No data to export' };
      }
      const headers = Object.keys(mappedRows[0]);
      const csvLines = [
        headers.map((h) => `"${h}"`).join(','),
        ...mappedRows.map((row) =>
          headers.map((h) => `"${String(row[h] || '').replace(/"/g, '""')}"`).join(',')
        ),
      ];
      fs.writeFileSync(outputPath, csvLines.join('\n'), 'utf-8');
      return { success: true, path: outputPath };
    } catch (err) {
      return { success: false, error: err.message };
    }
  });

  // ── Universal Mapper: Export mapped data as JSON ──
  ipcMain.handle('mapper:export-json', async (event, mappedRows, outputPath) => {
    try {
      fs.writeFileSync(outputPath, JSON.stringify(mappedRows, null, 2), 'utf-8');
      return { success: true, path: outputPath };
    } catch (err) {
      return { success: false, error: err.message };
    }
  });
}

module.exports = { registerIpcHandlers };
