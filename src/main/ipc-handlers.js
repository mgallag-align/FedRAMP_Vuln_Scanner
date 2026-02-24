const { ipcMain, dialog, BrowserWindow } = require('electron');
const fs = require('fs');
const path = require('path');
const { detectAndParse } = require('../parsers/index');
const { parseIIW } = require('../parsers/iiw');
const { matchAssets } = require('../engine/matcher');
const { generateIds } = require('../engine/id-generator');
const { validateExport } = require('../engine/validator');
const { exportRET } = require('../export/ret-writer');

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
      sendProgress(`Parsed ${fileName}: ${result.findings.length} findings`, 100);
      return result;
    } catch (err) {
      return { error: err.message, findings: [], scannerType: null };
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
}

module.exports = { registerIpcHandlers };
