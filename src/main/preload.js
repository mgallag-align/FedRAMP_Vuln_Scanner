const { contextBridge, ipcRenderer } = require('electron');

// Expose a safe API to the renderer process via contextBridge
contextBridge.exposeInMainWorld('electronAPI', {
  // File reading
  readFile: (filePath) => ipcRenderer.invoke('file:read', filePath),
  readBinaryFile: (filePath) => ipcRenderer.invoke('file:read-binary', filePath),

  // File dialogs
  openFileDialog: (options) => ipcRenderer.invoke('dialog:open-file', options),
  saveFileDialog: (options) => ipcRenderer.invoke('dialog:save-file', options),

  // Parsing operations (run in main process / worker)
  parseScanFile: (filePath, fileName) => ipcRenderer.invoke('parse:scan-file', filePath, fileName),
  parseScanFileWithMapping: (filePath, fileName, mapping) => ipcRenderer.invoke('parse:scan-file-with-mapping', filePath, fileName, mapping),
  parseIIW: (filePath) => ipcRenderer.invoke('parse:iiw', filePath),

  // Engine operations
  matchAssets: (cfos, iiwAssets) => ipcRenderer.invoke('engine:match-assets', cfos, iiwAssets),
  generateIds: (cfos, prefixConfig) => ipcRenderer.invoke('engine:generate-ids', cfos, prefixConfig),
  validateExport: (sessionData) => ipcRenderer.invoke('engine:validate', sessionData),

  // Export
  exportRET: (sessionData, outputPath) => ipcRenderer.invoke('export:ret', sessionData, outputPath),

  // Diagnostics
  getParseLogPath: () => ipcRenderer.invoke('log:get-parse-log-path'),

  // Universal Mapper
  mapperParseFile: (filePath, fileName) => ipcRenderer.invoke('mapper:parse-file', filePath, fileName),
  mapperApplyMapping: (rows, mapping, defaults) => ipcRenderer.invoke('mapper:apply-mapping', rows, mapping, defaults),
  mapperExportCSV: (mappedRows, outputPath) => ipcRenderer.invoke('mapper:export-csv', mappedRows, outputPath),
  mapperExportJSON: (mappedRows, outputPath) => ipcRenderer.invoke('mapper:export-json', mappedRows, outputPath),

  // Progress events
  onProgress: (callback) => {
    const subscription = (event, data) => callback(data);
    ipcRenderer.on('progress', subscription);
    return () => ipcRenderer.removeListener('progress', subscription);
  },
});
