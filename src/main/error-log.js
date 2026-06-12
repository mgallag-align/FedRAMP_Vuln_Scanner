const fs = require('fs');
const path = require('path');
const { app } = require('electron');

/**
 * Local, air-gap-safe parse error log.
 *
 * Parser failures are appended to a plain-text log under the app's userData
 * directory so an assessor can attach it to a bug report without the tool ever
 * touching the network. Nothing here makes outbound calls.
 */

let cachedLogFile = null;

function resolveLogFile() {
  if (cachedLogFile) return cachedLogFile;
  let logDir;
  try {
    // app may be unavailable in non-Electron contexts (tests) — fall back to cwd.
    const base = app && typeof app.getPath === 'function' ? app.getPath('userData') : process.cwd();
    logDir = path.join(base, 'logs');
    fs.mkdirSync(logDir, { recursive: true });
    cachedLogFile = path.join(logDir, 'parse-errors.log');
  } catch {
    cachedLogFile = path.join(process.cwd(), 'parse-errors.log');
  }
  return cachedLogFile;
}

/**
 * Append a parse failure to the log.
 * @param {{ fileName?: string, stage?: string, error?: Error|string }} info
 * @returns {string|null} the log file path, or null if logging failed.
 */
function logParseError({ fileName = 'unknown', stage = 'parse', error } = {}) {
  try {
    const file = resolveLogFile();
    const ts = new Date().toISOString();
    const detail = error && error.stack ? error.stack : String((error && error.message) || error || 'Unknown error');
    const entry = `[${ts}] file="${fileName}" stage="${stage}"\n${detail}\n\n`;
    fs.appendFileSync(file, entry, 'utf-8');
    return file;
  } catch {
    return null;
  }
}

/**
 * Return the absolute path to the parse error log (creating the directory if
 * needed). Used by the renderer to tell the user where to find the log.
 */
function getLogPath() {
  return resolveLogFile();
}

module.exports = { logParseError, getLogPath };
