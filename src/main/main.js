const { app, BrowserWindow, session } = require('electron');
const path = require('path');
const { registerIpcHandlers } = require('./ipc-handlers');

// Disable hardware acceleration for compatibility
app.disableHardwareAcceleration();

// Security: Disable navigation to external URLs
app.on('web-contents-created', (event, contents) => {
  contents.on('will-navigate', (navEvent) => {
    navEvent.preventDefault();
  });
  contents.setWindowOpenHandler(() => ({ action: 'deny' }));
});

let mainWindow = null;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 860,
    minWidth: 1024,
    minHeight: 700,
    title: 'FedRAMP RET Tool',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
      enableRemoteModule: false,
    },
  });

  // Security: Block all outbound network requests
  session.defaultSession.webRequest.onBeforeRequest((details, callback) => {
    const url = new URL(details.url);
    if (url.protocol === 'file:' || url.hostname === 'localhost' || url.hostname === '127.0.0.1') {
      callback({ cancel: false });
    } else {
      callback({ cancel: true });
    }
  });

  // Disable auto-updater
  if (typeof mainWindow.webContents.session.setPermissionRequestHandler === 'function') {
    mainWindow.webContents.session.setPermissionRequestHandler((webContents, permission, callback) => {
      callback(false);
    });
  }

  // Load renderer
  const isDev = !app.isPackaged;
  if (isDev) {
    mainWindow.loadURL('http://localhost:9000');
  } else {
    mainWindow.loadFile(path.join(__dirname, '..', '..', 'dist', 'index.html'));
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(() => {
  registerIpcHandlers();
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
