/**
 * TrustCore Sentinel X — Electron Main Process
 *
 * 1. Spawns the Python backend (python -m sentinel)
 * 2. Waits for it to be ready
 * 3. Opens a BrowserWindow + system tray
 */
const { app, BrowserWindow, Tray, Menu, nativeImage, shell } = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const http = require('http');

const BACKEND_URL = 'http://127.0.0.1:8321';
const BACKEND_READY_POLL_MS = 500;
const BACKEND_READY_TIMEOUT_MS = 30000;

let mainWindow = null;
let tray = null;
let backendProc = null;

// ── Start Python backend ───────────────────────────────────────────────────
function startBackend() {
  // Prefer bundled executable (PyInstaller), fall back to python -m sentinel
  const exe = path.join(process.resourcesPath || __dirname, '..', 'sentinel_backend.exe');
  const useExe = require('fs').existsSync(exe);

  console.log(useExe ? `[backend] launching ${exe}` : '[backend] launching python -m sentinel');

  backendProc = spawn(
    useExe ? exe : 'python',
    useExe ? [] : ['-m', 'sentinel'],
    {
      cwd: useExe ? path.dirname(exe) : path.join(__dirname, '..'),
      windowsHide: true,   // no console window on Windows
      stdio: 'ignore',
    }
  );

  backendProc.on('error', err => console.error('[backend] error:', err));
  backendProc.on('exit', code => console.log('[backend] exited with code', code));
}

// ── Poll until backend ready ───────────────────────────────────────────────
function waitForBackend(resolve, reject, deadline) {
  http.get(`${BACKEND_URL}/status`, res => {
    if (res.statusCode === 200) resolve();
    else retry(resolve, reject, deadline);
  }).on('error', () => retry(resolve, reject, deadline));
}

function retry(resolve, reject, deadline) {
  if (Date.now() > deadline) { reject(new Error('Backend timed out')); return; }
  setTimeout(() => waitForBackend(resolve, reject, deadline), BACKEND_READY_POLL_MS);
}

function backendReady() {
  return new Promise((resolve, reject) =>
    waitForBackend(resolve, reject, Date.now() + BACKEND_READY_TIMEOUT_MS)
  );
}

// ── Create window ──────────────────────────────────────────────────────────
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 860,
    minWidth: 900,
    minHeight: 600,
    title: 'TrustCore Sentinel X',
    backgroundColor: '#07080f',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
    },
    // Use a simple shield icon; swap with png asset if available
    // icon: path.join(__dirname, 'icons', 'icon.png'),
  });

  mainWindow.loadURL(BACKEND_URL);

  // Open external links in browser, not Electron
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: 'deny' };
  });

  mainWindow.on('close', e => {
    // Hide to tray instead of quitting
    if (process.platform !== 'darwin') {
      e.preventDefault();
      mainWindow.hide();
    }
  });
}

// ── System tray ────────────────────────────────────────────────────────────
function createTray() {
  // Minimal inline 16x16 blue shield icon (works without asset files)
  const iconData = nativeImage.createFromDataURL(
    'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAABmJLR0QA/wD/AP+gvaeTAAAAY0lEQVQ4y2NgGPSAkYGBIYuBgWEfFQ2YxMDAsI+KBmADkxi' +
    'oaAA2gIkBqzWoYMB5BgaGjVQ0YMI/BgaGjVQ2YNg/BgaGDVQ2YNgpBgaG9VQ0YMJ8BgaGelQ2YNg/BgYGANIlEBkEr5inAAAAAElFTkSuQmCC'
  );

  tray = new Tray(iconData);
  const contextMenu = Menu.buildFromTemplate([
    { label: '🛡️ TrustCore Sentinel X', enabled: false },
    { type: 'separator' },
    { label: 'Show Dashboard', click: () => { mainWindow.show(); mainWindow.focus(); } },
    { label: 'Open in Browser', click: () => shell.openExternal(BACKEND_URL) },
    { type: 'separator' },
    { label: 'Quit', click: () => { app.exit(0); } },
  ]);

  tray.setToolTip('TrustCore Sentinel X — AI Cyber Defense');
  tray.setContextMenu(contextMenu);
  tray.on('double-click', () => { mainWindow.show(); mainWindow.focus(); });
}

// ── App lifecycle ──────────────────────────────────────────────────────────
app.whenReady().then(async () => {
  startBackend();

  // Show a loading state while backend boots
  mainWindow = new BrowserWindow({
    width: 1400, height: 860,
    backgroundColor: '#07080f',
    title: 'TrustCore Sentinel X — Starting…',
    webPreferences: { nodeIntegration: false, contextIsolation: true },
  });
  mainWindow.loadURL(`data:text/html,<style>body{background:#07080f;color:#00f5ff;font-family:monospace;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;font-size:18px}</style><body>🛡️ Starting TrustCore Sentinel X…</body>`);

  try {
    await backendReady();
    console.log('[app] Backend ready');
    mainWindow.loadURL(BACKEND_URL);
  } catch (err) {
    console.error('[app] Backend failed:', err);
    mainWindow.loadURL(`data:text/html,<style>body{background:#07080f;color:#ff2d55;font-family:monospace;padding:40px;}</style><body><h2>❌ Backend failed to start</h2><p>${err.message}</p><p>Make sure Python and the sentinel package are installed:<br><code>pip install -r requirements.txt</code><br><code>python -m sentinel</code></p></body>`);
  }

  createTray();
});

app.on('window-all-closed', () => {
  // Keep running in tray on Windows/Linux
  if (process.platform === 'darwin') app.quit();
});

app.on('activate', () => {
  if (mainWindow) mainWindow.show();
});

app.on('before-quit', () => {
  if (backendProc) {
    backendProc.kill();
    backendProc = null;
  }
});
