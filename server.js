'use strict';

/**
 * ╔══════════════════════════════════════════════════════════════════╗
 * ║         ADMIN PANEL – HouseCityRolePlay VPS                     ║
 * ║         Secure • Real-Time • Production-Ready • Port 9999       ║
 * ╚══════════════════════════════════════════════════════════════════╝
 */

const express     = require('express');
const session     = require('express-session');
const helmet      = require('helmet');
const rateLimit   = require('express-rate-limit');
const cors        = require('cors');
const { WebSocketServer, WebSocket } = require('ws');
const http        = require('http');
const path        = require('path');
const fs          = require('fs');
const fsp         = fs.promises;
const { spawn }   = require('child_process');
const pm2         = require('pm2');
const os          = require('os');
const crypto      = require('crypto');
const bcrypt      = require('bcryptjs');
const winston     = require('winston');

// ─────────────────────────────────────────────────────────────────────────────
// CONFIGURATION — edit via environment variables or directly here
// ─────────────────────────────────────────────────────────────────────────────
const CFG = {
  PORT          : parseInt(process.env.PORT)         || 9999,

  // Comma-separated list of allowed IPs. Use '*' to allow all (NOT recommended).
  ALLOWED_IPS   : (process.env.ALLOWED_IPS || '127.0.0.1').split(',').map(s => s.trim()),

  // Session secret – generate once with: node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
  SESSION_SECRET: process.env.SESSION_SECRET         || crypto.randomBytes(64).toString('hex'),

  // bcrypt hash stored in env (recommended) — fallback to plain text for first boot
  PASSWORD_HASH : process.env.PASSWORD_HASH          || '',
  PANEL_PASSWORD: process.env.PANEL_PASSWORD         || 'Admin@Panel2024!',

  // Directory allowed for file editing
  EDIT_DIR      : path.resolve(process.env.EDIT_DIR  || '/home/ubuntu/HouseCityRolePlay-main'),

  LOG_DIR       : path.join(__dirname, 'logs'),
  BACKUP_DIR    : path.join(__dirname, 'logs', 'backups'),
  PUBLIC_DIR    : path.join(__dirname, 'public'),
  MAX_LOG_LINES : 500,

  // Automatic restart threshold (MB)
  MEM_LIMIT_MB  : parseInt(process.env.MEM_LIMIT_MB) || 1500,

  SESSION_TTL_MS: 30 * 60 * 1000,   // 30 min inactivity timeout
  WS_TICK_MS    : 2000,              // WebSocket broadcast interval
  BOT_NAME      : process.env.BOT_NAME || 'HouseCityBot',

  BLOCKED_EXTS  : new Set(['.env', '.key', '.pem', '.crt', '.p12', '.pfx', '.ppk', '.secret', '.passwd']),
  BLOCKED_DIRS  : ['/etc', '/root', '/proc', '/sys', '/boot', '/dev', '/var/run'],
};

// ─────────────────────────────────────────────────────────────────────────────
// LOGGER (Winston — 3 separate log files)
// ─────────────────────────────────────────────────────────────────────────────
[CFG.LOG_DIR, CFG.BACKUP_DIR].forEach(d => fs.mkdirSync(d, { recursive: true }));

const logFmt = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.printf(({ timestamp, level, message }) =>
    `[${timestamp}] [${level.toUpperCase().padEnd(7)}] ${message}`)
);

const mkLogger = (file) => winston.createLogger({
  format    : logFmt,
  transports: [
    new winston.transports.File({ filename: path.join(CFG.LOG_DIR, file), maxsize: 5_000_000, maxFiles: 3 }),
    ...(file === 'error.log' ? [new winston.transports.Console({ format: logFmt })] : []),
  ],
});

const log = {
  access : mkLogger('acesso.log'),
  error  : mkLogger('error.log'),
  action : mkLogger('actions.log'),
};

// ─────────────────────────────────────────────────────────────────────────────
// EXPRESS + HTTP SERVER
// ─────────────────────────────────────────────────────────────────────────────
const app    = express();
const server = http.createServer(app);

// ── Helmet (security headers) ────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc : ["'self'"],
      scriptSrc  : ["'self'", "'unsafe-inline'", 'cdn.jsdelivr.net', 'cdnjs.cloudflare.com'],
      styleSrc   : ["'self'", "'unsafe-inline'", 'cdn.jsdelivr.net', 'fonts.googleapis.com', 'cdnjs.cloudflare.com'],
      fontSrc    : ["'self'", 'fonts.gstatic.com', 'cdnjs.cloudflare.com'],
      imgSrc     : ["'self'", 'data:'],
      connectSrc : ["'self'", 'ws:', 'wss:'],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

// ── CORS — block cross-origin requests ──────────────────────────────────────
app.use(cors({ origin: false, credentials: true }));

// ── Body parsers ─────────────────────────────────────────────────────────────
app.use(express.json({ limit: '200kb' }));
app.use(express.urlencoded({ extended: false, limit: '100kb' }));

// ── Session ──────────────────────────────────────────────────────────────────
const sessionMW = session({
  secret           : CFG.SESSION_SECRET,
  resave           : false,
  saveUninitialized: false,
  rolling          : true,          // reset TTL on each request
  cookie: {
    secure  : false,                // set true when behind HTTPS/nginx
    httpOnly: true,
    sameSite: 'strict',
    maxAge  : CFG.SESSION_TTL_MS,
  },
});
app.use(sessionMW);

// ─────────────────────────────────────────────────────────────────────────────
// MIDDLEWARE STACK
// ─────────────────────────────────────────────────────────────────────────────

// 1. IP Allowlist — first line of defence
app.use((req, res, next) => {
  const raw  = req.ip || req.socket?.remoteAddress || '';
  const ip   = raw.replace(/^::ffff:/, '');
  if (CFG.ALLOWED_IPS[0] !== '*' && !CFG.ALLOWED_IPS.includes(ip)) {
    log.access.warn(`BLOCKED  ${ip} → ${req.method} ${req.path}`);
    return res.status(403).json({ error: 'Forbidden' });
  }
  req._ip = ip;
  next();
});

// 2. Rate limiters
const globalLimiter = rateLimit({ windowMs: 15 * 60_000, max: 200, standardHeaders: true, legacyHeaders: false });
const loginLimiter  = rateLimit({ windowMs: 15 * 60_000, max: 10,  standardHeaders: true, legacyHeaders: false,
  handler: (req, res) => {
    log.action.warn(`Brute-force detected from ${req._ip}`);
    res.status(429).json({ error: 'Too many login attempts. Try again in 15 minutes.' });
  }
});
app.use('/api/', globalLimiter);

// 3. Access log
app.use((req, res, next) => {
  log.access.info(`${req._ip} ${req.method} ${req.path}`);
  next();
});

// 4. Auth guard for all /api/ routes (except /api/login and /api/check)
const requireAuth = (req, res, next) => {
  if (!req.session?.authenticated) return res.status(401).json({ error: 'Unauthorized' });
  next();
};

// ── Static files (served before auth guard — login page is public) ───────────
app.use(express.static(CFG.PUBLIC_DIR, { index: 'index.html', dotfiles: 'deny' }));

// ─────────────────────────────────────────────────────────────────────────────
// AUTH ROUTES
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/login', loginLimiter, async (req, res) => {
  const { password } = req.body;
  if (typeof password !== 'string' || !password.length)
    return res.status(400).json({ error: 'Password required' });

  let valid = false;
  try {
    if (CFG.PASSWORD_HASH) {
      valid = await bcrypt.compare(password, CFG.PASSWORD_HASH);
    } else {
      // Timing-safe plain text comparison (dev/first-boot only)
      const a = Buffer.from(password.padEnd(72));
      const b = Buffer.from(CFG.PANEL_PASSWORD.padEnd(72));
      valid = crypto.timingSafeEqual(a, b) && password === CFG.PANEL_PASSWORD;
    }
  } catch (e) {
    log.error.error('Login error: ' + e.message);
    return res.status(500).json({ error: 'Internal error' });
  }

  if (!valid) {
    log.action.warn(`Failed login from ${req._ip}`);
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: 'Session error' });
    req.session.authenticated = true;
    req.session.loginAt = Date.now();
    log.action.info(`Login SUCCESS from ${req._ip}`);
    res.json({ ok: true });
  });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/check', (req, res) => {
  res.json({ authenticated: !!req.session?.authenticated });
});

// ─────────────────────────────────────────────────────────────────────────────
// SYSTEM METRICS HELPERS
// ─────────────────────────────────────────────────────────────────────────────

/** Read CPU usage via /proc/stat (accurate 1-second delta) */
let _prevCpu = null;
function getCpuPercent() {
  const stats = fs.readFileSync('/proc/stat', 'utf8').split('\n')[0].split(/\s+/).slice(1).map(Number);
  const [user, nice, sys, idle, iowait, irq, softirq, steal] = stats;
  const total  = stats.reduce((a, b) => a + b, 0);
  const active = total - idle - iowait;

  let pct = 0;
  if (_prevCpu) {
    const dTotal  = total  - _prevCpu.total;
    const dActive = active - _prevCpu.active;
    pct = dTotal > 0 ? Math.round((dActive / dTotal) * 100) : 0;
  }
  _prevCpu = { total, active };
  return Math.max(0, Math.min(100, pct));
}

/** Get disk usage via df */
function getDisk(mount = '/') {
  return new Promise((resolve) => {
    const p = spawn('df', ['-B1', '--output=size,used,avail', mount], { timeout: 4000 });
    let out = '';
    p.stdout.on('data', d => out += d);
    p.on('close', () => {
      const lines = out.trim().split('\n');
      if (lines.length < 2) return resolve({ total: 0, used: 0, free: 0, pct: 0 });
      const [total, used, avail] = lines[1].trim().split(/\s+/).map(Number);
      resolve({ total, used, free: avail, pct: Math.round((used / total) * 100) });
    });
    p.on('error', () => resolve({ total: 0, used: 0, free: 0, pct: 0 }));
  });
}

/** Event-loop delay measurement */
function measureELD() {
  return new Promise(resolve => {
    const start = process.hrtime.bigint();
    setImmediate(() => {
      const ns  = Number(process.hrtime.bigint() - start);
      resolve(Math.round(ns / 1_000_000)); // ms
    });
  });
}

async function collectMetrics() {
  const [disk, eldMs] = await Promise.all([getDisk('/'), measureELD()]);
  const mem   = process.memoryUsage();
  const total = os.totalmem();
  const free  = os.freemem();

  return {
    ts      : Date.now(),
    cpu     : getCpuPercent(),
    load    : os.loadavg(),
    mem     : { total, used: total - free, free, pct: Math.round(((total - free) / total) * 100) },
    disk,
    uptime  : os.uptime(),
    process : { heap: mem.heapUsed, heapTotal: mem.heapTotal, rss: mem.rss, eld: eldMs },
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// PM2 HELPERS
// ─────────────────────────────────────────────────────────────────────────────
const pm2Wrap = (fn) => new Promise((resolve, reject) => {
  pm2.connect(true, err => {
    if (err) return reject(err);
    fn(resolve, reject);
  });
});

function pm2List() {
  return pm2Wrap((res, rej) =>
    pm2.list((err, list) => {
      pm2.disconnect();
      if (err) return rej(err);
      res(list.map(p => ({
        id        : p.pm_id,
        name      : p.name,
        status    : p.pm2_env?.status,
        cpu       : p.monit?.cpu   ?? 0,
        mem       : p.monit?.memory ?? 0,
        uptime    : p.pm2_env?.pm_uptime,
        restarts  : p.pm2_env?.restart_time ?? 0,
        pid       : p.pid,
        mode      : p.pm2_env?.exec_mode,
        instances : p.pm2_env?.instances,
        memLimit  : CFG.MEM_LIMIT_MB,
      })));
    })
  );
}

const SAFE_PM2_ACTIONS = new Set(['restart', 'stop', 'reload', 'delete']);
function pm2Do(action, id) {
  if (!SAFE_PM2_ACTIONS.has(action)) return Promise.reject(new Error('Invalid PM2 action'));
  return pm2Wrap((res, rej) =>
    pm2[action](id, (err, result) => {
      pm2.disconnect();
      err ? rej(err) : res(result);
    })
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// PM2 ROUTES
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/pm2/list', requireAuth, async (req, res) => {
  try { res.json(await pm2List()); }
  catch (e) { log.error.error('PM2 list: ' + e.message); res.status(500).json({ error: e.message }); }
});

app.post('/api/pm2/:action/:id', requireAuth, async (req, res) => {
  const { action } = req.params;
  const id = parseInt(req.params.id);
  if (!SAFE_PM2_ACTIONS.has(action) || isNaN(id) || id < 0)
    return res.status(400).json({ error: 'Invalid action or id' });

  try {
    await pm2Do(action, id);
    log.action.info(`PM2 ${action.toUpperCase()} id=${id} by ${req._ip}`);
    res.json({ ok: true });
  } catch (e) {
    log.error.error(`PM2 ${action} error: ${e.message}`);
    res.status(500).json({ error: e.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// METRICS REST (backup for non-WS clients)
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/metrics', requireAuth, async (req, res) => {
  try {
    const [sys, procs] = await Promise.all([collectMetrics(), pm2List()]);
    res.json({ sys, pm2: procs });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────────────────────────────────────────
// SECURE FILE EDITOR — path validation
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Validates and resolves a user-supplied relative path against EDIT_DIR.
 * Throws on any traversal, symlink escape, or blocked extension.
 */
async function safePath(input) {
  if (typeof input !== 'string') throw new Error('Invalid path type');

  // Strip null bytes and dangerous sequences
  const sanitized = input.replace(/\0/g, '').replace(/\.\.\//g, '').trim();
  if (!sanitized) throw new Error('Empty path');

  const abs = path.resolve(CFG.EDIT_DIR, sanitized);

  // Must remain inside EDIT_DIR
  if (!abs.startsWith(CFG.EDIT_DIR + path.sep) && abs !== CFG.EDIT_DIR)
    throw new Error('Path escape attempt detected');

  // Blocked root directories
  for (const bd of CFG.BLOCKED_DIRS)
    if (abs.startsWith(bd + '/') || abs === bd)
      throw new Error('Blocked system directory');

  // Blocked extensions
  const ext  = path.extname(abs).toLowerCase();
  const base = path.basename(abs);
  if (CFG.BLOCKED_EXTS.has(ext) || base.startsWith('.env'))
    throw new Error(`Blocked file type: ${ext || base}`);

  // Verify realpath (detect symlink attacks — only when file exists)
  try {
    const real = await fsp.realpath(abs);
    if (!real.startsWith(CFG.EDIT_DIR))
      throw new Error('Symlink escape detected');
    return real;
  } catch (e) {
    if (e.code === 'ENOENT') return abs; // new file, OK
    throw e;
  }
}

/** Recursively build file tree (max depth) */
async function buildTree(dir, depth = 0, maxDepth = 4) {
  if (depth > maxDepth) return [];
  let entries;
  try { entries = await fsp.readdir(dir, { withFileTypes: true }); }
  catch (_) { return []; }

  const items = [];
  for (const e of entries) {
    if (e.name.startsWith('.')) continue; // skip hidden
    const full = path.join(dir, e.name);
    const rel  = path.relative(CFG.EDIT_DIR, full);

    if (e.isDirectory()) {
      const children = await buildTree(full, depth + 1, maxDepth);
      items.push({ name: e.name, path: rel, type: 'dir', children });
    } else {
      const ext = path.extname(e.name).toLowerCase();
      if (!CFG.BLOCKED_EXTS.has(ext))
        items.push({ name: e.name, path: rel, type: 'file' });
    }
  }
  // directories first, then files
  return items.sort((a, b) => (a.type === b.type ? a.name.localeCompare(b.name) : a.type === 'dir' ? -1 : 1));
}

app.get('/api/files/tree', requireAuth, async (req, res) => {
  try { res.json(await buildTree(CFG.EDIT_DIR)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/files/read', requireAuth, async (req, res) => {
  const { file } = req.query;
  if (!file) return res.status(400).json({ error: 'Missing ?file=' });

  try {
    const resolved = await safePath(file);
    const stat     = await fsp.stat(resolved);
    if (stat.size > 512 * 1024)
      return res.status(413).json({ error: 'File too large (max 512 KB)' });

    const content = await fsp.readFile(resolved, 'utf8');
    res.json({ content, path: file });
  } catch (e) {
    log.error.error('File read: ' + e.message);
    res.status(400).json({ error: e.message });
  }
});

app.post('/api/files/save', requireAuth, async (req, res) => {
  const { file, content } = req.body;
  if (!file || content === undefined) return res.status(400).json({ error: 'Missing file or content' });
  if (typeof content !== 'string')    return res.status(400).json({ error: 'Content must be string' });
  if (content.length > 512 * 1024)   return res.status(413).json({ error: 'Content too large (max 512 KB)' });

  try {
    const resolved   = await safePath(file);
    const backupName = `${path.basename(resolved)}.${Date.now()}.bak`;

    // Backup existing file before overwrite
    try { await fsp.copyFile(resolved, path.join(CFG.BACKUP_DIR, backupName)); }
    catch (_) { /* file may not exist yet */ }

    await fsp.writeFile(resolved, content, 'utf8');
    log.action.info(`File SAVED: ${file} by ${req._ip}`);
    res.json({ ok: true, backup: backupName });
  } catch (e) {
    log.error.error('File save: ' + e.message);
    res.status(400).json({ error: e.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GIT PULL → PM2 RESTART (SSE stream)
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/git/pull', requireAuth, (req, res) => {
  const safeDir = path.resolve(CFG.EDIT_DIR);
  if (!safeDir.startsWith('/home/ubuntu/') && !safeDir.startsWith('/var/www/'))
    return res.status(400).json({ error: 'Invalid EDIT_DIR configuration' });

  log.action.info(`Git pull initiated by ${req._ip}`);

  // Use Server-Sent Events so terminal output streams live
  res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('X-Accel-Buffering', 'no');

  const send  = (line) => res.write(`data: ${line.replace(/\n/g, ' ')}\n\n`);
  const done  = () => { send('[DONE]'); res.end(); };

  send('[PANEL] ▶ Running: git pull');

  // spawn instead of exec — safer, no shell injection
  const pull = spawn('git', ['pull'], {
    cwd    : safeDir,
    env    : { HOME: '/root', PATH: process.env.PATH, GIT_TERMINAL_PROMPT: '0' },
    timeout: 60_000,
  });

  pull.stdout.on('data', d => send(d.toString()));
  pull.stderr.on('data', d => send(`[STDERR] ${d.toString()}`));

  pull.on('error', e => { send(`[ERROR] ${e.message}`); done(); });

  pull.on('close', code => {
    send(`[PANEL] git pull exited (code ${code})`);

    if (code !== 0) { send('[ERROR] Pull failed — skipping restart'); return done(); }

    send(`[PANEL] ▶ Restarting ${CFG.BOT_NAME} via PM2...`);
    const restart = spawn('pm2', ['restart', CFG.BOT_NAME], { timeout: 20_000 });
    restart.stdout.on('data', d => send(d.toString()));
    restart.stderr.on('data', d => send(`[PM2] ${d.toString()}`));
    restart.on('close', c => {
      send(`[PANEL] pm2 restart exited (code ${c})`);
      log.action.info(`Git pull + pm2 restart completed. codes: git=${code} pm2=${c}`);
      done();
    });
    restart.on('error', e => { send(`[PM2 ERROR] ${e.message}`); done(); });
  });

  req.on('close', () => { pull.kill(); });
});

// ─────────────────────────────────────────────────────────────────────────────
// LOG ROUTES
// ─────────────────────────────────────────────────────────────────────────────
const LOG_MAP = new Map([
  ['acesso',  path.join(CFG.LOG_DIR, 'acesso.log')],
  ['error',   path.join(CFG.LOG_DIR, 'error.log')],
  ['actions', path.join(CFG.LOG_DIR, 'actions.log')],
]);

app.get('/api/logs/:type', requireAuth, async (req, res) => {
  const logPath = LOG_MAP.get(req.params.type);
  if (!logPath) return res.status(400).json({ error: 'Invalid log type' });

  try {
    const raw   = await fsp.readFile(logPath, 'utf8').catch(() => '');
    const lines = raw.split('\n').filter(Boolean).slice(-CFG.MAX_LOG_LINES);
    res.json({ lines });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────────────────────────────────────────
// WEBSOCKET — real-time metrics + PM2 log streaming
// ─────────────────────────────────────────────────────────────────────────────
const wss = new WebSocketServer({ noServer: true });

// Authenticate WS upgrades through session middleware
server.on('upgrade', (req, socket, head) => {
  sessionMW(req, {}, () => {
    if (!req.session?.authenticated) {
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, ws => wss.emit('connection', ws, req));
  });
});

/** Broadcast JSON to all authenticated WS clients */
function broadcast(obj) {
  const msg = JSON.stringify(obj);
  wss.clients.forEach(c => { if (c.readyState === WebSocket.OPEN) c.send(msg); });
}

/** Metrics broadcast loop */
let _metricsTick = null;
async function tickMetrics() {
  if (wss.clients.size === 0) return;
  try {
    const [sys, procs] = await Promise.all([collectMetrics(), pm2List()]);
    broadcast({ type: 'metrics', sys, pm2: procs });
  } catch (e) { log.error.error('WS metrics: ' + e.message); }
}

wss.on('connection', (ws, req) => {
  log.access.info(`WS connected`);

  ws.on('message', raw => {
    let msg;
    try { msg = JSON.parse(raw); } catch (_) { return; }

    switch (msg.type) {
      case 'ping':
        ws.send(JSON.stringify({ type: 'pong', ts: Date.now() }));
        break;

      case 'subscribe_logs':
        if (typeof msg.name === 'string') streamPm2Logs(ws, msg.name);
        break;
    }
  });

  ws.on('close',   () => log.access.info('WS disconnected'));
  ws.on('error', e => log.error.error('WS error: ' + e.message));
});

/** Tail PM2 log file and stream to a single WS client */
function streamPm2Logs(ws, name) {
  // Strict name whitelist: only alphanumeric, dashes, underscores
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(name)) return;

  const logFile = path.join('/root/.pm2/logs', `${name}-out.log`);
  if (!logFile.startsWith('/root/.pm2/logs/')) return;

  const tail = spawn('tail', ['-n', '100', '-f', logFile], { timeout: 0 });

  tail.stdout.on('data', d => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: 'pm2_log', name, line: d.toString() }));
    } else {
      tail.kill();
    }
  });

  ws.on('close', () => tail.kill());
}

// Start metrics broadcast
_metricsTick = setInterval(tickMetrics, CFG.WS_TICK_MS);

// ─────────────────────────────────────────────────────────────────────────────
// RESOURCE MONITOR — auto-kill if memory exceeds threshold
// ─────────────────────────────────────────────────────────────────────────────
setInterval(async () => {
  try {
    const procs = await pm2List();
    for (const p of procs) {
      const mb = Math.round(p.mem / 1024 / 1024);
      if (p.status === 'online' && mb > CFG.MEM_LIMIT_MB) {
        log.action.warn(`MEMORY LIMIT: ${p.name} is using ${mb}MB > ${CFG.MEM_LIMIT_MB}MB — restarting`);
        await pm2Do('restart', p.id).catch(() => {});
        broadcast({
          type   : 'alert',
          level  : 'warning',
          message: `⚠️ ${p.name} exceeded ${CFG.MEM_LIMIT_MB}MB (was ${mb}MB) — auto-restarted`,
        });
      }
    }
  } catch (_) { /* non-critical */ }
}, 30_000);

// ─────────────────────────────────────────────────────────────────────────────
// ROUTES — serve pages
// ─────────────────────────────────────────────────────────────────────────────
app.get('/dashboard', requireAuth, (req, res) =>
  res.sendFile(path.join(CFG.PUBLIC_DIR, 'dashboard.html'))
);
app.get('/', (req, res) =>
  res.sendFile(path.join(CFG.PUBLIC_DIR, 'index.html'))
);

// 404 handler
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// Global error handler
app.use((err, req, res, _next) => {
  log.error.error(`Unhandled: ${err.message} — ${req.method} ${req.path}`);
  res.status(500).json({ error: 'Internal server error' });
});

// ─────────────────────────────────────────────────────────────────────────────
// START
// ─────────────────────────────────────────────────────────────────────────────
server.listen(CFG.PORT, '0.0.0.0', () => {
  const line = '═'.repeat(46);
  console.log(`\n╔${line}╗`);
  console.log(`║  🔒 Admin Panel listening on port ${CFG.PORT}          ║`);
  console.log(`╚${line}╝`);
  console.log(`  Allowed IPs  : ${CFG.ALLOWED_IPS.join(', ')}`);
  console.log(`  Memory limit : ${CFG.MEM_LIMIT_MB} MB`);
  console.log(`  Session TTL  : ${CFG.SESSION_TTL_MS / 60_000} min`);
  console.log(`  Edit dir     : ${CFG.EDIT_DIR}`);
  console.log(`  Log dir      : ${CFG.LOG_DIR}\n`);
});

// Graceful shutdown
const shutdown = () => {
  console.log('\nShutting down gracefully...');
  clearInterval(_metricsTick);
  server.close(() => { pm2.disconnect(); process.exit(0); });
  setTimeout(() => process.exit(1), 8000);
};
process.on('SIGTERM', shutdown);
process.on('SIGINT',  shutdown);
process.on('uncaughtException',  e => log.error.error('Uncaught: ' + e.stack));
process.on('unhandledRejection', r => log.error.error('Rejection: ' + r));
