// API Gateway = Policy Enforcement Point (PEP). Satu-satunya pintu masuk (port 3000).
// Alur setiap request: validasi path -> verifikasi token -> verifikasi sesi & device
//                      -> keputusan Policy Engine -> audit log -> teruskan + X-Gateway-Secret.
const nodePath = require('path');
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const cfg = require('../shared/config');
const { open } = require('../shared/db');
const { verifyToken } = require('../shared/verify');
const audit = require('./audit');
const policy = require('./policy');
const authRoutes = require('./authRoutes');

const db = open();
const q = {
  user: db.prepare('SELECT id, username, role FROM users WHERE id = ?'),
  session: db.prepare('SELECT revoked, expires_at FROM refresh_tokens WHERE id = ? AND user_id = ?'),
  device: db.prepare('SELECT 1 FROM devices WHERE user_id = ? AND device_id = ?'),
};

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', false);

// --- Frontend uji (file statis, bukan resource). Semua panggilan API-nya tetap lewat PEP di bawah ---
app.use(express.static(nodePath.join(__dirname, '../../public'), { index: 'index.html', dotfiles: 'ignore' }));

// --- /auth/* ditangani gateway sendiri (body JSON hanya di-parse di sini) ---
app.use('/auth', express.json({ limit: '10kb' }), authRoutes);

// --- PEP: semua request lain wajib lolos pemeriksaan di bawah ini ---
function enforce(req, res, next) {
  const path = req.path;
  const device = req.get('X-Device-ID') || null;
  let subjectId = null;
  let subjectType = null;

  const log = (result, reason) =>
    audit.log({ subject: subjectId, subjectType, method: req.method, endpoint: path, device, result, reason, ip: req.ip });
  const reject = (status, reason) => {
    log('deny', reason);
    return res.status(status).json({ error: status === 401 ? 'Unauthorized' : 'Forbidden', message: reason });
  };

  // 0) Allowlist karakter path: menutup trik path (../, //, %2e, dll.) agar yang
  //    diperiksa policy sama persis dengan yang diteruskan ke service.
  if (!/^\/[A-Za-z0-9_\-/]*$/.test(path) || path.includes('//')) return reject(403, 'path tidak valid');

  // 1) Access token wajib ada, tanda tangan & masa berlakunya valid
  const m = /^Bearer\s+(.+)$/i.exec(req.get('Authorization') || '');
  if (!m) return reject(401, 'access token tidak ada');
  let payload;
  try {
    payload = verifyToken(m[1]);
  } catch (err) {
    return reject(401, `access token tidak valid: ${err.message}`);
  }
  subjectId = payload.sub;

  let subject;
  if (payload.role === 'service') {
    // Token service: subjek = service; tidak memerlukan device
    subjectType = 'service';
    subject = { type: 'service', id: payload.sub, role: 'service' };
  } else {
    subjectType = 'user';
    // 2) User harus ada & role di token harus sama dengan role di database (never trust the token)
    const user = q.user.get(Number(payload.sub));
    if (!user) return reject(401, 'user pada token tidak ditemukan');
    subjectId = user.username;
    if (user.role !== payload.role) return reject(401, 'role pada token tidak sesuai dengan data user');

    // 3) Sesi harus masih aktif: logout (refresh token dicabut) langsung mematikan access token
    const s = q.session.get(payload.sid, user.id);
    if (!s || s.revoked || s.expires_at < Date.now()) return reject(401, 'sesi tidak aktif (sudah logout/dicabut)');

    // 4) Device terdaftar untuk user tersebut (4.3)
    if (!device) return reject(403, 'header X-Device-ID tidak ada');
    if (!q.device.get(user.id, device)) return reject(403, `device ${device} tidak terdaftar untuk user ${user.username}`);

    subject = { type: 'user', id: user.id, role: user.role };
  }

  // 5) Keputusan Policy Engine
  const decision = policy.decide({ subject, method: req.method, path, query: req.query });
  if (!decision.allow) return reject(403, decision.reason);

  log('allow', decision.reason);
  next();
}
app.use(enforce);

// Alat demo (admin saja, sudah lolos PEP di atas). Matikan dengan DEMO_MODE=0.
if (process.env.DEMO_MODE !== '0') app.use('/demo', express.json({ limit: '10kb' }), require('./demo'));

// --- Meneruskan request yang sudah diizinkan, dengan X-Gateway-Secret ---
const forward = (target, pathFilter) =>
  createProxyMiddleware({
    target,
    pathFilter,
    on: {
      proxyReq: (proxyReq) => {
        // setHeader menimpa header yang mungkin dikirim klien -> klien tidak bisa memalsukan secret
        proxyReq.setHeader('X-Gateway-Secret', cfg.gatewaySecret);
      },
      error: (err, req, res) => {
        console.error('[gateway] upstream error:', err.message);
        if (res && typeof res.writeHead === 'function' && !res.headersSent) {
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Bad Gateway', message: 'Service tujuan tidak dapat dihubungi' }));
        }
      },
    },
  });

app.use(forward(cfg.nilaiUrl, ['/nilai', '/kelas']));
app.use(forward(cfg.transkripUrl, '/transkrip'));

app.use((req, res) => res.status(404).json({ error: 'Not Found' }));

app.listen(cfg.ports.gateway, cfg.host, () => {
  console.log(`[gateway] PEP berjalan di http://${cfg.host}:${cfg.ports.gateway}`);
});
