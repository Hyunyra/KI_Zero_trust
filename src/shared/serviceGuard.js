// Middleware pengaman untuk Service Nilai & Service Transkrip (4.1: gateway secret + verifikasi ulang token).
// Urutan: (1) X-Gateway-Secret  ->  (2) access token / token service  ->  (3) role (per route).
const crypto = require('crypto');
const cfg = require('./config');
const { verifyToken } = require('./verify');

const sha = (s) => crypto.createHash('sha256').update(String(s)).digest();
// timingSafeEqual pada hash agar panjang input tidak bocor dan perbandingan konstan-waktu
const safeEqual = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));

function guard(serviceName) {
  return (req, res, next) => {
    // 1) Service tidak boleh diakses langsung: wajib membawa secret dari gateway
    const secret = req.get('X-Gateway-Secret') || '';
    if (!safeEqual(secret, cfg.gatewaySecret)) {
      console.log(`[${serviceName}] TOLAK ${req.method} ${req.originalUrl} - gateway secret tidak valid`);
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Akses langsung ke service ditolak: X-Gateway-Secret tidak valid',
      });
    }

    // 2) Walaupun secret benar, token tetap diverifikasi ulang (tanda tangan + exp)
    const m = /^Bearer\s+(.+)$/i.exec(req.get('Authorization') || '');
    if (!m) {
      return res.status(401).json({ error: 'Unauthorized', message: 'Token tidak ada (diverifikasi ulang di service)' });
    }
    try {
      req.auth = verifyToken(m[1]); // { sub, role, ... }
    } catch (err) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: `Token tidak valid di service: ${err.message}`,
      });
    }
    next();
  };
}

// 3) Pembatasan role di tingkat service (defense in depth, selain keputusan Policy Engine)
const requireRole = (...roles) => (req, res, next) => {
  if (roles.includes(req.auth.role)) return next();
  return res.status(403).json({
    error: 'Forbidden',
    message: `Role '${req.auth.role}' tidak diizinkan di endpoint ini (service)`,
  });
};

module.exports = { guard, requireRole };
