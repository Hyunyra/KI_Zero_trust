// Endpoint /auth/* ditangani langsung oleh gateway (peran PE/PA):
// login, refresh, logout, dan token service.
const express = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const cfg = require('../shared/config');
const { open } = require('../shared/db');
const audit = require('./audit');
const tokens = require('./tokens');

const db = open();
const router = express.Router();
const DUMMY_HASH = bcrypt.hashSync('dummy-password', 10); // mencegah user-enumeration lewat waktu respons
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

const q = {
  userByName: db.prepare('SELECT * FROM users WHERE username = ?'),
  userById: db.prepare('SELECT * FROM users WHERE id = ?'),
  device: db.prepare('SELECT 1 FROM devices WHERE user_id = ? AND device_id = ?'),
  insertRefresh: db.prepare(
    'INSERT INTO refresh_tokens (user_id, token_hash, device_id, expires_at, revoked, created_at) VALUES (?,?,?,?,0,?)'
  ),
  refreshByHash: db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?'),
  revoke: db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE id = ?'),
  client: db.prepare('SELECT * FROM service_clients WHERE client_id = ?'),
};

const STATUS_NAME = { 400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden' };

// Membuat helper deny/allow yang otomatis menulis audit log
function helpers(req, endpoint, subjectType) {
  const device = req.get('X-Device-ID') || null;
  const base = { method: req.method, endpoint, device, ip: req.ip, subjectType };
  return {
    deny(status, subject, reason, message) {
      audit.log({ ...base, subject, result: 'deny', reason });
      return req.res.status(status).json({ error: STATUS_NAME[status], message: message || reason });
    },
    allow(subject, reason) {
      audit.log({ ...base, subject, result: 'allow', reason });
    },
    device,
  };
}

// ---------- POST /auth/login : kredensial valid + device terdaftar ----------
router.post('/login', (req, res) => {
  const h = helpers(req, '/auth/login', 'user');
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string')
    return h.deny(400, String(username), 'input tidak lengkap', 'username dan password wajib diisi');
  if (!h.device)
    return h.deny(400, username, 'header X-Device-ID tidak ada', 'Header X-Device-ID wajib dikirim');

  const user = q.userByName.get(username);
  const passOk = bcrypt.compareSync(password, user ? user.password_hash : DUMMY_HASH);
  if (!user || !passOk)
    return h.deny(401, username, 'kredensial tidak valid', 'Username atau password salah');

  if (!q.device.get(user.id, h.device))
    return h.deny(403, username, `device ${h.device} tidak terdaftar untuk user`, 'Device tidak terdaftar untuk user ini');

  // Refresh token: acak, disimpan sebagai HASH di database (dapat dicabut), berlaku 1 hari
  const refreshToken = crypto.randomBytes(48).toString('base64url');
  const info = q.insertRefresh.run(
    user.id, sha256(refreshToken), h.device, Date.now() + cfg.jwt.refreshTtlMs, new Date().toISOString()
  );
  const accessToken = tokens.signUser(user, Number(info.lastInsertRowid));

  h.allow(username, 'login berhasil');
  res.json({
    token_type: 'Bearer',
    access_token: accessToken,
    expires_in: 600,
    refresh_token: refreshToken,
    refresh_expires_in: cfg.jwt.refreshTtlMs / 1000,
  });
});

// Validasi refresh token (dipakai refresh & logout)
function checkRefresh(req, h) {
  const { refresh_token: rt } = req.body || {};
  if (typeof rt !== 'string') return { fail: h.deny(400, null, 'refresh_token tidak ada', 'refresh_token wajib dikirim') };
  const row = q.refreshByHash.get(sha256(rt));
  if (!row) return { fail: h.deny(401, null, 'refresh token tidak dikenal', 'Refresh token tidak valid') };
  const user = q.userById.get(row.user_id);
  const who = user ? user.username : String(row.user_id);
  if (row.revoked) return { fail: h.deny(401, who, 'refresh token sudah dicabut', 'Refresh token sudah dicabut') };
  if (row.expires_at < Date.now()) return { fail: h.deny(401, who, 'refresh token kedaluwarsa', 'Refresh token kedaluwarsa') };
  // Jika device dikirim, harus sama dengan device saat login (token terikat ke device)
  if (h.device && h.device !== row.device_id)
    return { fail: h.deny(403, who, 'device tidak cocok dengan device pada refresh token', 'Device tidak cocok') };
  return { row, user, who };
}

// ---------- POST /auth/refresh : refresh token valid & belum dicabut ----------
router.post('/refresh', (req, res) => {
  const h = helpers(req, '/auth/refresh', 'user');
  const r = checkRefresh(req, h);
  if (r.fail) return;
  if (!r.user) return h.deny(401, r.who, 'user tidak ditemukan', 'Refresh token tidak valid');
  h.allow(r.who, 'access token baru diterbitkan');
  res.json({ token_type: 'Bearer', access_token: tokens.signUser(r.user, r.row.id), expires_in: 600 });
});

// ---------- POST /auth/logout : mencabut refresh token ----------
router.post('/logout', (req, res) => {
  const h = helpers(req, '/auth/logout', 'user');
  const r = checkRefresh(req, h);
  if (r.fail) return;
  q.revoke.run(r.row.id);
  h.allow(r.who, 'logout: refresh token dicabut');
  res.json({ message: 'Logout berhasil, refresh token dicabut' });
});

// ---------- POST /auth/service : token service (client ID + secret) ----------
router.post('/service', (req, res) => {
  const h = helpers(req, '/auth/service', 'service');
  const { client_id: id, client_secret: secret } = req.body || {};
  if (typeof id !== 'string' || typeof secret !== 'string')
    return h.deny(400, String(id), 'client_id/client_secret tidak ada', 'client_id dan client_secret wajib dikirim');
  const c = q.client.get(id);
  const ok = bcrypt.compareSync(secret, c ? c.secret_hash : DUMMY_HASH);
  if (!c || !ok) return h.deny(401, id, 'client id/secret tidak valid', 'Client ID atau secret salah');
  h.allow(id, 'token service diterbitkan');
  res.json({ token_type: 'Bearer', access_token: tokens.signService(id), expires_in: 300 });
});

module.exports = router;
