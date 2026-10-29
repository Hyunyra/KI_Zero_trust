// ALAT DEMO (opsional, hanya admin). Nonaktifkan dengan environment DEMO_MODE=0.
// Semua endpoint ini tetap melewati PEP (token + device + policy + audit log) dan hanya boleh dipakai admin.
const express = require('express');
const cfg = require('../shared/config');
const { open } = require('../shared/db');
const hours = require('./accessHours');

const db = open();
const router = express.Router();

// Audit log untuk ditampilkan di frontend
router.get('/audit', (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 40, 200);
  const filter = ['allow', 'deny'].includes(req.query.result) ? req.query.result : null;
  const rows = db.prepare(
    `SELECT id, ts, subject, subject_type, method, endpoint, device, result, reason FROM audit_log
     ${filter ? 'WHERE result = ?' : ''} ORDER BY id DESC LIMIT ?`
  ).all(...(filter ? [filter, limit] : [limit]));
  res.json({ data: rows });
});

// Jam akses (baca / ubah)
router.get('/jam-akses', (req, res) => {
  const { ok, config } = hours.isWithinAccessHours();
  res.json({ config, dalam_jam_akses: ok });
});
router.put('/jam-akses', (req, res) => {
  const { start, end } = req.body || {};
  const valid = (s) => typeof s === 'string' && /^([01]\d|2[0-3]):[0-5]\d$/.test(s);
  if (!valid(start) || !valid(end)) return res.status(400).json({ error: 'Bad Request', message: 'format jam harus HH:MM' });
  hours.save({ start, end });
  const { ok, config } = hours.isWithinAccessHours();
  res.json({ message: `Jam akses diubah: ${start}-${end}`, config, dalam_jam_akses: ok });
});

// Membuka kembali finalisasi agar demo bisa diulang (tanpa reset total)
router.post('/buka-finalisasi', (req, res) => {
  const id = Number((req.body || {}).kelas_id) || null;
  const w = id ? 'WHERE kelas_id = ?' : '';
  const a = id ? [id] : [];
  const out = db.transaction(() => ({
    nilai: db.prepare(`UPDATE nilai SET final = 0 ${w}`).run(...a).changes,
    transkrip: db.prepare(`DELETE FROM transkrip ${w}`).run(...a).changes,
  }))();
  res.json({ message: `Finalisasi dibuka kembali (${id ? 'kelas ' + id : 'semua kelas'})`, ...out });
});

// Simulasi penyerang yang mengakses Service Nilai langsung (browser tidak bisa melakukannya karena CORS,
// sehingga gateway yang mencobanya dari sisi server).
router.post('/serangan-langsung', async (req, res) => {
  const palsu = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.palsu';
  const tries = [
    ['Langsung ke :3001 tanpa gateway secret', {}, 403],
    ['Secret benar tetapi tanpa token', { 'X-Gateway-Secret': cfg.gatewaySecret }, 401],
    ['Secret benar + token palsu', { 'X-Gateway-Secret': cfg.gatewaySecret, Authorization: `Bearer ${palsu}` }, 401],
  ];
  const hasil = [];
  for (const [label, headers, expect] of tries) {
    try {
      const r = await fetch(`${cfg.nilaiUrl}/nilai`, { headers, signal: AbortSignal.timeout(3000) });
      const j = await r.json().catch(() => ({}));
      hasil.push({ label, expect, status: r.status, message: j.message || j.error || '' });
    } catch (e) {
      hasil.push({ label, expect, status: 0, message: e.message });
    }
  }
  res.json({ hasil });
});

module.exports = router;
