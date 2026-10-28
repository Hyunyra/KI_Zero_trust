// Service Nilai (port 3001) - resource: data nilai & kelas.
// Tidak bisa diakses langsung: wajib X-Gateway-Secret + token valid (diverifikasi ulang di sini).
const express = require('express');
const cfg = require('../shared/config');
const { open } = require('../shared/db');
const { guard, requireRole } = require('../shared/serviceGuard');

const db = open();
const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '100kb' }));
app.use(guard('nilai'));

const q = {
  user: db.prepare('SELECT id, nim FROM users WHERE id = ?'),
  nilai: db.prepare(
    `SELECT n.id, n.kelas_id, n.mahasiswa_nim, n.nilai, n.final, k.dosen_id
     FROM nilai n JOIN kelas k ON k.id = n.kelas_id WHERE n.id = ?`
  ),
  kelas: db.prepare('SELECT id, nama, dosen_id FROM kelas WHERE id = ?'),
};

// ---------- GET /nilai ----------
app.get('/nilai', requireRole('mahasiswa', 'dosen'), (req, res) => {
  const me = Number(req.auth.sub);
  const where = [];
  const args = [];

  if (req.auth.role === 'mahasiswa') {
    const u = q.user.get(me);
    // cakupan data ditentukan dari identitas di token, bukan dari parameter klien
    if (req.query.nim !== undefined && String(req.query.nim) !== u.nim)
      return res.status(403).json({ error: 'Forbidden', message: 'Hanya boleh melihat nilai milik sendiri' });
    where.push('n.mahasiswa_nim = ?'); args.push(u.nim);
  } else {
    where.push('k.dosen_id = ?'); args.push(me);
    if (req.query.kelas_id !== undefined) {
      const k = q.kelas.get(Number(req.query.kelas_id));
      if (!k || k.dosen_id !== me)
        return res.status(403).json({ error: 'Forbidden', message: 'Kelas bukan kelas yang diampu' });
      where.push('n.kelas_id = ?'); args.push(k.id);
    }
    if (req.query.nim !== undefined) { where.push('n.mahasiswa_nim = ?'); args.push(String(req.query.nim)); }
  }

  const rows = db.prepare(
    `SELECT n.id, n.kelas_id, k.nama AS kelas, n.mahasiswa_nim AS nim, u.nama AS mahasiswa, n.nilai, n.final
     FROM nilai n JOIN kelas k ON k.id = n.kelas_id LEFT JOIN users u ON u.nim = n.mahasiswa_nim
     WHERE ${where.join(' AND ')} ORDER BY n.kelas_id, n.mahasiswa_nim`
  ).all(...args);
  // Mahasiswa hanya boleh melihat nilai yang SUDAH final; nilai draft disembunyikan di sumber data
  const isMhs = req.auth.role === 'mahasiswa';
  res.json({
    data: rows.map((r) => ({ ...r, nilai: isMhs && !r.final ? null : r.nilai, final: !!r.final })),
  });
});

// ---------- PUT /nilai/:id ----------
app.put('/nilai/:id', requireRole('dosen'), (req, res) => {
  const id = Number(req.params.id);
  const nilai = req.body && req.body.nilai;
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Bad Request', message: 'id tidak valid' });
  if (typeof nilai !== 'number' || !Number.isFinite(nilai) || nilai < 0 || nilai > 100)
    return res.status(400).json({ error: 'Bad Request', message: 'nilai harus angka 0-100' });

  const row = q.nilai.get(id);
  if (!row) return res.status(404).json({ error: 'Not Found', message: 'Nilai tidak ditemukan' });
  if (row.dosen_id !== Number(req.auth.sub))
    return res.status(403).json({ error: 'Forbidden', message: 'Nilai bukan milik kelas yang diampu' });
  if (row.final)
    return res.status(403).json({ error: 'Forbidden', message: 'Nilai sudah final' });

  db.prepare('UPDATE nilai SET nilai = ? WHERE id = ?').run(nilai, id);
  res.json({ message: 'Nilai diperbarui', data: { id, nilai } });
});

// ---------- Token service untuk memanggil Service Transkrip LEWAT GATEWAY ----------
let cached = { token: null, exp: 0 };
async function getServiceToken() {
  if (cached.token && Date.now() < cached.exp - 15000) return cached.token;
  const r = await fetch(`${cfg.gatewayUrl}/auth/service`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_id: cfg.serviceClient.id, client_secret: cfg.serviceClient.secret }),
    signal: AbortSignal.timeout(5000),
  });
  if (!r.ok) throw new Error(`gagal mendapat token service (HTTP ${r.status})`);
  const j = await r.json();
  cached = { token: j.access_token, exp: Date.now() + j.expires_in * 1000 };
  return cached.token;
}

async function sinkronTranskrip(payload) {
  const token = await getServiceToken();
  const r = await fetch(`${cfg.gatewayUrl}/transkrip/sinkron`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(5000),
  });
  if (!r.ok) throw new Error(`sinkron transkrip ditolak (HTTP ${r.status}): ${await r.text()}`);
}

// ---------- POST /kelas/:id/finalisasi ----------
app.post('/kelas/:id/finalisasi', requireRole('dosen'), async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Bad Request', message: 'id tidak valid' });
  const kelas = q.kelas.get(id);
  if (!kelas) return res.status(404).json({ error: 'Not Found', message: 'Kelas tidak ditemukan' });
  if (kelas.dosen_id !== Number(req.auth.sub))
    return res.status(403).json({ error: 'Forbidden', message: 'Kelas bukan kelas yang diampu' });

  const rows = db.prepare('SELECT mahasiswa_nim AS nim, nilai, final FROM nilai WHERE kelas_id = ?').all(id);
  if (rows.length === 0) return res.status(422).json({ error: 'Unprocessable', message: 'Kelas belum memiliki nilai' });
  if (rows.every((r) => r.final)) return res.status(409).json({ error: 'Conflict', message: 'Kelas sudah difinalisasi' });
  if (rows.some((r) => r.nilai === null)) return res.status(422).json({ error: 'Unprocessable', message: 'Masih ada nilai yang kosong' });

  db.prepare('UPDATE nilai SET final = 1 WHERE kelas_id = ?').run(id);
  try {
    await sinkronTranskrip({
      kelas_id: id,
      nama_kelas: kelas.nama,
      items: rows.map((r) => ({ nim: r.nim, nilai: r.nilai })),
    });
  } catch (err) {
    db.prepare('UPDATE nilai SET final = 0 WHERE kelas_id = ?').run(id); // batalkan agar konsisten
    console.error('[nilai] finalisasi dibatalkan:', err.message);
    return res.status(502).json({ error: 'Bad Gateway', message: `Finalisasi dibatalkan: ${err.message}` });
  }
  res.json({ message: 'Kelas difinalisasi dan nilai dikirim ke transkrip', kelas_id: id, jumlah_nilai: rows.length });
});

app.use((req, res) => res.status(404).json({ error: 'Not Found' }));

app.listen(cfg.ports.nilai, cfg.host, () => {
  console.log(`[nilai] Service Nilai berjalan di http://${cfg.host}:${cfg.ports.nilai}`);
});
