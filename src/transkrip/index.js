// Service Transkrip (port 3002) - resource: transkrip mahasiswa.
// Tidak bisa diakses langsung: wajib X-Gateway-Secret + token valid (diverifikasi ulang di sini).
const express = require('express');
const cfg = require('../shared/config');
const { open } = require('../shared/db');
const { guard, requireRole } = require('../shared/serviceGuard');

const db = open();
const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '100kb' }));
app.use(guard('transkrip'));

const huruf = (n) => (n >= 85 ? 'A' : n >= 70 ? 'B' : n >= 55 ? 'C' : n >= 40 ? 'D' : 'E');

// ---------- GET /transkrip/:nim ----------
app.get('/transkrip/:nim', requireRole('mahasiswa', 'admin'), (req, res) => {
  const nim = req.params.nim;
  if (req.auth.role === 'mahasiswa') {
    const me = db.prepare('SELECT nim FROM users WHERE id = ?').get(Number(req.auth.sub));
    if (!me || me.nim !== nim)
      return res.status(403).json({ error: 'Forbidden', message: 'Mahasiswa hanya boleh melihat transkrip NIM sendiri' });
  }
  const mhs = db.prepare("SELECT nama, nim FROM users WHERE nim = ? AND role = 'mahasiswa'").get(nim);
  if (!mhs) return res.status(404).json({ error: 'Not Found', message: 'Mahasiswa tidak ditemukan' });

  const mk = db.prepare(
    'SELECT kelas_id, nama_kelas AS mata_kuliah, nilai, huruf FROM transkrip WHERE nim = ? ORDER BY kelas_id'
  ).all(nim);
  const rata = mk.length ? mk.reduce((a, b) => a + b.nilai, 0) / mk.length : null;
  res.json({ nim: mhs.nim, nama: mhs.nama, mata_kuliah: mk, rata_rata: rata === null ? null : Number(rata.toFixed(2)) });
});

// ---------- POST /transkrip/sinkron : hanya token service ----------
app.post('/transkrip/sinkron', requireRole('service'), (req, res) => {
  const { kelas_id: kelasId, nama_kelas: nama, items } = req.body || {};
  if (!Number.isInteger(kelasId) || typeof nama !== 'string' || !Array.isArray(items) || items.length === 0)
    return res.status(400).json({ error: 'Bad Request', message: 'kelas_id, nama_kelas, dan items wajib diisi' });
  const valid = items.every(
    (i) => i && typeof i.nim === 'string' && typeof i.nilai === 'number' && i.nilai >= 0 && i.nilai <= 100
  );
  if (!valid) return res.status(400).json({ error: 'Bad Request', message: 'format items tidak valid' });

  const upsert = db.prepare(
    `INSERT INTO transkrip (nim, kelas_id, nama_kelas, nilai, huruf, updated_at) VALUES (?,?,?,?,?,?)
     ON CONFLICT (nim, kelas_id) DO UPDATE SET nama_kelas = excluded.nama_kelas, nilai = excluded.nilai,
       huruf = excluded.huruf, updated_at = excluded.updated_at`
  );
  const now = new Date().toISOString();
  db.transaction(() => items.forEach((i) => upsert.run(i.nim, kelasId, nama, i.nilai, huruf(i.nilai), now)))();
  res.json({ message: 'Transkrip disinkronkan', jumlah: items.length });
});

app.use((req, res) => res.status(404).json({ error: 'Not Found' }));

app.listen(cfg.ports.transkrip, cfg.host, () => {
  console.log(`[transkrip] Service Transkrip berjalan di http://${cfg.host}:${cfg.ports.transkrip}`);
});
