// Setup awal: membuat keypair RS256, skema database, dan data awal (seed).
//   npm run setup           -> buat jika belum ada
//   npm run reset           -> hapus database lalu seed ulang
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const cfg = require('../src/shared/config');

const reset = process.argv.includes('--reset');

// ---------- 1. Keypair JWT (RS256) ----------
if (!fs.existsSync(cfg.privateKeyPath) || !fs.existsSync(cfg.publicKeyPath)) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  fs.mkdirSync(path.dirname(cfg.privateKeyPath), { recursive: true });
  fs.mkdirSync(path.dirname(cfg.publicKeyPath), { recursive: true });
  fs.writeFileSync(cfg.privateKeyPath, privateKey, { mode: 0o600 });
  fs.writeFileSync(cfg.publicKeyPath, publicKey);
  console.log('[setup] keypair RS256 dibuat');
} else {
  console.log('[setup] keypair sudah ada, dilewati');
}

// ---------- 2. Database ----------
if (fs.existsSync(cfg.dbPath) && !reset) {
  console.log('[setup] database sudah ada, dilewati (gunakan `npm run reset` untuk seed ulang)');
  process.exit(0);
}
for (const suffix of ['', '-wal', '-shm']) {
  try { fs.unlinkSync(cfg.dbPath + suffix); } catch { /* tidak ada */ }
}
const { open } = require('../src/shared/db');
const db = open();

db.exec(`
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  nama TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('mahasiswa','dosen','admin')),
  nim TEXT UNIQUE
);
CREATE TABLE devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  device_id TEXT NOT NULL,
  UNIQUE (user_id, device_id)
);
CREATE TABLE kelas (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kode TEXT NOT NULL,
  nama TEXT NOT NULL,
  dosen_id INTEGER NOT NULL REFERENCES users(id)
);
CREATE TABLE nilai (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kelas_id INTEGER NOT NULL REFERENCES kelas(id),
  mahasiswa_nim TEXT NOT NULL,
  nilai REAL,
  final INTEGER NOT NULL DEFAULT 0,
  UNIQUE (kelas_id, mahasiswa_nim)
);
CREATE TABLE transkrip (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nim TEXT NOT NULL,
  kelas_id INTEGER NOT NULL,
  nama_kelas TEXT NOT NULL,
  nilai REAL NOT NULL,
  huruf TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (nim, kelas_id)
);
CREATE TABLE refresh_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  token_hash TEXT UNIQUE NOT NULL,
  device_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE TABLE service_clients (
  client_id TEXT PRIMARY KEY,
  secret_hash TEXT NOT NULL
);
CREATE TABLE audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  subject TEXT,
  subject_type TEXT,
  method TEXT,
  endpoint TEXT,
  device TEXT,
  result TEXT NOT NULL CHECK (result IN ('allow','deny')),
  reason TEXT,
  ip TEXT
);
`);

// ---------- 3. Seed ----------
const PASSWORD = 'password123';
const hash = bcrypt.hashSync(PASSWORD, 10);

const addUser = db.prepare('INSERT INTO users (username, password_hash, nama, role, nim) VALUES (?,?,?,?,?)');
const addDevice = db.prepare('INSERT INTO devices (user_id, device_id) VALUES (?,?)');

const users = [
  ['admin',  'Admin Prodi',          'admin',     null,      'DEV-ADMIN-01'],
  ['dosen1', 'Dr. Budi Santoso',     'dosen',     null,      'DEV-DOSEN1-01'],
  ['dosen2', 'Dr. Siti Aminah',      'dosen',     null,      'DEV-DOSEN2-01'],
  ['mhs1',   'Andi Pratama',         'mahasiswa', '2210001', 'DEV-MHS1-01'],
  ['mhs2',   'Rina Lestari',         'mahasiswa', '2210002', 'DEV-MHS2-01'],
  ['mhs3',   'Dewi Anggraini',       'mahasiswa', '2210003', 'DEV-MHS3-01'],
];
const ids = {};
for (const [username, nama, role, nim, device] of users) {
  const r = addUser.run(username, hash, nama, role, nim);
  ids[username] = Number(r.lastInsertRowid);
  addDevice.run(ids[username], device); // setiap user: 1 device terdaftar
}

const addKelas = db.prepare('INSERT INTO kelas (kode, nama, dosen_id) VALUES (?,?,?)');
const k1 = Number(addKelas.run('KP70065004', 'Keamanan Informasi', ids.dosen1).lastInsertRowid);
const k2 = Number(addKelas.run('KP70065002', 'Pemrograman Web', ids.dosen2).lastInsertRowid);

const addNilai = db.prepare('INSERT INTO nilai (kelas_id, mahasiswa_nim, nilai) VALUES (?,?,?)');
const awal = {
  [k1]: { '2210001': 85, '2210002': 78, '2210003': 90 },
  [k2]: { '2210001': 70, '2210002': 88, '2210003': 65 },
};
for (const [kelasId, rows] of Object.entries(awal)) {
  for (const [nim, n] of Object.entries(rows)) addNilai.run(Number(kelasId), nim, n);
}

db.prepare('INSERT INTO service_clients (client_id, secret_hash) VALUES (?,?)')
  .run(cfg.serviceClient.id, bcrypt.hashSync(cfg.serviceClient.secret, 10));

db.close();
console.log('[setup] database dan data awal siap di', cfg.dbPath);
