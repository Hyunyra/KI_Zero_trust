// Uji end-to-end seluruh kebutuhan Zero Trust. Jalankan setelah `npm run reset` dan `npm start`.
//   npm run reset && npm start     (terminal 1)
//   npm test                       (terminal 2)
const fs = require('fs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const cfg = require('../src/shared/config');
const { open } = require('../src/shared/db');

const GW = `http://127.0.0.1:${cfg.ports.gateway}`;
const NILAI = `http://127.0.0.1:${cfg.ports.nilai}`;
const TRANSKRIP = `http://127.0.0.1:${cfg.ports.transkrip}`;
const DEV = {
  admin: 'DEV-ADMIN-01', dosen1: 'DEV-DOSEN1-01', dosen2: 'DEV-DOSEN2-01',
  mhs1: 'DEV-MHS1-01', mhs2: 'DEV-MHS2-01', mhs3: 'DEV-MHS3-01',
};

let pass = 0, fail = 0;
function check(nama, kondisi, info = '') {
  if (kondisi) { pass++; console.log(`  \x1b[32m✔\x1b[0m ${nama}`); }
  else { fail++; console.log(`  \x1b[31m✘ ${nama}\x1b[0m ${info}`); }
}
const section = (t) => console.log(`\n\x1b[1m${t}\x1b[0m`);

async function call(method, url, { token, device, body, headers = {} } = {}) {
  const h = { ...headers };
  if (token) h.Authorization = `Bearer ${token}`;
  if (device) h['X-Device-ID'] = device;
  if (body !== undefined) h['Content-Type'] = 'application/json';
  const r = await fetch(url, { method, headers: h, body: body !== undefined ? JSON.stringify(body) : undefined });
  let json = null;
  try { json = await r.json(); } catch { /* bukan JSON */ }
  return { status: r.status, json };
}
const gw = (m, p, o) => call(m, GW + p, o);

async function login(user, password = 'password123', device = DEV[user]) {
  return gw('POST', '/auth/login', { body: { username: user, password }, device });
}

(async () => {
  const db = open();

  section('1. Autentikasi & token (4.1)');
  let r = await login('mhs1');
  check('login mahasiswa valid -> 200 + access & refresh token', r.status === 200 && r.json.access_token && r.json.refresh_token, JSON.stringify(r));
  const mhs1 = r.json;
  const claims = jwt.decode(mhs1.access_token);
  check('access token berisi sub & role, masa berlaku 10 menit', claims.sub && claims.role === 'mahasiswa' && claims.exp - claims.iat === 600);
  r = await login('mhs1', 'salah');
  check('password salah -> 401', r.status === 401);
  r = await login('mhs1', 'password123', DEV.dosen1);
  check('device milik user lain -> 403', r.status === 403, JSON.stringify(r));
  r = await gw('POST', '/auth/login', { body: { username: 'mhs1', password: 'password123' } });
  check('tanpa X-Device-ID -> 400', r.status === 400);

  const tok = {};
  for (const u of Object.keys(DEV)) tok[u] = (await login(u)).json.access_token;

  section('2. Verifikasi token di gateway');
  r = await gw('GET', '/nilai');
  check('tanpa token -> 401', r.status === 401);
  r = await gw('GET', '/nilai', { token: tok.mhs1 });
  check('token valid tanpa X-Device-ID -> 403', r.status === 403);
  r = await gw('GET', '/nilai', { token: tok.mhs1, device: DEV.mhs2 });
  check('device milik user lain -> 403', r.status === 403);
  const fake = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const forged = jwt.sign({ role: 'admin' }, fake.privateKey, { algorithm: 'RS256', subject: '1', issuer: cfg.jwt.issuer, expiresIn: '10m' });
  r = await gw('GET', '/transkrip/2210001', { token: forged, device: DEV.admin });
  check('token dengan tanda tangan palsu -> 401', r.status === 401);
  const expired = jwt.sign({ role: 'admin', sid: 1 }, fs.readFileSync(cfg.privateKeyPath), { algorithm: 'RS256', subject: '1', issuer: cfg.jwt.issuer, expiresIn: -10 });
  r = await gw('GET', '/transkrip/2210001', { token: expired, device: DEV.admin });
  check('token kedaluwarsa -> 401', r.status === 401);
  const none = Buffer.from('{"alg":"none","typ":"JWT"}').toString('base64url') + '.' + Buffer.from(JSON.stringify({ sub: '1', role: 'admin', iss: cfg.jwt.issuer })).toString('base64url') + '.';
  r = await gw('GET', '/transkrip/2210001', { token: none, device: DEV.admin });
  check('token alg=none -> 401', r.status === 401);

  section('3. Service tidak bisa diakses langsung (gateway secret + verifikasi ulang)');
  r = await call('GET', `${NILAI}/nilai`);
  check('Service Nilai langsung tanpa secret -> 403', r.status === 403);
  r = await call('GET', `${TRANSKRIP}/transkrip/2210001`, { headers: { 'X-Gateway-Secret': 'tebakan-salah' } });
  check('Service Transkrip dengan secret salah -> 403', r.status === 403);
  r = await call('GET', `${NILAI}/nilai`, { headers: { 'X-Gateway-Secret': cfg.gatewaySecret } });
  check('secret benar tapi tanpa token -> 401', r.status === 401);
  r = await call('GET', `${NILAI}/nilai`, { token: forged, headers: { 'X-Gateway-Secret': cfg.gatewaySecret } });
  check('secret benar tapi token palsu -> 401', r.status === 401);
  r = await call('GET', `${NILAI}/nilai`, { token: tok.mhs1, headers: { 'X-Gateway-Secret': cfg.gatewaySecret } });
  check('secret benar + token valid -> 200 (jalur yang sah)', r.status === 200);
  r = await gw('GET', '/nilai', { token: tok.mhs1, device: DEV.mhs1, headers: { 'X-Gateway-Secret': 'dipalsukan-klien' } });
  check('klien tidak bisa memalsukan secret lewat gateway -> tetap 200', r.status === 200);

  section('4. Kebijakan akses (Tabel 3)');
  r = await gw('GET', '/nilai', { token: tok.mhs1, device: DEV.mhs1 });
  check('mahasiswa hanya melihat nilai sendiri', r.status === 200 && r.json.data.length === 2 && r.json.data.every((x) => x.nim === '2210001'), JSON.stringify(r));
  r = await gw('GET', '/nilai?nim=2210002', { token: tok.mhs1, device: DEV.mhs1 });
  check('mahasiswa minta nilai NIM lain -> 403', r.status === 403);
  r = await gw('GET', '/nilai', { token: tok.dosen1, device: DEV.dosen1 });
  check('dosen1 hanya melihat kelas 1', r.status === 200 && r.json.data.length === 3 && r.json.data.every((x) => x.kelas_id === 1), JSON.stringify(r));
  r = await gw('GET', '/nilai?kelas_id=2', { token: tok.dosen1, device: DEV.dosen1 });
  check('dosen1 minta kelas dosen2 -> 403', r.status === 403);
  r = await gw('GET', '/nilai', { token: tok.admin, device: DEV.admin });
  check('admin tidak boleh melihat nilai -> 403', r.status === 403);

  r = await gw('PUT', '/nilai/1', { token: tok.mhs1, device: DEV.mhs1, body: { nilai: 100 } });
  check('mahasiswa mengubah nilai -> 403', r.status === 403);
  r = await gw('PUT', '/nilai/1', { token: tok.dosen2, device: DEV.dosen2, body: { nilai: 100 } });
  check('dosen2 mengubah nilai kelas dosen1 -> 403', r.status === 403);
  r = await gw('PUT', '/nilai/1', { token: tok.dosen1, device: DEV.dosen1, body: { nilai: 88 } });
  check('dosen1 mengubah nilai kelasnya -> 200', r.status === 200, JSON.stringify(r));
  r = await gw('PUT', '/nilai/1', { token: tok.dosen1, device: DEV.dosen1, body: { nilai: 150 } });
  check('nilai di luar 0-100 ditolak service -> 400', r.status === 400);

  section('5. Verifikasi konteks: jam akses (4.3)');
  const orig = fs.readFileSync(cfg.accessHoursFile, 'utf8');
  try {
    // jendela 1 menit yang sudah lewat: pasti di luar jam akses
    fs.writeFileSync(cfg.accessHoursFile, JSON.stringify({ start: '00:00', end: '00:00', timezone: 'Asia/Jakarta' }));
    r = await gw('PUT', '/nilai/2', { token: tok.dosen1, device: DEV.dosen1, body: { nilai: 80 } });
    check('ubah nilai di luar jam akses -> 403', r.status === 403 && /jam akses/.test(r.json.message), JSON.stringify(r));
    r = await gw('POST', '/kelas/1/finalisasi', { token: tok.dosen1, device: DEV.dosen1 });
    check('finalisasi di luar jam akses -> 403', r.status === 403 && /jam akses/.test(r.json.message));
    r = await gw('GET', '/nilai', { token: tok.dosen1, device: DEV.dosen1 });
    check('melihat nilai tetap boleh di luar jam akses -> 200', r.status === 200);
  } finally {
    fs.writeFileSync(cfg.accessHoursFile, orig);
  }
  fs.writeFileSync(cfg.accessHoursFile, JSON.stringify({ start: '00:00', end: '23:59', timezone: 'Asia/Jakarta' }));
  r = await gw('PUT', '/nilai/2', { token: tok.dosen1, device: DEV.dosen1, body: { nilai: 80 } });
  check('ubah nilai di dalam jam akses -> 200', r.status === 200, JSON.stringify(r));
  fs.writeFileSync(cfg.accessHoursFile, orig);

  section('6. Finalisasi + panggilan antar-service via gateway');
  const hrsOk = (() => { fs.writeFileSync(cfg.accessHoursFile, JSON.stringify({ start: '00:00', end: '23:59', timezone: 'Asia/Jakarta' })); })();
  r = await gw('POST', '/kelas/1/finalisasi', { token: tok.dosen2, device: DEV.dosen2 });
  check('dosen2 memfinalisasi kelas dosen1 -> 403', r.status === 403);
  r = await gw('POST', '/kelas/1/finalisasi', { token: tok.mhs1, device: DEV.mhs1 });
  check('mahasiswa memfinalisasi -> 403', r.status === 403);
  r = await gw('POST', '/kelas/1/finalisasi', { token: tok.dosen1, device: DEV.dosen1 });
  check('dosen1 memfinalisasi kelas 1 -> 200', r.status === 200, JSON.stringify(r));
  r = await gw('PUT', '/nilai/1', { token: tok.dosen1, device: DEV.dosen1, body: { nilai: 99 } });
  check('mengubah nilai yang sudah final -> 403', r.status === 403 && /final/.test(r.json.message), JSON.stringify(r));
  r = await gw('POST', '/kelas/1/finalisasi', { token: tok.dosen1, device: DEV.dosen1 });
  check('finalisasi ulang -> 409', r.status === 409);
  fs.writeFileSync(cfg.accessHoursFile, orig);

  section('7. Transkrip');
  r = await gw('GET', '/transkrip/2210001', { token: tok.mhs1, device: DEV.mhs1 });
  check('transkrip mhs1 memuat hasil sinkron kelas 1', r.status === 200 && r.json.mata_kuliah.length === 1 && r.json.mata_kuliah[0].mata_kuliah === 'Keamanan Informasi', JSON.stringify(r));
  r = await gw('GET', '/transkrip/2210002', { token: tok.mhs1, device: DEV.mhs1 });
  check('mahasiswa melihat transkrip NIM lain -> 403', r.status === 403);
  r = await gw('GET', '/transkrip/2210002', { token: tok.admin, device: DEV.admin });
  check('admin melihat transkrip NIM mana pun -> 200', r.status === 200);
  r = await gw('GET', '/transkrip/2210001', { token: tok.dosen1, device: DEV.dosen1 });
  check('dosen melihat transkrip -> 403', r.status === 403);

  section('8. Token service & /transkrip/sinkron');
  const body = { kelas_id: 9, nama_kelas: 'X', items: [{ nim: '2210001', nilai: 50 }] };
  r = await gw('POST', '/transkrip/sinkron', { token: tok.admin, device: DEV.admin, body });
  check('token admin ke /transkrip/sinkron -> 403', r.status === 403);
  r = await gw('POST', '/transkrip/sinkron', { token: tok.dosen1, device: DEV.dosen1, body });
  check('token dosen ke /transkrip/sinkron -> 403', r.status === 403);
  r = await gw('POST', '/auth/service', { body: { client_id: 'service-nilai', client_secret: 'salah' } });
  check('client secret salah -> 401', r.status === 401);
  r = await gw('POST', '/auth/service', { body: { client_id: cfg.serviceClient.id, client_secret: cfg.serviceClient.secret } });
  check('token service diterbitkan (5 menit, role service)', r.status === 200 && jwt.decode(r.json.access_token).role === 'service' && jwt.decode(r.json.access_token).exp - jwt.decode(r.json.access_token).iat === 300);
  const svc = r.json.access_token;
  r = await gw('GET', '/nilai', { token: svc });
  check('token service ke endpoint user -> 403', r.status === 403);
  r = await gw('POST', '/transkrip/sinkron', { token: svc, body: { kelas_id: 1, nama_kelas: 'X', items: [{ nim: 'x', nilai: 500 }] } });
  check('token service + payload tidak valid -> 400 (ditolak service)', r.status === 400);

  section('9. Default deny & path aneh');
  r = await gw('GET', '/admin/rahasia', { token: tok.admin, device: DEV.admin });
  check('endpoint tanpa kebijakan -> 403', r.status === 403);
  r = await gw('GET', '/nilai/../transkrip/2210002', { token: tok.mhs1, device: DEV.mhs1 });
  check('path traversal -> ditolak', [400, 403, 404].includes(r.status));
  r = await gw('GET', '/transkrip/sinkron', { token: tok.admin, device: DEV.admin });
  check('GET /transkrip/sinkron tidak dianggap NIM -> 403', r.status === 403);

  section('10. Refresh & logout');
  r = await gw('POST', '/auth/refresh', { body: { refresh_token: mhs1.refresh_token } });
  check('refresh token valid -> access token baru', r.status === 200 && r.json.access_token);
  const newAccess = r.json.access_token;
  r = await gw('GET', '/nilai', { token: newAccess, device: DEV.mhs1 });
  check('access token hasil refresh bisa dipakai', r.status === 200);
  r = await gw('POST', '/auth/refresh', { body: { refresh_token: 'ngawur' } });
  check('refresh token ngawur -> 401', r.status === 401);
  r = await gw('POST', '/auth/logout', { body: { refresh_token: mhs1.refresh_token } });
  check('logout -> 200', r.status === 200);
  r = await gw('POST', '/auth/refresh', { body: { refresh_token: mhs1.refresh_token } });
  check('refresh setelah logout -> 401 (token dicabut)', r.status === 401);
  r = await gw('GET', '/nilai', { token: newAccess, device: DEV.mhs1 });
  check('access token sesi yang di-logout langsung ditolak -> 401', r.status === 401, JSON.stringify(r));

  section('11. Audit log (4.4)');
  const total = db.prepare('SELECT COUNT(*) c FROM audit_log').get().c;
  const dn = db.prepare("SELECT COUNT(*) c FROM audit_log WHERE result='deny'").get().c;
  const al = db.prepare("SELECT COUNT(*) c FROM audit_log WHERE result='allow'").get().c;
  check(`audit log memuat allow (${al}) dan deny (${dn})`, total > 20 && dn > 10 && al > 10);
  const row = db.prepare("SELECT * FROM audit_log WHERE reason LIKE '%jam akses%' ORDER BY id DESC LIMIT 1").get();
  check('entri audit memuat waktu, subjek, endpoint, device, hasil, alasan', row && row.ts && row.subject && row.endpoint && row.device && row.result && row.reason, JSON.stringify(row));

  console.log(`\n\x1b[1mHasil: ${pass} lulus, ${fail} gagal\x1b[0m`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(2); });
