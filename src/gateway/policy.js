// Policy Engine (PE) - menjawab allow/deny beserta alasan.
// Kebijakan yang bergantung pada kepemilikan data (kelas yang diampu, NIM milik sendiri)
// diputuskan dengan membaca atribut dari database, bukan dari isi token saja.
// Prinsip: DEFAULT DENY -> endpoint yang tidak ada di tabel kebijakan selalu ditolak.
const { open } = require('../shared/db');
const { isWithinAccessHours } = require('./accessHours');

const db = open();
const q = {
  user: db.prepare('SELECT id, role, nim FROM users WHERE id = ?'),
  kelas: db.prepare('SELECT id, dosen_id FROM kelas WHERE id = ?'),
  nilai: db.prepare(
    `SELECT n.id, n.final, k.dosen_id FROM nilai n JOIN kelas k ON k.id = n.kelas_id WHERE n.id = ?`
  ),
};

const allow = (reason) => ({ allow: true, reason });
const deny = (reason) => ({ allow: false, reason });
const hasRole = (s, ...roles) => roles.includes(s.role);

function cekJam() {
  const { ok, config } = isWithinAccessHours();
  return ok ? null : deny(`di luar jam akses (${config.start}-${config.end} ${config.timezone})`);
}

// ---------- Tabel 3: Kebijakan akses ----------
const rules = [
  {
    // GET /nilai : mahasiswa -> hanya miliknya; dosen -> hanya kelas yang diampu
    method: 'GET', re: /^\/nilai\/?$/,
    check: ({ subject, query }) => {
      if (!hasRole(subject, 'mahasiswa', 'dosen')) return deny(`role ${subject.role} tidak boleh melihat nilai`);
      if (subject.role === 'mahasiswa') {
        const u = q.user.get(subject.id);
        if (query.nim !== undefined && String(query.nim) !== u.nim) return deny('mahasiswa hanya boleh melihat nilai miliknya sendiri');
        return allow('mahasiswa melihat nilai miliknya');
      }
      if (query.kelas_id !== undefined) {
        const k = q.kelas.get(Number(query.kelas_id));
        if (!k || k.dosen_id !== subject.id) return deny('kelas bukan kelas yang diampu dosen ini');
      }
      return allow('dosen melihat nilai kelas yang diampunya');
    },
  },
  {
    // PUT /nilai/:id : dosen, kelas diampu, belum final, dalam jam akses
    method: 'PUT', re: /^\/nilai\/(\d+)\/?$/,
    check: ({ subject, params }) => {
      if (!hasRole(subject, 'dosen')) return deny(`role ${subject.role} tidak boleh mengubah nilai`);
      const n = q.nilai.get(Number(params[0]));
      if (!n) return deny('data nilai tidak ditemukan');
      if (n.dosen_id !== subject.id) return deny('nilai bukan milik kelas yang diampu dosen ini');
      if (n.final) return deny('nilai sudah final dan tidak dapat diubah');
      return cekJam() || allow('dosen mengubah nilai kelas yang diampunya');
    },
  },
  {
    // POST /kelas/:id/finalisasi : dosen, kelas diampu, dalam jam akses
    method: 'POST', re: /^\/kelas\/(\d+)\/finalisasi\/?$/,
    check: ({ subject, params }) => {
      if (!hasRole(subject, 'dosen')) return deny(`role ${subject.role} tidak boleh memfinalisasi nilai`);
      const k = q.kelas.get(Number(params[0]));
      if (!k) return deny('kelas tidak ditemukan');
      if (k.dosen_id !== subject.id) return deny('kelas bukan kelas yang diampu dosen ini');
      return cekJam() || allow('dosen memfinalisasi kelas yang diampunya');
    },
  },
  {
    // POST /transkrip/sinkron : HANYA token service (token user apa pun ditolak)
    method: 'POST', re: /^\/transkrip\/sinkron\/?$/,
    check: ({ subject }) =>
      subject.type === 'service' && subject.role === 'service'
        ? allow('panggilan antar-service dengan token service')
        : deny('endpoint sinkron hanya untuk token service'),
  },
  {
    // GET /transkrip/:nim : mahasiswa -> NIM sendiri; admin -> semua NIM
    method: 'GET', re: /^\/transkrip\/(?!sinkron\/?$)([A-Za-z0-9_-]+)\/?$/,
    check: ({ subject, params }) => {
      if (!hasRole(subject, 'mahasiswa', 'admin')) return deny(`role ${subject.role} tidak boleh melihat transkrip`);
      if (subject.role === 'admin') return allow('admin melihat transkrip');
      const u = q.user.get(subject.id);
      return u.nim === params[0]
        ? allow('mahasiswa melihat transkrip miliknya')
        : deny('mahasiswa hanya boleh melihat transkrip dengan NIM sendiri');
    },
  },
];

// ---------- Alat demo: hanya admin, nonaktif jika DEMO_MODE=0 (lihat demo.js) ----------
if (process.env.DEMO_MODE !== '0') {
  const adminOnly = ({ subject }) =>
    hasRole(subject, 'admin') ? allow('admin memakai alat demo') : deny('alat demo hanya untuk admin');
  for (const [method, re] of [
    ['GET', /^\/demo\/audit\/?$/], ['GET', /^\/demo\/jam-akses\/?$/], ['PUT', /^\/demo\/jam-akses\/?$/],
    ['POST', /^\/demo\/buka-finalisasi\/?$/], ['POST', /^\/demo\/serangan-langsung\/?$/],
  ]) rules.push({ method, re, check: adminOnly });
}

// subject: { type:'user'|'service', id, role }
function decide({ subject, method, path, query }) {
  const rule = rules.find((r) => r.method === method && r.re.test(path));
  if (!rule) return deny('tidak ada kebijakan untuk endpoint ini (default deny)');
  const params = path.match(rule.re).slice(1);
  return rule.check({ subject, params, query: query || {} });
}

module.exports = { decide };
