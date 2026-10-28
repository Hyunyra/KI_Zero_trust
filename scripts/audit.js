// Menampilkan audit log: npm run audit            (50 terakhir)
//                        npm run audit -- 200     (200 terakhir)
//                        npm run audit -- deny    (hanya yang ditolak)
const { open } = require('../src/shared/db');
const db = open();
const args = process.argv.slice(2);
const limit = Number(args.find((a) => /^\d+$/.test(a))) || 50;
const onlyDeny = args.includes('deny');

const rows = db.prepare(
  `SELECT id, ts, subject, subject_type AS tipe, method, endpoint, device, result AS hasil, reason AS alasan
   FROM audit_log ${onlyDeny ? "WHERE result='deny'" : ''} ORDER BY id DESC LIMIT ?`
).all(limit).reverse();
console.table(rows);
