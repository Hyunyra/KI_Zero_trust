// Membuka kembali finalisasi untuk keperluan demo (tanpa menghapus akun/data lain).
//   npm run unfinalize          -> semua kelas
//   npm run unfinalize -- 1     -> hanya kelas id 1
// Efek: nilai.final = 0 dan baris transkrip kelas tersebut dihapus.
// Aman dijalankan saat server menyala. Ini alat admin lokal, BUKAN endpoint API.
const { open } = require('../src/shared/db');
const db = open();
const kelasId = process.argv.slice(2).find((a) => /^\d+$/.test(a));

const run = db.transaction(() => {
  const w = kelasId ? 'WHERE kelas_id = ?' : '';
  const a = kelasId ? [Number(kelasId)] : [];
  const n = db.prepare(`UPDATE nilai SET final = 0 ${w}`).run(...a).changes;
  const t = db.prepare(`DELETE FROM transkrip ${w}`).run(...a).changes;
  return { n, t };
});
const { n, t } = run();
console.log(`[unfinalize] ${n} nilai dibuka kembali, ${t} baris transkrip dihapus (${kelasId ? 'kelas ' + kelasId : 'semua kelas'})`);
