// 4.4 Audit Log: setiap keputusan akses dicatat (waktu, subjek, endpoint, device, hasil, alasan).
const { open } = require('../shared/db');
const db = open();

const insert = db.prepare(
  `INSERT INTO audit_log (ts, subject, subject_type, method, endpoint, device, result, reason, ip)
   VALUES (?,?,?,?,?,?,?,?,?)`
);

function log({ subject, subjectType, method, endpoint, device, result, reason, ip }) {
  const ts = new Date().toISOString();
  insert.run(ts, subject ?? null, subjectType ?? null, method, endpoint, device ?? null, result, reason ?? null, ip ?? null);
  console.log(
    `[AUDIT] ${ts} ${result.toUpperCase().padEnd(5)} ${subjectType || '-'}:${subject ?? '-'} ` +
    `${method} ${endpoint} device=${device || '-'} alasan="${reason}"`
  );
}

module.exports = { log };
