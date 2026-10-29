// 4.3 Jam akses. Rentang dibaca dari config/access-hours.json di setiap pemanggilan,
// sehingga bisa diubah ketika demo tanpa restart.
const fs = require('fs');
const cfg = require('../shared/config');

const DEFAULT = { start: '07:00', end: '21:00', timezone: 'Asia/Jakarta' };

function readConfig() {
  try {
    return { ...DEFAULT, ...JSON.parse(fs.readFileSync(cfg.accessHoursFile, 'utf8')) };
  } catch {
    return DEFAULT; // file hilang/rusak -> pakai default yang ketat (07.00-21.00)
  }
}

const toMinutes = (hhmm) => {
  const [h, m] = String(hhmm).split(':').map(Number);
  return h * 60 + (m || 0);
};

function currentMinutes(timeZone) {
  const parts = new Intl.DateTimeFormat('en-GB', {
    hour: '2-digit', minute: '2-digit', hourCycle: 'h23', timeZone,
  }).formatToParts(new Date());
  const get = (t) => Number(parts.find((p) => p.type === t).value);
  return get('hour') * 60 + get('minute');
}

// true jika sekarang berada di dalam [start, end)
function isWithinAccessHours() {
  const c = readConfig();
  const now = currentMinutes(c.timezone);
  return { ok: now >= toMinutes(c.start) && now < toMinutes(c.end), config: c };
}

// Dipakai alat demo (admin) untuk mengubah rentang jam; zona waktu dipertahankan
function save(partial) {
  const next = { ...readConfig(), ...partial };
  fs.writeFileSync(cfg.accessHoursFile, JSON.stringify(next, null, 2) + '\n');
  return next;
}

module.exports = { isWithinAccessHours, save };
