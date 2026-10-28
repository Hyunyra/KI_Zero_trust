// Menjalankan gateway + 2 service sekaligus (satu perintah: npm start).
const { spawn } = require('child_process');
const path = require('path');

const apps = [
  ['gateway',   'src/gateway/index.js'],
  ['nilai',     'src/nilai/index.js'],
  ['transkrip', 'src/transkrip/index.js'],
];
const children = apps.map(([name, file]) => {
  const c = spawn(process.execPath, [path.join(__dirname, '..', file)], { stdio: 'inherit' });
  c.on('exit', (code) => {
    console.log(`[start] ${name} berhenti (kode ${code})`);
    shutdown();
  });
  return c;
});

let closing = false;
function shutdown() {
  if (closing) return;
  closing = true;
  children.forEach((c) => { try { c.kill(); } catch { /* sudah mati */ } });
  setTimeout(() => process.exit(0), 300);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
