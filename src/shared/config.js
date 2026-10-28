// Konfigurasi terpusat. Semua nilai bisa di-override lewat environment variable.
const path = require('path');
const root = path.resolve(__dirname, '../..');
const env = process.env;

module.exports = {
  root,
  host: env.HOST || '127.0.0.1',
  ports: {
    gateway: Number(env.GATEWAY_PORT) || 3000,
    nilai: Number(env.NILAI_PORT) || 3001,
    transkrip: Number(env.TRANSKRIP_PORT) || 3002,
  },
  // Alamat upstream (dipakai gateway) dan alamat gateway (dipakai Service Nilai)
  nilaiUrl: env.NILAI_URL || 'http://127.0.0.1:3001',
  transkripUrl: env.TRANSKRIP_URL || 'http://127.0.0.1:3002',
  gatewayUrl: env.GATEWAY_URL || 'http://127.0.0.1:3000',

  dbPath: env.DB_PATH || path.join(root, 'data', 'nilai.db'),

  // Kunci RS256: hanya gateway yang memegang private key.
  // Service hanya memegang public key, jadi service tidak bisa memalsukan token.
  privateKeyPath: env.PRIVATE_KEY_PATH || path.join(root, 'keys', 'gateway', 'private.pem'),
  publicKeyPath: env.PUBLIC_KEY_PATH || path.join(root, 'keys', 'public', 'public.pem'),

  // File jam akses dibaca ulang di setiap request -> bisa diubah saat demo tanpa restart.
  accessHoursFile: env.ACCESS_HOURS_FILE || path.join(root, 'config', 'access-hours.json'),

  // Rahasia bersama gateway -> service. GANTI untuk penggunaan selain demo.
  gatewaySecret: env.GATEWAY_SECRET || 'dev-gateway-secret-ganti-di-produksi',

  serviceClient: {
    id: env.SERVICE_CLIENT_ID || 'service-nilai',
    secret: env.SERVICE_CLIENT_SECRET || 'dev-service-nilai-secret',
  },

  jwt: {
    issuer: 'zt-gateway',
    accessTtl: '10m',   // access token user
    serviceTtl: '5m',   // token service
    refreshTtlMs: 24 * 60 * 60 * 1000, // refresh token 1 hari
  },
};
