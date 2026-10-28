// Verifikasi tanda tangan + masa berlaku JWT dengan public key.
// Dipakai oleh gateway DAN kedua service (verifikasi ulang di service).
const fs = require('fs');
const jwt = require('jsonwebtoken');
const cfg = require('./config');

let publicKey;
function getPublicKey() {
  if (!publicKey) publicKey = fs.readFileSync(cfg.publicKeyPath, 'utf8');
  return publicKey;
}

// Melempar error jika tanda tangan salah, token kedaluwarsa, atau issuer tidak cocok.
function verifyToken(token) {
  return jwt.verify(token, getPublicKey(), {
    algorithms: ['RS256'], // algoritma dikunci -> menolak alg:none / HS256 confusion
    issuer: cfg.jwt.issuer,
  });
}

module.exports = { verifyToken };
