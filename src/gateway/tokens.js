// Penerbitan JWT (hanya gateway yang memegang private key).
const fs = require('fs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const cfg = require('../shared/config');

const privateKey = fs.readFileSync(cfg.privateKeyPath, 'utf8');

// Access token user: berlaku 10 menit, berisi sub + role (+ sid = id sesi refresh token)
function signUser(user, sid) {
  return jwt.sign({ role: user.role, sid }, privateKey, {
    algorithm: 'RS256',
    subject: String(user.id),
    issuer: cfg.jwt.issuer,
    expiresIn: cfg.jwt.accessTtl,
    jwtid: crypto.randomUUID(),
  });
}

// Token service: berlaku 5 menit, role: service
function signService(clientId) {
  return jwt.sign({ role: 'service' }, privateKey, {
    algorithm: 'RS256',
    subject: clientId,
    issuer: cfg.jwt.issuer,
    expiresIn: cfg.jwt.serviceTtl,
    jwtid: crypto.randomUUID(),
  });
}

module.exports = { signUser, signService };
