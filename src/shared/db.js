// Satu database SQLite bersama untuk gateway, Service Nilai, dan Service Transkrip.
const Database = require('better-sqlite3');
const fs = require('fs');
const path = require('path');
const cfg = require('./config');

function open() {
  fs.mkdirSync(path.dirname(cfg.dbPath), { recursive: true });
  const db = new Database(cfg.dbPath);
  db.pragma('journal_mode = WAL');   // aman dipakai beberapa proses sekaligus
  db.pragma('busy_timeout = 5000');
  db.pragma('foreign_keys = ON');
  return db;
}

module.exports = { open };
