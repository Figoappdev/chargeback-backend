const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database(':memory:');

db.run(`CREATE TABLE IF NOT EXISTS complaints (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  transactionId TEXT,
  atmLocation TEXT,
  timestamp TEXT,
  accountId TEXT,
  status TEXT DEFAULT 'Pending'
)`);

module.exports = db;