const db = require('./complaint');

db.run(`CREATE TABLE IF NOT EXISTS chargebacks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  complaintId INTEGER,
  status TEXT DEFAULT 'Pending',
  initiatedAt TEXT,
  resolvedAt TEXT,
  FOREIGN KEY (complaintId) REFERENCES complaints(id)
)`);

module.exports = db;