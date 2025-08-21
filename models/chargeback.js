const sqlite3 = require('sqlite3').verbose();
const db = require('./complaint'); // Use the same database instance

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS chargebacks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    complaintId INTEGER NOT NULL,
    status TEXT DEFAULT 'Pending' CHECK (status IN ('Pending', 'Chargeback Initiated', 'Resolved')),
    initiatedAt TEXT,
    resolvedAt TEXT,
    FOREIGN KEY (complaintId) REFERENCES complaints(id) ON DELETE CASCADE
  )`);
});

module.exports = db;