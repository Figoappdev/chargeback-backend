const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database(process.env.DATABASE_PATH || ':memory:');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS complaints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    transactionId TEXT NOT NULL,
    atmLocation TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    accountId TEXT NOT NULL,
    status TEXT DEFAULT 'Pending' CHECK (status IN ('Pending', 'Chargeback Initiated', 'Resolved'))
  )`);
});

module.exports = db;