const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database(process.env.DATABASE_PATH);

exports.getDisputes = (req, res) => {
  db.all('SELECT * FROM disputes', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
};

exports.createDispute = (req, res) => {
  const { amount, reason, customerEmail, status, priority } = req.body;
  if (!amount || !reason || !customerEmail || !priority) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  db.run(
    'INSERT INTO disputes (amount, reason, customerEmail, status, priority, createdAt) VALUES (?, ?, ?, ?, ?, ?)',
    [amount, reason, customerEmail, status, priority, new Date().toISOString()],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      db.get('SELECT * FROM disputes WHERE rowid = ?', [this.lastID], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json(row);
      });
    }
  );
};

exports.deleteDispute = (req, res) => {
  db.run('DELETE FROM disputes WHERE id = ?', [req.params.id], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ error: 'Dispute not found' });
    res.json({ message: 'Dispute deleted' });
  });
};

// Initialize table if it doesn't exist
db.run(`
  CREATE TABLE IF NOT EXISTS disputes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    amount REAL NOT NULL,
    reason TEXT NOT NULL,
    customerEmail TEXT NOT NULL,
    status TEXT NOT NULL,
    priority TEXT NOT NULL CHECK(priority IN ('Low', 'Medium', 'High')),
    createdAt TEXT DEFAULT CURRENT_TIMESTAMP
  )
`);