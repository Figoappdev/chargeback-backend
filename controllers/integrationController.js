const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database(process.env.DATABASE_PATH);

exports.getIntegrations = (req, res) => {
  db.all('SELECT * FROM integrations', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
};

exports.createIntegration = (req, res) => {
  const { name, clientId, clientSecret, username, password, securityToken, instanceUrl } = req.body;
  if (!name || !clientId || !clientSecret || !username || !password || !instanceUrl) {
    return res.status(400).json({ error: 'All fields except security token are required' });
  }
  db.run(
    'INSERT INTO integrations (name, clientId, clientSecret, username, password, securityToken, instanceUrl, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    [name, clientId, clientSecret, username, password, securityToken || '', instanceUrl, 'Pending'],
    function (err) {
      if (err) return res.status(400).json({ error: err.message });
      db.get('SELECT * FROM integrations WHERE rowid = ?', [this.lastID], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json(row);
      });
    }
  );
};

exports.updateIntegration = (req, res) => {
  const { name, clientId, clientSecret, username, password, securityToken, instanceUrl } = req.body;
  db.run(
    'UPDATE integrations SET name = ?, clientId = ?, clientSecret = ?, username = ?, password = ?, securityToken = ?, instanceUrl = ?, status = ? WHERE id = ?',
    [name, clientId, clientSecret, username, password, securityToken || '', instanceUrl, 'Pending', req.params.id],
    function (err) {
      if (err) return res.status(400).json({ error: err.message });
      if (this.changes === 0) return res.status(404).json({ error: 'Integration not found' });
      db.get('SELECT * FROM integrations WHERE id = ?', [req.params.id], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(row);
      });
    }
  );
};

exports.deleteIntegration = (req, res) => {
  db.run('DELETE FROM integrations WHERE id = ?', [req.params.id], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ error: 'Integration not found' });
    res.json({ message: 'Integration deleted' });
  });
};

// Initialize table if it doesn't exist
db.run(`
  CREATE TABLE IF NOT EXISTS integrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    clientId TEXT NOT NULL,
    clientSecret TEXT NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    securityToken TEXT,
    instanceUrl TEXT NOT NULL,
    status TEXT DEFAULT 'Pending'
  )
`);