const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');
const cors = require('cors');
const moment = require('moment');
const jsforce = require('jsforce');

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

const db = new sqlite3.Database(process.env.DATABASE_PATH || ':memory:');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    role TEXT,
    business TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS disputes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    transaction_id TEXT,
    reason_code TEXT,
    amount REAL,
    status TEXT,
    user_id INTEGER,
    priority INTEGER,
    deadline TEXT,
    evidence TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS fraud_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    field TEXT,
    condition TEXT,
    value TEXT,
    action TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    transaction_id TEXT,
    amount REAL,
    date TEXT,
    merchant TEXT
  )`);

   db.run(`CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER UNIQUE,
    salesforce_client_id TEXT,
    salesforce_client_secret TEXT,
    salesforce_username TEXT,
    salesforce_password TEXT,
    salesforce_security_token TEXT,
    salesforce_instance_url TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);

  db.get('SELECT COUNT(*) as count FROM users', (err, row) => {
    if (row.count === 0) {
      const hashedPassword = bcrypt.hashSync('pass123', 10);
      db.run('INSERT INTO users (email, password, role, business) VALUES (?, ?, ?, ?)', ['demo@bank.com', hashedPassword, 'bank', 'Demo Bank']);
      db.run('INSERT INTO users (email, password, role, business) VALUES (?, ?, ?, ?)', ['admin@bank.com', hashedPassword, 'admin', 'Demo Bank']);
    }
  });
});

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(401).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

const getUserCredentials = (userId, callback) => {
  db.get('SELECT * FROM credentials WHERE user_id = ?', [userId], callback);
};

const connectToSalesforce = async (credentials) => {
  const conn = new jsforce.Connection({
    loginUrl: credentials.salesforce_instance_url || 'https://login.salesforce.com'
  });
  try {
    await conn.login(credentials.salesforce_username, credentials.salesforce_password + (credentials.salesforce_security_token || ''));
    console.log(`Connected to Salesforce for user ${credentials.user_id}`);
    return conn;
  } catch (err) {
    console.error(`Salesforce connection failed for user ${credentials.user_id}:`, err.message);
    return null;
  }
};

const syncToSalesforce = async (dispute, credentials) => {
  if (!credentials) {
    console.log('No credentials available for sync');
    return;
  }
  const conn = await connectToSalesforce(credentials);
  if (!conn) return;

  try {
    const result = await conn.sobject('Dispute__c').create({
      Transaction_Id__c: dispute.transaction_id,
      Reason_Code__c: dispute.reason_code,
      Amount__c: dispute.amount,
      Status__c: dispute.status,
      Priority__c: dispute.priority,
      Deadline__c: dispute.deadline,
      Evidence__c: dispute.evidence
    });
    db.run('UPDATE disputes SET salesforce_id = ? WHERE id = ?', [result.id, dispute.id]);
    console.log(`Dispute ${dispute.id} synced to Salesforce: ${result.id}`);
  } catch (err) {
    console.error(`Sync error for dispute ${dispute.id}:`, err.message);
  }
};

app.post('/api/register', async (req, res) => {
  const { email, password, business, role = 'bank' } = req.body;
  if (!email || !password || !business) {
    return res.status(400).json({ error: 'Email, password, and business are required' });
  }
  const validRoles = ['bank', 'admin', 'manager', 'analyst', 'viewer'];
  if (!validRoles.includes(role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run(
      'INSERT INTO users (email, password, role, business) VALUES (?, ?, ?, ?)',
      [email, hashedPassword, role, business],
      function (err) {
        if (err) {
          return res.status(400).json({ error: 'Email already exists' });
        }
        res.status(201).json({ message: 'User registered successfully' });
      }
    );
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err || !user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, role: user.role });
  });
});

app.get('/api/check-auth', authenticateToken, (req, res) => {
  res.json({ message: 'Authenticated', user: req.user });
});

app.get('/api/users', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  db.all('SELECT id, email, role, business FROM users', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Server error' });
    res.json(rows);
  });
});

app.put('/api/users/:id', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  const { role } = req.body;
  const validRoles = ['bank', 'admin', 'manager', 'analyst', 'viewer'];
  if (!validRoles.includes(role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }
  db.run('UPDATE users SET role = ? WHERE id = ?', [role, req.params.id], function (err) {
    if (err) return res.status(500).json({ error: 'Server error' });
    res.json({ message: 'User updated' });
  });
});

app.delete('/api/users/:id', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  db.run('DELETE FROM users WHERE id = ?', [req.params.id], function (err) {
    if (err) return res.status(500).json({ error: 'Server error' });
    if (this.changes === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ message: 'User deleted' });
  });
});

app.post('/api/users/:id/reset-password', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  const { newPassword } = req.body;
  if (!newPassword) {
    return res.status(400).json({ error: 'New password is required' });
  }
  try {
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    db.run('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, req.params.id], function (err) {
      if (err) return res.status(500).json({ error: 'Server error' });
      if (this.changes === 0) return res.status(404).json({ error: 'User not found' });
      console.log(`Email notification sent to ${db.get('SELECT email FROM users WHERE id = ?', [req.params.id]).email}: Password updated`);
      res.json({ message: 'Password updated and notification triggered' });
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/disputes', authenticateToken, (req, res) => {
  const { status, reason, minAmount, maxAmount, startDate, endDate, search } = req.query;
  let query = 'SELECT * FROM disputes WHERE 1=1';
  const params = [];
  if (status && status !== 'all') {
    query += ' AND status = ?';
    params.push(status);
  }
  if (reason) {
    query += ' AND reason_code = ?';
    params.push(reason);
  }
  if (minAmount) {
    query += ' AND amount >= ?';
    params.push(minAmount);
  }
  if (maxAmount) {
    query += ' AND amount <= ?';
    params.push(maxAmount);
  }
  if (startDate) {
    query += ' AND deadline >= ?';
    params.push(startDate);
  }
  if (endDate) {
    query += ' AND deadline <= ?';
    params.push(endDate);
  }
  if (search) {
    query += ' AND transaction_id LIKE ?';
    params.push(`%${search}%`);
  }
  if (req.user.role === 'bank' || req.user.role === 'manager') {
    query += ' AND user_id = ?';
    params.push(req.user.id);
  }
  db.all(query, params, (err, rows) => {
    if (err) return res.status(500).json({ error: 'Server error' });
    res.json(rows);
  });
});

app.post('/api/disputes', authenticateToken, (req, res) => {
  const { transaction_id, reason_code, amount, priority } = req.body;
  if (!transaction_id || !reason_code || !amount) {
    return res.status(400).json({ error: 'Transaction ID, reason code, and amount are required' });
  }
  if (req.user.role === 'viewer' || req.user.role === 'analyst') {
    return res.status(403).json({ error: 'Insufficient permissions to create disputes' });
  }
  const status = 'initiated';
  const user_id = req.user.id;
  const deadline = moment().add(90, 'days').format('YYYY-MM-DD');
  db.run(
    'INSERT INTO disputes (transaction_id, reason_code, amount, status, user_id, priority, deadline) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [transaction_id, reason_code, amount, status, user_id, priority || 0, deadline],
    function (err) {
      if (err) return res.status(500).json({ error: 'Server error' });
      res.status(201).json({ id: this.lastID });
    }
  );
});

app.put('/api/disputes/:id', authenticateToken, (req, res) => {
  const { status, evidence, priority } = req.body;
  if (req.user.role === 'viewer') {
    return res.status(403).json({ error: 'Insufficient permissions to update disputes' });
  }
  db.run(
    'UPDATE disputes SET status = ?, evidence = ?, priority = ? WHERE id = ?',
    [status, evidence, priority, req.params.id],
    function (err) {
      if (err) return res.status(500).json({ error: 'Server error' });
      res.json({ message: 'Dispute updated' });
    }
  );
});

app.put('/api/disputes/assign/:id', authenticateToken, (req, res) => {
  const { user_id } = req.body;
  if (req.user.role !== 'admin' && req.user.role !== 'manager') {
    return res.status(403).json({ error: 'Insufficient permissions to assign disputes' });
  }
  db.run('UPDATE disputes SET user_id = ? WHERE id = ?', [user_id, req.params.id], function (err) {
    if (err) return res.status(500).json({ error: 'Server error' });
    res.json({ message: 'Dispute assigned' });
  });
});

app.post('/api/disputes/sync', authenticateToken, async (req, res) => {
  const { id } = req.body;
  db.get('SELECT * FROM disputes WHERE id = ?', [id], async (err, dispute) => {
    if (err || !dispute) return res.status(404).json({ error: 'Dispute not found' });
    await syncToSalesforce(dispute);
    res.json({ message: 'Sync triggered' });
  });
});

app.get('/api/disputes/:id/salesforce-status', authenticateToken, (req, res) => {
  const { id } = req.params;
  db.get('SELECT salesforce_id FROM disputes WHERE id = ?', [id], (err, row) => {
    if (err || !row) return res.status(404).json({ error: 'Dispute not found' });
    res.json({ status: row.salesforce_id ? 'Synced' : 'Not Synced' });
  });
});

app.post('/api/notify', authenticateToken, (req, res) => {
  console.log('Notification sent:', req.body.message);
  res.json({ message: 'Notification sent' });
});

app.get('/api/fraud', authenticateToken, (req, res) => {
  if (req.user.role === 'viewer') {
    return res.status(403).json({ error: 'Insufficient permissions to view fraud rules' });
  }
  db.all('SELECT * FROM fraud_rules', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Server error' });
    res.json(rows);
  });
});

app.post('/api/fraud', authenticateToken, (req, res) => {
  const { field, condition, value, action } = req.body;
  if (!field || !condition || !value || !action) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  if (req.user.role === 'viewer' || req.user.role === 'analyst') {
    return res.status(403).json({ error: 'Insufficient permissions to create fraud rules' });
  }
  db.run(
    'INSERT INTO fraud_rules (field, condition, value, action) VALUES (?, ?, ?, ?)',
    [field, condition, value, action],
    function (err) {
      if (err) return res.status(500).json({ error: 'Server error' });
      res.status(201).json({ id: this.lastID });
    }
  );
});

app.get('/api/transactions', authenticateToken, (req, res) => {
  const { merchant, minAmount, maxAmount, startDate, endDate } = req.query;
  let query = 'SELECT * FROM transactions WHERE 1=1';
  const params = [];
  if (merchant) {
    query += ' AND merchant = ?';
    params.push(merchant);
  }
  if (minAmount) {
    query += ' AND amount >= ?';
    params.push(minAmount);
  }
  if (maxAmount) {
    query += ' AND amount <= ?';
    params.push(maxAmount);
  }
  if (startDate) {
    query += ' AND date >= ?';
    params.push(startDate);
  }
  if (endDate) {
    query += ' AND date <= ?';
    params.push(endDate);
  }
  db.all(query, params, (err, rows) => {
    if (err) return res.status(500).json({ error: 'Server error' });
    res.json(rows);
  });
});

app.post('/api/transactions', authenticateToken, (req, res) => {
  const { transaction_id, amount, merchant } = req.body;
  if (!transaction_id || !amount || !merchant) {
    return res.status(400).json({ error: 'Transaction ID, amount, and merchant are required' });
  }
  if (req.user.role === 'viewer') {
    return res.status(403).json({ error: 'Insufficient permissions to create transactions' });
  }
  const date = moment().format('YYYY-MM-DD');
  db.run(
    'INSERT INTO transactions (transaction_id, amount, date, merchant) VALUES (?, ?, ?, ?)',
    [transaction_id, amount, date, merchant],
    function (err) {
      if (err) return res.status(500).json({ error: 'Server error' });
      res.status(201).json({ id: this.lastID });
    }
  );
});

app.get('/api/auto-response/:reason_code', authenticateToken, (req, res) => {
  const responses = {
    fraud: 'Initiated investigation for fraudulent transaction.',
    unauthorized: 'Transaction marked as unauthorized, refund processing.',
    'non-delivered': 'Requesting proof of delivery from merchant.',
    duplicate: 'Duplicate transaction confirmed, refund initiated.'
  };
  res.json({ response: responses[req.params.reason_code] || 'No response available' });
});

app.get('/api/analytics', authenticateToken, (req, res) => {
  const { startDate, endDate, reasonCodes } = req.query;
  let query = 'SELECT reason_code, COUNT(*) as count FROM disputes WHERE 1=1';
  const params = [];
  if (startDate) {
    query += ' AND deadline >= ?';
    params.push(startDate);
  }
  if (endDate) {
    query += ' AND deadline <= ?';
    params.push(endDate);
  }
  if (reasonCodes) {
    query += ' AND reason_code IN (' + reasonCodes.split(',').map(() => '?').join(',') + ')';
    params.push(...reasonCodes.split(','));
  }
  if (req.user.role === 'bank' || req.user.role === 'manager') {
    query += ' AND user_id = ?';
    params.push(req.user.id);
  }
  query += ' GROUP BY reason_code';
  db.all(query, params, (err, rows) => {
    if (err) return res.status(500).json({ error: 'Server error' });
    res.json(rows);
  });
});

app.get('/api/mock-gateway', authenticateToken, (req, res) => {
  res.json([
    { transaction_id: 'TXN001', amount: 5000, status: 'completed' },
    { transaction_id: 'TXN002', amount: 3000, status: 'pending' },
    { transaction_id: 'TXN003', amount: 7000, status: 'failed' }
  ]);
});

app.get('/api/mock-webhooks', authenticateToken, (req, res) => {
  res.json([
    { id: 1, event: 'transaction_created', data: { transaction_id: 'TXN001', amount: 5000 } },
    { id: 2, event: 'dispute_initiated', data: { transaction_id: 'TXN002', reason: 'fraud' } }
  ]);
});

app.get('/api/docs', authenticateToken, (req, res) => {
  res.json({
    openapi: '3.0.0',
    info: { title: 'Chargeback API', version: '1.0.0' },
    paths: {
      '/api/register': { post: { summary: 'Register a new user' } },
      '/api/login': { post: { summary: 'User login' } },
      '/api/disputes': { get: { summary: 'Get disputes' }, post: { summary: 'Create dispute' } }
    }
  });
});

app.get('/api/settings/salesforce', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  db.get('SELECT * FROM credentials WHERE user_id = ?', [req.user.id], (err, row) => {
    if (err) return res.status(500).json({ error: 'Server error' });
    res.json(row || {});
  });
});

app.post('/api/settings/salesforce', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  const { salesforce_client_id, salesforce_client_secret, salesforce_username, salesforce_password, salesforce_security_token, salesforce_instance_url } = req.body;
  if (!salesforce_username || !salesforce_password || !salesforce_instance_url) {
    return res.status(400).json({ error: 'Required fields missing' });
  }
  db.run(
    'INSERT OR REPLACE INTO credentials (user_id, salesforce_client_id, salesforce_client_secret, salesforce_username, salesforce_password, salesforce_security_token, salesforce_instance_url) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [req.user.id, salesforce_client_id, salesforce_client_secret, salesforce_username, salesforce_password, salesforce_security_token, salesforce_instance_url],
    (err) => {
      if (err) return res.status(500).json({ error: 'Failed to save credentials' });
      res.json({ message: 'Credentials saved' });
    }
  );
});


const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => console.log(`Server running on port ${PORT}`));