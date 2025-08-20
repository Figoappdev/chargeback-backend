const express = require('express');
  const router = express.Router();
  const jwt = require('jsonwebtoken');
  const bcrypt = require('bcryptjs');
  const sqlite3 = require('sqlite3').verbose();
  const db = new sqlite3.Database(process.env.DATABASE_PATH);

  router.post('/login', (req, res) => {
    const { email, password } = req.body;
    db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!user) return res.status(401).json({ error: 'Invalid email or password' });
      bcrypt.compare(password, user.password, (err, match) => {
        if (err || !match) return res.status(401).json({ error: 'Invalid email or password' });
        const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
      });
    });
  });

  module.exports = router;