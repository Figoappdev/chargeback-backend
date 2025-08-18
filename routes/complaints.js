const express = require('express');
const router = express.Router();
const db = require('../models/complaint');

router.post('/', (req, res) => {
  const { transactionId, atmLocation, timestamp, accountId } = req.body;
  db.run(
    `INSERT INTO complaints (transactionId, atmLocation, timestamp, accountId) VALUES (?, ?, ?, ?)`,
    [transactionId, atmLocation, timestamp, accountId],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.status(201).json({ id: this.lastID, status: 'Pending' });
    }
  );
});

module.exports = router;