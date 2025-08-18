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

router.post('/:id/chargeback', (req, res) => {
  const { id } = req.params;
  const initiatedAt = new Date().toISOString();
  db.run(
    `INSERT INTO chargebacks (complaintId, status, initiatedAt) VALUES (?, ?, ?)`,
    [id, 'Chargeback Initiated', initiatedAt],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      db.run(`UPDATE complaints SET status = 'Chargeback Initiated' WHERE id = ?`, [id]);
      setTimeout(() => {
        db.run(`UPDATE chargebacks SET status = 'Resolved' WHERE id = ?`, [this.lastID]);
      }, 7200000); // 2-hour mock delay
      res.status(200).json({ id: this.lastID, status: 'Chargeback Initiated' });
    }
  );
});

router.get('/chargebacks/:id/status', (req, res) => {
  const { id } = req.params;
  db.get(`SELECT status FROM chargebacks WHERE id = ?`, [id], (err, row) => {
    if (err || !row) return res.status(404).json({ error: 'Chargeback not found' });
    res.json({ status: row.status });
  });
});

module.exports = router;