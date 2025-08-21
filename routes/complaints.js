const express = require('express');
const router = express.Router();
const db = require('../models/complaint');
const winston = require('winston'); // Added for logging

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

router.post('/', (req, res) => {
  const { transactionId, atmLocation, timestamp, accountId } = req.body;
  if (!transactionId || !atmLocation || !timestamp || !accountId) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  db.run(
    `INSERT INTO complaints (transactionId, atmLocation, timestamp, accountId) VALUES (?, ?, ?, ?)`,
    [transactionId, atmLocation, timestamp, accountId],
    function(err) {
      if (err) {
        logger.error('Complaint creation error:', err);
        return res.status(500).json({ error: err.message });
      }
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
      if (err) {
        logger.error('Chargeback initiation error:', err);
        return res.status(500).json({ error: err.message });
      }
      db.run(`UPDATE complaints SET status = 'Chargeback Initiated' WHERE id = ?`, [id], (err) => {
        if (err) logger.error('Complaint status update error:', err);
      });
      setTimeout(() => {
        db.run(`UPDATE chargebacks SET status = 'Resolved' WHERE id = ?`, [this.lastID], (err) => {
          if (err) logger.error('Chargeback resolution error:', err);
        });
      }, 7200000); // 2-hour mock delay
      res.status(200).json({ id: this.lastID, status: 'Chargeback Initiated' });
    }
  );
});

router.get('/chargebacks/:id/status', (req, res) => {
  const { id } = req.params;
  db.get(`SELECT status FROM chargebacks WHERE id = ?`, [id], (err, row) => {
    if (err || !row) {
      logger.warn('Chargeback status fetch error or not found:', { id, error: err?.message });
      return res.status(404).json({ error: 'Chargeback not found' });
    }
    res.json({ status: row.status });
  });
});

module.exports = router;