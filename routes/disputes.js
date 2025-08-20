const express = require('express');
const router = express.Router();
const Dispute = require('../models/Dispute');

router.get('/', async (req, res) => {
  try {
    const disputes = await Dispute.find();
    res.json(disputes);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/', async (req, res) => {
  try {
    const { amount, reason, customerEmail, status, priority } = req.body;
    if (!amount || !reason || !customerEmail || !priority) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    const dispute = new Dispute({ amount, reason, customerEmail, status, priority });
    await dispute.save();
    res.status(201).json(dispute);
  } catch (err) {
    res.status(500).json({ error: 'Failed to create dispute' });
  }
});

router.delete('/:id', async (req, res) => {
  try {
    const dispute = await Dispute.findByIdAndDelete(req.params.id);
    if (!dispute) return res.status(404).json({ error: 'Dispute not found' });
    res.json({ message: 'Dispute deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;