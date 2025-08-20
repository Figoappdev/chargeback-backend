const mongoose = require('mongoose');

const disputeSchema = new mongoose.Schema({
  amount: { type: Number, required: true },
  reason: { type: String, required: true },
  customerEmail: { type: String, required: true },
  status: { type: String, required: true },
  priority: { type: String, enum: ['Low', 'Medium', 'High'], required: true, default: 'Medium' },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Dispute', disputeSchema);