const mongoose = require('mongoose');

const integrationSchema = new mongoose.Schema({
  name: { type: String, required: true },
  clientId: { type: String, required: true },
  clientSecret: { type: String, required: true },
  username: { type: String, required: true },
  password: { type: String, required: true },
  securityToken: { type: String },
  instanceUrl: { type: String, required: true },
  status: { type: String, default: 'Pending' } // e.g., 'Connected', 'Disconnected'
});

module.exports = mongoose.model('Integration', integrationSchema);