const Integration = require('../models/Integration');

exports.getIntegrations = async (req, res) => {
  try {
    const integrations = await Integration.find();
    res.json(integrations);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

exports.createIntegration = async (req, res) => {
  try {
    const integration = new Integration(req.body);
    await integration.save();
    res.status(201).json(integration);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
};

exports.updateIntegration = async (req, res) => {
  try {
    const integration = await Integration.findByIdAndUpdate(req.params.id, req.body, { new: true, runValidators: true });
    if (!integration) return res.status(404).json({ error: 'Integration not found' });
    res.json(integration);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
};

exports.deleteIntegration = async (req, res) => {
  try {
    const integration = await Integration.findByIdAndDelete(req.params.id);
    if (!integration) return res.status(404).json({ error: 'Integration not found' });
    res.json({ message: 'Integration deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};