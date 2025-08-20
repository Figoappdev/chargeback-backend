const express = require('express');
const router = express.Router();
const integrationController = require('../controllers/integrationController');

router.get('/', integrationController.getIntegrations);
router.post('/', integrationController.createIntegration);
router.put('/:id', integrationController.updateIntegration);
router.delete('/:id', integrationController.deleteIntegration);

module.exports = router;