const express = require('express');
const router = express.Router();
const disputeController = require('../controllers/disputeController');

router.get('/', disputeController.getDisputes);
router.post('/', disputeController.createDispute);
router.delete('/:id', disputeController.deleteDispute);

module.exports = router;