const express = require('express');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();

/**
 * GET /api/v1/me
 * Protected endpoint returning authenticated user identity.
 */
router.get('/', authenticateToken, (req, res) => {
  return res.status(200).json({
    id: req.user.id,
    email: req.user.email
  });
});

module.exports = router;
