const router = require('express').Router();
const validate = require('../../middlewares/validate');
const authenticateClient = require('../../middlewares/authenticateClient');
const { validateLimiter } = require('../../middlewares/rateLimiter');
const controller = require('./auth.controller');
const { validateSchema } = require('./auth.schema');

// Order matters: who is calling, then is the body valid, then is this account being hammered
router.post('/validate', authenticateClient('auth:validate'), validate(validateSchema), validateLimiter, controller.validate);

module.exports = router;
