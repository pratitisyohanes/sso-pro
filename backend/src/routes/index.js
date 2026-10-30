const router = require('express').Router();
const { apiLimiter } = require('../middlewares/rateLimiter');

router.use('/health', require('../modules/health/health.routes'));
router.use('/auth', apiLimiter, require('../modules/auth/auth.routes'));
router.use('/users', apiLimiter, require('../modules/users/users.routes'));

module.exports = router;
