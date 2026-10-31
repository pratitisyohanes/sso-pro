const express = require('express');
const { loadSession } = require('../../middlewares/ssoSession');
const { issueCsrf, verifyCsrf } = require('../../middlewares/csrf');
const { requireAdmin } = require('../../middlewares/requireAdmin');
const { adminLimiter } = require('../../middlewares/rateLimiter');
const controller = require('./admin.controller');

const router = express.Router();
const form = express.urlencoded({ extended: false });

// Every admin page needs a logged-in administrator
router.use(loadSession, issueCsrf, requireAdmin);

router.get('/users', controller.list);
router.get('/users/:id', controller.showUser);
router.post('/users/:id/reset-link', form, verifyCsrf, adminLimiter, controller.resetLink);
router.post('/users/:id/email', form, verifyCsrf, adminLimiter, controller.changeEmail);

module.exports = router;
