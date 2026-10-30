const express = require('express');
const { loadSession } = require('../../middlewares/ssoSession');
const { issueCsrf, verifyCsrf } = require('../../middlewares/csrf');
const { pageLimiter } = require('../../middlewares/rateLimiter');
const controller = require('./login.controller');

const router = express.Router();
const form = express.urlencoded({ extended: false });

// Every page knows the current session and carries a CSRF token in its forms
router.use(loadSession, issueCsrf);

router.get('/', controller.home);
router.get('/login', controller.showLogin);
router.post('/login', form, verifyCsrf, pageLimiter, controller.login);
router.get('/mfa', controller.showMfa);
router.post('/mfa', form, verifyCsrf, controller.verifyMfa);
router.get('/register', controller.showRegister);
router.post('/register', form, verifyCsrf, pageLimiter, controller.register);

module.exports = router;
