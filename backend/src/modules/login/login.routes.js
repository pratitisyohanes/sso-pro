const express = require('express');
const { loadSession } = require('../../middlewares/ssoSession');
const { issueCsrf, verifyCsrf } = require('../../middlewares/csrf');
const { pageLimiter, resetLimiter } = require('../../middlewares/rateLimiter');
const controller = require('./login.controller');
const passwordController = require('./password.controller');

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

// Forgot password (link by email) and change password (while logged in)
router.get('/forgot', passwordController.showForgot);
router.post('/forgot', form, verifyCsrf, resetLimiter, passwordController.forgot);
router.get('/reset', passwordController.showReset);
router.post('/reset', form, verifyCsrf, resetLimiter, passwordController.reset);
router.get('/account/password', passwordController.showChange);
router.post('/account/password', form, verifyCsrf, pageLimiter, passwordController.change);

module.exports = router;
