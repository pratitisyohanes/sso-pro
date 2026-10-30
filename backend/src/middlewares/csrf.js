const crypto = require('crypto');
const env = require('../config/env');
const { randomToken } = require('../utils/randomToken');

const COOKIE = 'kid_csrf';

// Double-submit token: the same random value lives in a cookie and in a hidden form field
const issueCsrf = (req, res, next) => {
  let token = req.cookies?.[COOKIE];
  if (!token) {
    token = randomToken(24);
    res.cookie(COOKIE, token, { httpOnly: true, secure: env.COOKIE_SECURE, sameSite: 'lax', path: '/' });
  }
  res.locals.csrfToken = token;
  next();
};

// Another site can submit a form here, but it cannot read our cookie to copy the value into the form
const verifyCsrf = (req, res, next) => {
  const sent = Buffer.from(String(req.body?._csrf || ''));
  const expected = Buffer.from(String(req.cookies?.[COOKIE] || ''));
  if (!expected.length || sent.length !== expected.length || !crypto.timingSafeEqual(sent, expected)) {
    return res.status(403).render('message', {
      title: 'Form expired',
      message: 'This form is no longer valid. Go back, reload the page and try again.',
      tone: 'error',
    });
  }
  return next();
};

module.exports = { issueCsrf, verifyCsrf };
