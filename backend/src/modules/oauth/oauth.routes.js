const express = require('express');
const { tokenLimiter } = require('../../middlewares/rateLimiter');
const OAuthError = require('../../utils/OAuthError');
const controller = require('./oauth.controller');
const { tokenSchema } = require('./oauth.schema');

const router = express.Router();

// Clients may send id and secret as HTTP Basic auth (RFC 6749 section 2.3.1), which Swagger UI does by default
const readBasicAuth = (req, res, next) => {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Basic ')) return next();

  const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
  const split = decoded.indexOf(':');
  if (split < 1) return next(OAuthError.invalidRequest('Malformed Basic credentials'));

  try {
    // The spec form-encodes id and secret before base64
    const clientId = decodeURIComponent(decoded.slice(0, split).replace(/\+/g, ' '));
    const clientSecret = decodeURIComponent(decoded.slice(split + 1).replace(/\+/g, ' '));
    req.body = { ...(req.body || {}), client_id: clientId, client_secret: clientSecret };
    return next();
  } catch {
    return next(OAuthError.invalidRequest('Malformed Basic credentials'));
  }
};

// OAuth validation errors use the OAuth shape instead of the 422 envelope
const validateToken = (req, res, next) => {
  const result = tokenSchema.safeParse({ body: req.body || {} });
  if (!result.success) return next(OAuthError.invalidRequest(result.error.issues[0].message));
  req.body = result.data.body;
  return next();
};

// The spec uses form encoding; JSON is accepted too because it is easier to try in Postman
router.post('/token', express.urlencoded({ extended: false }), readBasicAuth, tokenLimiter, validateToken, controller.issueToken);

module.exports = router;
