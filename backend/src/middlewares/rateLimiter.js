const rateLimit = require('express-rate-limit');
const env = require('../config/env');
const ApiError = require('../utils/ApiError');

const createLimiter = ({ windowMinutes, limit, message, keyGenerator, handler }) =>
  rateLimit({
    windowMs: windowMinutes * 60 * 1000,
    limit,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    skip: () => env.NODE_ENV === 'test',
    ...(keyGenerator && { keyGenerator }),
    handler: handler || ((req, res, next) => next(new ApiError(429, message))),
  });

// Login and register forms on the KandangID page come from real browsers, so they are limited per IP
const pageLimiter = createLimiter({
  windowMinutes: 15,
  limit: 20,
  handler: (req, res) =>
    res.status(429).render('message', { title: 'Too many attempts', message: 'Wait 15 minutes before trying again.', tone: 'error' }),
});

// Every caller is a server on 127.0.0.1, so limits are keyed by client and username instead of IP
const tokenLimiter = createLimiter({
  windowMinutes: 1,
  limit: 30,
  message: 'Too many token requests',
  keyGenerator: (req) => `token:${req.body?.client_id || 'unknown'}`,
});

// Guessing one account's password is slowed down even when the attacker rotates IPs on the app side
const validateLimiter = createLimiter({
  windowMinutes: 15,
  limit: 10,
  message: 'Too many login attempts for this account, try again in 15 minutes',
  keyGenerator: (req) => `validate:${req.client.id}:${String(req.body?.username || '').toLowerCase()}`,
});

const apiLimiter = createLimiter({
  windowMinutes: 1,
  limit: 300,
  message: 'Too many requests, please slow down',
  keyGenerator: (req) => `api:${req.client?.id || req.ip}`,
});

module.exports = { tokenLimiter, validateLimiter, apiLimiter, pageLimiter };
