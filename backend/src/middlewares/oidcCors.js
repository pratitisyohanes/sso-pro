const { Client } = require('../models');

const CACHE_MS = 60 * 1000;
let cache = { origins: new Set(), loadedAt: 0 };

// Origins of every registered browser app, re-read at most once a minute
const allowedOrigins = async () => {
  if (Date.now() - cache.loadedAt < CACHE_MS) return cache.origins;
  const clients = await Client.findAll({ where: { isActive: true }, attributes: ['allowedOrigins'] });
  cache = { origins: new Set(clients.flatMap((client) => client.allowedOrigins)), loadedAt: Date.now() };
  return cache.origins;
};

// The browser apps call /oidc/token and /oidc/userinfo with fetch, so only their exact origins get CORS headers
const oidcCors = async (req, res, next) => {
  try {
    const origin = req.get('Origin');
    if (origin && (await allowedOrigins()).has(origin)) {
      res.set({
        'Access-Control-Allow-Origin': origin,
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Authorization, Content-Type',
        Vary: 'Origin',
      });
    }
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    return next();
  } catch (error) {
    return next(error);
  }
};

// For tests and after registering a new client
const resetCorsCache = () => {
  cache = { origins: new Set(), loadedAt: 0 };
};

module.exports = { oidcCors, resetCorsCache };
