const ApiError = require('../utils/ApiError');
const { verifyServiceToken } = require('../utils/tokens');

// Require a service token from /oauth/token that carries every listed scope
const authenticateClient =
  (...requiredScopes) =>
  async (req, res, next) => {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return next(ApiError.unauthorized('Service token is missing'));

    let payload;
    try {
      payload = await verifyServiceToken(token);
    } catch {
      return next(ApiError.unauthorized('Service token is invalid or expired'));
    }

    const scopes = String(payload.scope || '').split(' ').filter(Boolean);
    const missing = requiredScopes.filter((scope) => !scopes.includes(scope));
    if (missing.length) return next(ApiError.forbidden(`Client is missing scope: ${missing.join(', ')}`));

    req.client = { id: payload.sub, scopes };
    return next();
  };

module.exports = authenticateClient;
