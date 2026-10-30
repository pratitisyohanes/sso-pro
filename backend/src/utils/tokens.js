const { SignJWT, jwtVerify, decodeJwt } = require('jose');
const env = require('../config/env');
const { privateKey, publicKey } = require('../config/keys');

// Service tokens are only accepted by auth-service itself
const SERVICE_AUDIENCE = 'auth-service';

const sign = (claims, { issuer, subject, audience, expiresIn }) =>
  new SignJWT(claims)
    .setProtectedHeader({ alg: 'RS256', kid: env.JWT_KEY_ID })
    .setIssuer(issuer)
    .setSubject(subject)
    .setAudience(audience)
    .setIssuedAt()
    .setExpirationTime(expiresIn)
    .sign(privateKey);

// Like the office API gateway token: proves which application is calling, not which user
const signServiceToken = (client) =>
  sign({ scope: client.scopes.join(' ') }, { issuer: env.TOKEN_ISSUER, subject: client.id, audience: SERVICE_AUDIENCE, expiresIn: env.SERVICE_TOKEN_EXPIRES });

const verifyServiceToken = async (token) => {
  const { payload } = await jwtVerify(token, publicKey, { issuer: env.TOKEN_ISSUER, audience: SERVICE_AUDIENCE, algorithms: ['RS256'] });
  return payload;
};

// User access token for booking-api and pos-api; carries the same id, role and name as the old HS256 token
const signAccessToken = (user, { clientId, sessionId }) =>
  sign(
    { name: user.name, email: user.email, role: user.role, azp: clientId, sid: sessionId, scope: 'openid profile email' },
    { issuer: env.PUBLIC_URL, subject: user.id, audience: env.USER_AUDIENCES, expiresIn: env.ACCESS_TOKEN_EXPIRES },
  );

// id_token tells the browser app who logged in; nonce ties it to the login request the app started
const signIdToken = (user, { clientId, nonce }) =>
  sign(
    { name: user.name, email: user.email, role: user.role, ...(nonce && { nonce }) },
    { issuer: env.PUBLIC_URL, subject: user.id, audience: clientId, expiresIn: env.ACCESS_TOKEN_EXPIRES },
  );

const verifyAccessToken = async (token) => {
  const { payload } = await jwtVerify(token, publicKey, { issuer: env.PUBLIC_URL, audience: env.USER_AUDIENCES, algorithms: ['RS256'] });
  return payload;
};

// Seconds until expiry, for the expires_in field of the OAuth response
const secondsLeft = (token) => {
  const { exp, iat } = decodeJwt(token);
  return exp - iat;
};

module.exports = { signServiceToken, verifyServiceToken, signAccessToken, signIdToken, verifyAccessToken, secondsLeft, SERVICE_AUDIENCE };
