const { sequelize, Client, SsoSession, AuthorizationCode, RefreshToken } = require('../../models');
const env = require('../../config/env');
const ldap = require('../../ldap/ldap.gateway');
const OAuthError = require('../../utils/OAuthError');
const { randomToken, sha256, pkceChallenge } = require('../../utils/randomToken');
const { signAccessToken, signIdToken, secondsLeft } = require('../../utils/tokens');

const CODE_TTL_MS = 60 * 1000;
const DAY_MS = 24 * 60 * 60 * 1000;
const HOUR_MS = 60 * 60 * 1000;

const invalidGrant = (description) => new OAuthError(400, 'invalid_grant', description);

// A browser app is a client with at least one registered return address
const findWebClient = async (clientId) => {
  if (!clientId) return null;
  const client = await Client.findByPk(clientId);
  if (!client || !client.isActive || !client.redirectUris.length) return null;
  return client;
};

const withParams = (url, params) => {
  const target = new URL(url);
  Object.entries(params).forEach(([key, value]) => value !== undefined && value !== null && target.searchParams.set(key, value));
  return target.toString();
};

// Checked before anything else: an unregistered redirect_uri is never redirected to (it gets an error page instead)
const checkAuthorizeRequest = async (query) => {
  const client = await findWebClient(query.client_id);
  if (!client || !client.redirectUris.includes(query.redirect_uri)) {
    return { fatal: 'This application or its return address is not registered with ELEFEZ FARM.' };
  }
  const fail = (error, description) => ({ client, redirect: withParams(query.redirect_uri, { error, error_description: description, state: query.state }) });
  if (query.response_type !== 'code') return fail('unsupported_response_type', 'Only response_type=code is supported');
  if (!query.state) return fail('invalid_request', 'state is required');
  if (query.code_challenge_method !== 'S256' || !/^[A-Za-z0-9_-]{43,128}$/.test(query.code_challenge || '')) {
    return fail('invalid_request', 'PKCE with code_challenge_method=S256 is required');
  }
  return { client };
};

// The moment single sign-on happens: an active session gets a code without seeing the login form
const issueCode = async (session, client, query) => {
  const code = randomToken();
  await AuthorizationCode.create({
    codeHash: sha256(code),
    clientId: client.id,
    sessionId: session.id,
    userId: session.userId,
    redirectUri: query.redirect_uri,
    codeChallenge: query.code_challenge,
    nonce: query.nonce || null,
    expiresAt: new Date(Date.now() + CODE_TTL_MS),
  });
  return withParams(query.redirect_uri, { code, state: query.state });
};

const userOf = (session) => ({ id: session.userId, name: session.name, email: session.email, role: session.role });

const issueTokenSet = async (session, { clientId, nonce }, transaction) => {
  const user = userOf(session);
  const accessToken = await signAccessToken(user, { clientId, sessionId: session.id });
  const idToken = await signIdToken(user, { clientId, nonce });
  const refreshToken = randomToken();

  await RefreshToken.create(
    { tokenHash: sha256(refreshToken), sessionId: session.id, clientId, userId: session.userId, expiresAt: new Date(Date.now() + env.REFRESH_TOKEN_DAYS * DAY_MS) },
    { transaction },
  );

  return { access_token: accessToken, id_token: idToken, refresh_token: refreshToken, token_type: 'Bearer', expires_in: secondsLeft(accessToken), scope: 'openid profile email' };
};

// authorization_code grant: the code is single-use, short-lived, bound to the client, the redirect_uri and the PKCE verifier
const exchangeCode = async ({ code, code_verifier: verifier, client_id: clientId, redirect_uri: redirectUri }) => {
  if (!code || !verifier || !clientId || !redirectUri) throw OAuthError.invalidRequest('code, code_verifier, client_id and redirect_uri are required');

  const outcome = await sequelize.transaction(async (transaction) => {
    const row = await AuthorizationCode.findByPk(sha256(code), { lock: transaction.LOCK.UPDATE, transaction });
    if (!row) return { error: 'Code is invalid' };
    if (row.usedAt) {
      // A code used twice was probably intercepted: end every token of that session for this client
      await RefreshToken.update({ revokedAt: new Date() }, { where: { sessionId: row.sessionId, clientId: row.clientId, revokedAt: null }, transaction });
      return { error: 'Code was already used' };
    }
    if (row.expiresAt < new Date()) return { error: 'Code has expired' };
    if (row.clientId !== clientId || row.redirectUri !== redirectUri) return { error: 'Code was issued to another client or redirect_uri' };
    if (pkceChallenge(verifier) !== row.codeChallenge) return { error: 'PKCE verification failed' };

    await row.update({ usedAt: new Date() }, { transaction });
    const session = await SsoSession.findByPk(row.sessionId, { transaction });
    if (!session || !session.isActive()) return { error: 'Login session has ended' };

    return { tokens: await issueTokenSet(session, { clientId, nonce: row.nonce }, transaction) };
  });

  if (outcome.error) throw invalidGrant(outcome.error);
  return outcome.tokens;
};

// refresh_token grant: rotate the token, slide the session, and re-read LDAP so role changes and cn=disabled apply
const rotateRefreshToken = async ({ refresh_token: token, client_id: clientId }) => {
  if (!token || !clientId) throw OAuthError.invalidRequest('refresh_token and client_id are required');

  const outcome = await sequelize.transaction(async (transaction) => {
    const row = await RefreshToken.findOne({ where: { tokenHash: sha256(token) }, lock: transaction.LOCK.UPDATE, transaction });
    if (!row || row.clientId !== clientId) return { error: 'Refresh token is invalid' };
    if (row.revokedAt) {
      // Reuse of a rotated token means a copy exists somewhere: end the whole SSO session
      await SsoSession.destroy({ where: { id: row.sessionId }, transaction });
      return { error: 'Refresh token was already used; please log in again' };
    }
    if (row.expiresAt < new Date()) return { error: 'Refresh token has expired' };

    const session = await SsoSession.findByPk(row.sessionId, { transaction });
    if (!session || !session.isActive()) return { error: 'Login session has ended' };

    const account = await ldap.findById(session.userId);
    if (!account || account.disabled) {
      await SsoSession.destroy({ where: { id: session.id }, transaction });
      return { error: 'Account is deactivated' };
    }

    await session.update(
      { name: account.name, email: account.email, role: account.role, expiresAt: new Date(Date.now() + env.SESSION_HOURS * HOUR_MS), lastSeenAt: new Date() },
      { transaction },
    );
    await row.update({ revokedAt: new Date() }, { transaction });
    return { tokens: await issueTokenSet(session, { clientId }, transaction) };
  });

  if (outcome.error) throw invalidGrant(outcome.error);
  return outcome.tokens;
};

const exchangeToken = (body) => {
  if (body.grant_type === 'authorization_code') return exchangeCode(body);
  if (body.grant_type === 'refresh_token') return rotateRefreshToken(body);
  throw new OAuthError(400, 'unsupported_grant_type', 'Use authorization_code or refresh_token');
};

// Central logout: the session and, through ON DELETE CASCADE, its codes and refresh tokens disappear
const endSession = async (session) => {
  if (session) await SsoSession.destroy({ where: { id: session.id } });
};

// Only addresses registered for this client may receive the user after logout
const postLogoutTarget = async ({ client_id: clientId, post_logout_redirect_uri: uri, state }) => {
  const client = await findWebClient(clientId);
  if (!client || !uri || !client.postLogoutRedirectUris.includes(uri)) return null;
  return withParams(uri, { state });
};

const discovery = () => {
  const base = env.PUBLIC_URL;
  return {
    issuer: base,
    authorization_endpoint: `${base}/oidc/authorize`,
    token_endpoint: `${base}/oidc/token`,
    userinfo_endpoint: `${base}/oidc/userinfo`,
    end_session_endpoint: `${base}/oidc/logout`,
    jwks_uri: `${base}/.well-known/jwks.json`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    scopes_supported: ['openid', 'profile', 'email'],
    claims_supported: ['sub', 'name', 'email', 'role'],
  };
};

module.exports = { findWebClient, checkAuthorizeRequest, issueCode, exchangeToken, endSession, postLogoutTarget, discovery, withParams };
