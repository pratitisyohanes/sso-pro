const bcrypt = require('bcryptjs');
const { Client } = require('../../models');
const OAuthError = require('../../utils/OAuthError');
const { signServiceToken, secondsLeft } = require('../../utils/tokens');

// Compared when the client does not exist, so a wrong id takes as long as a wrong secret
const DUMMY_HASH = bcrypt.hashSync('no-such-client', 10);

// A client may ask for fewer scopes than it owns, never more
const pickScopes = (owned, requested) => {
  if (!requested) return owned;
  const wanted = requested.split(' ').filter(Boolean);
  if (wanted.some((scope) => !owned.includes(scope))) throw new OAuthError(400, 'invalid_scope', 'Requested scope is not allowed for this client');
  return wanted;
};

// Mirrors the office gateway call pub.apigateway.oauth2/getAccessToken
const issueToken = async ({ grant_type: grantType, client_id: clientId, client_secret: clientSecret, scope }) => {
  if (grantType !== 'client_credentials') throw OAuthError.unsupportedGrantType();

  const client = await Client.scope('withSecret').findByPk(clientId);
  const secretMatches = await bcrypt.compare(clientSecret, client?.secretHash || DUMMY_HASH);
  if (!client || !client.isActive || !secretMatches) throw OAuthError.invalidClient();

  const scopes = pickScopes(client.scopes, scope);
  const accessToken = await signServiceToken({ id: client.id, scopes });

  return { access_token: accessToken, token_type: 'Bearer', expires_in: secondsLeft(accessToken), scope: scopes.join(' ') };
};

module.exports = { issueToken };
