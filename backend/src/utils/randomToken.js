const crypto = require('crypto');

// Opaque values handed to browsers (session id, code, refresh token); only their SHA-256 is stored
const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url');

const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');

// PKCE S256: base64url(sha256(code_verifier)) must equal the code_challenge sent to /authorize
const pkceChallenge = (verifier) => crypto.createHash('sha256').update(verifier).digest('base64url');

module.exports = { randomToken, sha256, pkceChallenge };
