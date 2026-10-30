// Error for /oauth/token, answered in the OAuth 2.0 shape { error, error_description } instead of the API envelope
class OAuthError extends Error {
  constructor(statusCode, code, description) {
    super(description);
    this.name = 'OAuthError';
    this.statusCode = statusCode;
    this.code = code;
  }

  static invalidRequest(description) {
    return new OAuthError(400, 'invalid_request', description);
  }

  static invalidClient() {
    return new OAuthError(401, 'invalid_client', 'Client authentication failed');
  }

  static unsupportedGrantType() {
    return new OAuthError(400, 'unsupported_grant_type', 'Only client_credentials is supported');
  }
}

module.exports = OAuthError;
