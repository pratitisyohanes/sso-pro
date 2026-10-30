const { UniqueConstraintError, ValidationError, ConnectionError } = require('sequelize');
const { ZodError } = require('zod');
const env = require('../config/env');
const ApiError = require('../utils/ApiError');
const OAuthError = require('../utils/OAuthError');
const { formatIssues } = require('./validate');

const NETWORK_CODES = ['ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'EHOSTUNREACH'];

// LDAP or PostgreSQL being down is reported as 503 so callers know to retry later
const isUnavailable = (err) =>
  NETWORK_CODES.includes(err.code) || err instanceof ConnectionError || /timeout/i.test(err.name || '') || /timeout/i.test(err.message || '');

// Translate known library errors into ApiError instances
const normalizeError = (err) => {
  if (err instanceof ApiError) return err;
  if (err instanceof ZodError) return new ApiError(422, 'Validation failed', formatIssues(err.issues));
  if (err.type === 'entity.parse.failed') return ApiError.badRequest('Request body is not valid JSON');
  if (err instanceof UniqueConstraintError) return ApiError.conflict('A record with the same value already exists');
  if (err instanceof ValidationError) {
    return new ApiError(422, 'Validation failed', err.errors.map((e) => ({ field: e.path, message: e.message })));
  }
  if (isUnavailable(err)) return new ApiError(503, 'Directory or database is not reachable, please try again');
  return null;
};

// Last middleware in the chain; Express needs all four arguments to treat it as an error handler
// eslint-disable-next-line no-unused-vars
const errorHandler = (err, req, res, next) => {
  // OAuth endpoints answer in the OAuth shape so standard clients understand them
  if (err instanceof OAuthError) {
    return res.status(err.statusCode).json({ error: err.code, error_description: err.message });
  }

  const apiError = normalizeError(err);

  // Details stay in the server log; secrets and stack traces never go back to the caller (lesson from ERM)
  if (!apiError || apiError.statusCode >= 500) console.error(err);
  if (!apiError) {
    const body = { success: false, message: 'Internal server error' };
    if (env.NODE_ENV === 'development') body.detail = err.message;
    return res.status(500).json(body);
  }

  const body = { success: false, message: apiError.message };
  if (apiError.errors) body.errors = apiError.errors;
  return res.status(apiError.statusCode).json(body);
};

module.exports = errorHandler;
