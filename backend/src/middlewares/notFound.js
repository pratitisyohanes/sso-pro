const ApiError = require('../utils/ApiError');

// Catch requests that did not match any route
const notFound = (req, res, next) => next(ApiError.notFound(`Route ${req.method} ${req.originalUrl} not found`));

module.exports = notFound;
