const ApiError = require('../utils/ApiError');

const formatIssues = (issues) =>
  issues.map((issue) => ({
    field: issue.path.slice(1).join('.') || issue.path[0] || 'request',
    message: issue.message,
  }));

// Validate body/query/params with a Zod schema and replace them with the parsed values
const validate = (schema) => (req, res, next) => {
  const result = schema.safeParse({ body: req.body, query: req.query, params: req.params });
  if (!result.success) return next(new ApiError(422, 'Validation failed', formatIssues(result.error.issues)));

  if (result.data.body !== undefined) req.body = result.data.body;
  if (result.data.query !== undefined) req.query = result.data.query;
  if (result.data.params !== undefined) req.params = result.data.params;
  return next();
};

module.exports = validate;
module.exports.formatIssues = formatIssues;
