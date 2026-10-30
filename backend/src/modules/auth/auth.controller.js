const asyncHandler = require('../../utils/asyncHandler');
const { success } = require('../../utils/response');
const authService = require('./auth.service');

const validate = asyncHandler(async (req, res) => {
  const data = await authService.validate(req.body, { client: req.client, ip: req.get('X-Forwarded-For') || req.ip });
  success(res, { message: data.login ? 'Credentials are valid' : 'Credentials are not valid', data });
});

module.exports = { validate };
