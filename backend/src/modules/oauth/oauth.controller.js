const asyncHandler = require('../../utils/asyncHandler');
const oauthService = require('./oauth.service');

// OAuth responses are not wrapped in the { success, data } envelope and must never be cached
const issueToken = asyncHandler(async (req, res) => {
  const data = await oauthService.issueToken(req.body);
  res.set('Cache-Control', 'no-store').json(data);
});

module.exports = { issueToken };
