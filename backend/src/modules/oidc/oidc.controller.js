const asyncHandler = require('../../utils/asyncHandler');
const ApiError = require('../../utils/ApiError');
const { getJwks } = require('../../config/keys');
const { verifyAccessToken } = require('../../utils/tokens');
const { clearSessionCookie } = require('../../middlewares/ssoSession');
const oidcService = require('./oidc.service');

const discovery = (req, res) => res.json(oidcService.discovery());

const jwks = asyncHandler(async (req, res) => {
  res.set('Cache-Control', 'public, max-age=300').json(await getJwks());
});

// prompt is removed from the address we come back to, otherwise prompt=login would loop forever
const authorizeReturnPath = (query) => {
  const { prompt, ...rest } = query;
  return `/oidc/authorize?${new URLSearchParams(rest).toString()}`;
};

const authorize = asyncHandler(async (req, res) => {
  const check = await oidcService.checkAuthorizeRequest(req.query);
  if (check.fatal) return res.status(400).render('message', { title: 'Cannot sign in', message: check.fatal, tone: 'error' });
  if (check.redirect) return res.redirect(check.redirect);

  const session = req.ssoSession?.isActive() ? req.ssoSession : null;
  const returnTo = encodeURIComponent(authorizeReturnPath(req.query));

  // prompt=create (from a "Sign up" button) opens the register page; prompt=login forces the password form again
  if (!session && req.query.prompt === 'create') return res.redirect(`/register?return_to=${returnTo}`);
  if (!session || req.query.prompt === 'login') return res.redirect(`/login?return_to=${returnTo}`);

  return res.redirect(await oidcService.issueCode(session, check.client, req.query));
});

const token = asyncHandler(async (req, res) => {
  const data = await oidcService.exchangeToken(req.body || {});
  res.set({ 'Cache-Control': 'no-store', Pragma: 'no-cache' }).json(data);
});

// Standard profile endpoint for apps that want fresh claims
const userinfo = asyncHandler(async (req, res) => {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) throw ApiError.unauthorized('Access token is missing');
  let claims;
  try {
    claims = await verifyAccessToken(header.slice(7));
  } catch {
    throw ApiError.unauthorized('Access token is invalid or expired');
  }
  res.json({ sub: claims.sub, name: claims.name, email: claims.email, role: claims.role });
});

const logout = asyncHandler(async (req, res) => {
  await oidcService.endSession(req.ssoSession);
  clearSessionCookie(res);

  const target = await oidcService.postLogoutTarget(req.query);
  if (target) return res.redirect(target);
  return res.render('message', { title: 'You are logged out', message: 'Your ELEFEZ FARM session has ended on this browser.', tone: 'ok' });
});

module.exports = { discovery, jwks, authorize, token, userinfo, logout };
