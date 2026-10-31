const asyncHandler = require('../../utils/asyncHandler');
const ApiError = require('../../utils/ApiError');
const env = require('../../config/env');
const { Client } = require('../../models');
const { setSessionCookie, clearSessionCookie } = require('../../middlewares/ssoSession');
const oidcService = require('../oidc/oidc.service');
const loginService = require('./login.service');
const mfaService = require('./mfa.service');
const { loginFormSchema, codeFormSchema, registerFormSchema, fieldErrors } = require('./login.schema');

// Only our own /oidc/authorize may be the next step, so the forms can never become an open redirect
const safeReturn = (value) => (typeof value === 'string' && value.startsWith('/oidc/authorize?') ? value : '/');

const returnOf = (req) => safeReturn(req.body?.return_to ?? req.query.return_to);

// The app the user is signing in to, shown as "to continue to Booking" and written to the audit log
const clientOf = async (returnTo) => {
  if (returnTo === '/') return null;
  const params = new URLSearchParams(returnTo.split('?')[1]);
  return oidcService.findWebClient(params.get('client_id'));
};

const contextOf = async (req, returnTo) => ({ ip: req.ip, userAgent: req.get('user-agent'), client: await clientOf(returnTo) });

const withReturn = (path, returnTo) => (returnTo === '/' ? path : `${path}?return_to=${encodeURIComponent(returnTo)}`);

const activeSession = (req) => (req.ssoSession?.isActive() ? req.ssoSession : null);

const pendingSession = (req) => (req.ssoSession && req.ssoSession.stage !== 'ACTIVE' ? req.ssoSession : null);

// KandangID home: who is logged in and which apps use this account.
// Each app links to its own /login, which starts single sign-on at once, so one click lands inside the app already logged in.
const home = asyncHandler(async (req, res) => {
  const session = activeSession(req);
  const clients = await Client.findAll({ where: { isActive: true }, order: [['name', 'ASC']] });
  const apps = clients
    .filter((client) => client.allowedOrigins.length)
    .map((client) => ({ name: client.name, url: client.allowedOrigins[0], loginUrl: `${client.allowedOrigins[0]}/login` }));
  res.render('home', { session, apps });
});

// Messages that other pages may show on the login page, picked by a fixed code so no text from the address is ever printed
const NOTICES = { 'password-changed': 'Password changed. Log in with your new password.' };

const renderLogin = async (res, { status = 200, returnTo, email = '', errors = {}, error = null, notice = null }) => {
  const client = await clientOf(returnTo);
  res.status(status).render('login', { returnTo, email, errors, error, notice, appName: client?.name, mailEnabled: env.MAIL_ENABLED });
};

const showLogin = asyncHandler(async (req, res) => {
  const returnTo = returnOf(req);
  if (activeSession(req)) return res.redirect(returnTo);
  return renderLogin(res, { returnTo, notice: NOTICES[req.query.notice] ?? null });
});

const login = asyncHandler(async (req, res) => {
  const returnTo = returnOf(req);
  const parsed = loginFormSchema.safeParse(req.body);
  if (!parsed.success) return renderLogin(res, { status: 422, returnTo, email: req.body.email, errors: fieldErrors(parsed.error) });

  try {
    const { sid, stage, maxAge } = await loginService.passwordLogin(parsed.data, await contextOf(req, returnTo));
    setSessionCookie(res, sid, maxAge);
    return res.redirect(stage === 'ACTIVE' ? returnTo : withReturn('/mfa', returnTo));
  } catch (error) {
    if (!(error instanceof ApiError)) throw error;
    return renderLogin(res, { status: error.statusCode, returnTo, email: parsed.data.email, error: error.message });
  }
});

const renderMfa = async (res, session, { status = 200, returnTo, error = null }) => {
  const setup = session.stage === 'MFA_SETUP' ? await mfaService.pendingSetup(session) : null;
  res.status(status).render('mfa', { setup, returnTo, error, email: session.email });
};

const showMfa = asyncHandler(async (req, res) => {
  const returnTo = returnOf(req);
  const session = pendingSession(req);
  if (!session) return res.redirect(activeSession(req) ? returnTo : withReturn('/login', returnTo));
  return renderMfa(res, session, { returnTo });
});

const verifyMfa = asyncHandler(async (req, res) => {
  const returnTo = returnOf(req);
  const session = pendingSession(req);
  if (!session) return res.redirect(withReturn('/login', returnTo));

  const parsed = codeFormSchema.safeParse(req.body);
  if (!parsed.success) return renderMfa(res, session, { status: 422, returnTo, error: 'Enter the 6-digit code' });

  try {
    const { maxAge } = await loginService.verifySecondFactor(session, parsed.data.code, await contextOf(req, returnTo));
    // Same session id, longer life: the cookie now lasts as long as the active session
    setSessionCookie(res, req.cookies.kid_sid, maxAge);
    return res.redirect(returnTo);
  } catch (error) {
    if (!(error instanceof ApiError)) throw error;
    if (error.statusCode === 429) {
      clearSessionCookie(res);
      return renderLogin(res, { status: 429, returnTo, email: session.email, error: error.message });
    }
    return renderMfa(res, session, { status: error.statusCode, returnTo, error: error.message });
  }
});

const renderRegister = async (res, { status = 200, returnTo, values = {}, errors = {}, error = null }) => {
  const client = await clientOf(returnTo);
  res.status(status).render('register', { returnTo, values, errors, error, appName: client?.name });
};

const showRegister = asyncHandler(async (req, res) => {
  const returnTo = returnOf(req);
  if (activeSession(req)) return res.redirect(returnTo);
  return renderRegister(res, { returnTo });
});

const register = asyncHandler(async (req, res) => {
  const returnTo = returnOf(req);
  const values = { name: req.body.name, email: req.body.email, phone: req.body.phone };
  const parsed = registerFormSchema.safeParse(req.body);
  if (!parsed.success) return renderRegister(res, { status: 422, returnTo, values, errors: fieldErrors(parsed.error) });

  try {
    const { sid, maxAge } = await loginService.register(parsed.data, await contextOf(req, returnTo));
    setSessionCookie(res, sid, maxAge);
    return res.redirect(returnTo);
  } catch (error) {
    if (!(error instanceof ApiError)) throw error;
    const errors = error.statusCode === 409 ? { email: error.message } : {};
    return renderRegister(res, { status: error.statusCode, returnTo, values, errors, error: error.statusCode === 409 ? null : error.message });
  }
});

module.exports = { home, showLogin, login, showMfa, verifyMfa, showRegister, register };
