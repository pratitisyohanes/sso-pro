const asyncHandler = require('../../utils/asyncHandler');
const ApiError = require('../../utils/ApiError');
const env = require('../../config/env');
const passwordService = require('./password.service');
const { forgotFormSchema, resetFormSchema, changePasswordFormSchema, fieldErrors } = require('./login.schema');

const activeSession = (req) => (req.ssoSession?.isActive() ? req.ssoSession : null);

const contextOf = (req) => ({ ip: req.ip, userAgent: req.get('user-agent'), client: null });

const renderMessage = (res, { status = 200, title, message, tone = 'error', link }) =>
  res.status(status).render('message', { title, message, tone, link });

const mailOffMessage = (res) =>
  renderMessage(res, { status: 503, title: 'Not available', message: 'Password reset by email is not set up yet. Please contact the administrator.' });

const invalidLinkMessage = (res) =>
  renderMessage(res, {
    status: 400,
    title: 'Link expired',
    message: 'This reset link is invalid or has expired. Request a new one.',
    link: { href: '/forgot', label: 'Request a new link' },
  });

// Forgot password: ask for the email address
const showForgot = (req, res) => {
  if (!env.MAIL_ENABLED) return mailOffMessage(res);
  return res.render('forgot', { email: '', errors: {} });
};

const forgot = asyncHandler(async (req, res) => {
  if (!env.MAIL_ENABLED) return mailOffMessage(res);

  const parsed = forgotFormSchema.safeParse(req.body);
  if (!parsed.success) return res.status(422).render('forgot', { email: req.body.email || '', errors: fieldErrors(parsed.error) });

  await passwordService.requestReset(parsed.data.email, contextOf(req));
  return renderMessage(res, {
    title: 'Check your email',
    message: `If that address belongs to an account, a reset link is on its way. It works once and expires in ${passwordService.LINK_MINUTES} minutes.`,
    tone: 'ok',
  });
});

// The link from the email lands here; the form only opens for a link that still works
const showReset = asyncHandler(async (req, res) => {
  const token = String(req.query.token || '');
  if (!(await passwordService.findValidReset(token))) return invalidLinkMessage(res);
  return res.render('reset', { token, errors: {} });
});

const reset = asyncHandler(async (req, res) => {
  const token = String(req.body?.token || '');
  const parsed = resetFormSchema.safeParse(req.body);
  if (!parsed.success) return res.status(422).render('reset', { token, errors: fieldErrors(parsed.error) });

  try {
    await passwordService.resetPassword(parsed.data.token, parsed.data.password, contextOf(req));
    return res.redirect('/login?notice=password-changed');
  } catch (error) {
    if (!(error instanceof ApiError)) throw error;
    return invalidLinkMessage(res);
  }
});

// Change password: for someone who is logged in and knows the current password
const showChange = (req, res) => {
  if (!activeSession(req)) return res.redirect('/login');
  return res.render('password', { errors: {}, error: null, notice: null });
};

const change = asyncHandler(async (req, res) => {
  const session = activeSession(req);
  if (!session) return res.redirect('/login');

  const parsed = changePasswordFormSchema.safeParse(req.body);
  if (!parsed.success) return res.status(422).render('password', { errors: fieldErrors(parsed.error), error: null, notice: null });

  try {
    await passwordService.changePassword(session, { currentPassword: parsed.data.currentPassword, newPassword: parsed.data.password }, contextOf(req));
    return res.render('password', { errors: {}, error: null, notice: 'Password changed. Your other devices were logged out.' });
  } catch (error) {
    if (!(error instanceof ApiError)) throw error;
    return res.status(error.statusCode).render('password', { errors: {}, error: error.message, notice: null });
  }
});

module.exports = { showForgot, forgot, showReset, reset, showChange, change };
