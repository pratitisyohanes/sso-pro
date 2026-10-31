const { z } = require('zod');
const asyncHandler = require('../../utils/asyncHandler');
const ApiError = require('../../utils/ApiError');
const adminService = require('./admin.service');

const idSchema = z.string().uuid();
const emailSchema = z.object({ email: z.string().trim().toLowerCase().email('Enter a valid email address').max(150) });

const contextOf = (req) => ({ ip: req.ip });

const backToList = { href: '/admin/users', label: 'Back to users' };

const renderNotFound = (res) =>
  res.status(404).render('message', { title: 'Not found', message: 'This account does not exist.', tone: 'error', link: backToList });

const renderUser = (req, res, target, extra = {}) => {
  const { status = 200, ...locals } = extra;
  res.status(status).render('admin-user', {
    target,
    canManage: adminService.canManage(req.admin, target),
    emailValue: target.email,
    link: null,
    expiresAt: null,
    notice: null,
    error: null,
    errors: {},
    ...locals,
  });
};

// Sends the 404 page itself and returns null when the id is not an account
const loadTarget = async (req, res) => {
  const id = idSchema.safeParse(req.params.id);
  if (!id.success) {
    renderNotFound(res);
    return null;
  }

  try {
    return await adminService.getUser(id.data);
  } catch (error) {
    if (!(error instanceof ApiError && error.statusCode === 404)) throw error;
    renderNotFound(res);
    return null;
  }
};

const list = asyncHandler(async (req, res) => {
  const q = String(req.query.q ?? '').trim().slice(0, 100);
  const notice = req.query.deleted === '1' ? 'Account deleted. It can no longer log in.' : null;
  res.render('admin-users', { q, people: await adminService.search(q), notice });
});

const showUser = asyncHandler(async (req, res) => {
  const target = await loadTarget(req, res);
  if (target) renderUser(req, res, target);
});

const resetLink = asyncHandler(async (req, res) => {
  const target = await loadTarget(req, res);
  if (!target) return;

  try {
    const { link, expiresAt } = await adminService.createResetLink(req.admin, target, contextOf(req));
    renderUser(req, res, target, { link, expiresAt });
  } catch (error) {
    if (!(error instanceof ApiError)) throw error;
    renderUser(req, res, target, { status: error.statusCode, error: error.message });
  }
});

const changeEmail = asyncHandler(async (req, res) => {
  const target = await loadTarget(req, res);
  if (!target) return;

  const parsed = emailSchema.safeParse(req.body);
  if (!parsed.success) {
    renderUser(req, res, target, { status: 422, errors: { email: parsed.error.issues[0].message }, emailValue: req.body.email || '' });
    return;
  }

  try {
    const updated = await adminService.changeEmail(req.admin, target, parsed.data.email, contextOf(req));
    renderUser(req, res, updated, { notice: `Email changed to ${updated.email}. The account was logged out everywhere.` });
  } catch (error) {
    if (!(error instanceof ApiError)) throw error;
    renderUser(req, res, target, { status: error.statusCode, error: error.message, emailValue: parsed.data.email });
  }
});

// The administrator has to type the account's email, so a stray click cannot delete anyone
const remove = asyncHandler(async (req, res) => {
  const target = await loadTarget(req, res);
  if (!target) return;

  const typed = String(req.body?.confirm ?? '').trim().toLowerCase();
  if (typed !== target.email.toLowerCase()) {
    renderUser(req, res, target, { status: 422, error: 'The email you typed does not match. Nothing was deleted.' });
    return;
  }

  try {
    await adminService.deleteUser(req.admin, target, contextOf(req));
    res.redirect('/admin/users?deleted=1');
  } catch (error) {
    if (!(error instanceof ApiError)) throw error;
    renderUser(req, res, target, { status: error.statusCode, error: error.message });
  }
});

module.exports = { list, showUser, resetLink, changeEmail, remove };
