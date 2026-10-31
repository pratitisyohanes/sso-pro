const ldap = require('../../ldap/ldap.gateway');
const { AuthorizationCode, MfaFactor, PasswordReset, RefreshToken } = require('../../models');
const ApiError = require('../../utils/ApiError');
const audit = require('../../utils/audit');
const passwordService = require('../login/password.service');

// Long enough to send the link by chat, short enough not to linger
const LINK_MINUTES = 60;

const getUser = async (id) => {
  const account = await ldap.findById(id);
  if (!account) throw ApiError.notFound('Account not found');
  return account;
};

const search = (term) => ldap.searchPeople(term);

// The web panel manages customers and the administrator's own account. Resetting another administrator needs
// access to the server (npm run user:reset-link), so one stolen admin login cannot take over the other admins
const canManage = (admin, target) => target.role !== 'ADMIN' || target.id === admin.id;

const assertManageable = (admin, target) => {
  if (!canManage(admin, target)) {
    throw ApiError.forbidden('Administrator accounts are reset on the server with: npm run user:reset-link');
  }
};

// The audit table has no column for who acted, so the administrator goes into the username text
const record = (admin, target, action, ip) =>
  audit({ action, result: 'SUCCESS', username: `${target.email} by ${admin.email}`.slice(0, 150), userId: target.id, ip });

// The owner opens the link and chooses the password; the administrator never sees it
const createResetLink = async (admin, target, { ip }) => {
  assertManageable(admin, target);
  if (target.disabled) throw ApiError.badRequest('This account is deactivated');

  const { link, expiresAt } = await passwordService.createResetLink(target, { minutes: LINK_MINUTES, ip });
  await record(admin, target, 'ADMIN_RESET_LINK', ip);
  return { link, expiresAt };
};

// Logging out everywhere afterwards: sessions and tokens still carry the old address
const changeEmail = async (admin, target, email, { ip }) => {
  assertManageable(admin, target);
  if (email === target.email) throw ApiError.badRequest('That is already the email of this account');

  const owner = await ldap.findByEmail(email);
  if (owner && owner.id !== target.id) throw ApiError.conflict('This email is already used by another account');

  const updated = await ldap.updatePerson(target.id, { email });
  await passwordService.endSessions(target.id);
  await record(admin, target, 'ADMIN_CHANGE_EMAIL', ip);
  return updated;
};

// Deleting removes the login for good. Booking keeps its own copy of the profile (its bookings point at it) and the audit log
// keeps its history, so only what KandangID itself holds about the account is cleared. Administrators are never deleted from the page
const deleteUser = async (admin, target, { ip }) => {
  if (target.role === 'ADMIN') throw ApiError.forbidden('Administrator accounts cannot be deleted from this page');

  try {
    await ldap.deletePerson(target.id);
  } catch (error) {
    console.error('The directory refused to delete an account:', error.message);
    throw new ApiError(503, 'The directory could not delete this account. Nothing was changed.');
  }

  // Codes and refresh tokens first: both point at the sessions that are removed next
  await RefreshToken.destroy({ where: { userId: target.id } });
  await AuthorizationCode.destroy({ where: { userId: target.id } });
  await passwordService.endSessions(target.id);
  await PasswordReset.destroy({ where: { userId: target.id } });
  await MfaFactor.destroy({ where: { userId: target.id } });
  await record(admin, target, 'ADMIN_DELETE_USER', ip);
};

module.exports = { getUser, search, canManage, createResetLink, changeEmail, deleteUser, LINK_MINUTES };
