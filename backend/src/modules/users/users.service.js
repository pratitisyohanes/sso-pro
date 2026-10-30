const crypto = require('crypto');
const ldap = require('../../ldap/ldap.gateway');
const ApiError = require('../../utils/ApiError');
const audit = require('../../utils/audit');
const { hashSsha } = require('../../utils/ssha');

const findOrFail = async (id) => {
  const account = await ldap.findById(id);
  if (!account) throw ApiError.notFound('User not found in the directory');
  return account;
};

const getUser = (id) => findOrFail(id);

// Register: the password is hashed here, so slapd never receives or stores it in plain text
const createUser = async ({ id = crypto.randomUUID(), name, email, phone, password }, context) => {
  if (await ldap.findByEmail(email)) throw ApiError.conflict('Email is already registered');
  if (await ldap.findById(id)) throw ApiError.conflict('User id is already taken');

  const account = await ldap.createPerson({ id, name, email, phone, passwordHash: hashSsha(password) });
  await audit({ ...context, action: 'CREATE_USER', result: 'SUCCESS', username: email, userId: id });
  return account;
};

// A new password needs the current one, checked by binding as the user
const updateUser = async (id, { name, phone, currentPassword, newPassword }, context) => {
  const account = await findOrFail(id);

  if (newPassword) {
    const isValid = await ldap.checkPassword(id, currentPassword);
    await audit({ ...context, action: 'CHANGE_PASSWORD', result: isValid ? 'SUCCESS' : 'INVALID_CREDENTIALS', username: account.email, userId: id });
    if (!isValid) throw ApiError.badRequest('Current password is incorrect');
  }

  return ldap.updatePerson(id, { name, phone, passwordHash: newPassword && hashSsha(newPassword) });
};

// Role and disabled are group memberships; only clients with users:admin may change them
const updateStatus = async (id, { role, disabled }, context) => {
  const account = await findOrFail(id);
  const updated = await ldap.setAccess(id, { role, disabled });
  await audit({ ...context, action: 'SET_ACCESS', result: 'SUCCESS', username: account.email, userId: id });
  return updated;
};

module.exports = { getUser, createUser, updateUser, updateStatus };
