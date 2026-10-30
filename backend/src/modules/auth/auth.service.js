const ldap = require('../../ldap/ldap.gateway');
const audit = require('../../utils/audit');

// Wrong email and wrong password give the same answer so nobody can probe which emails exist
const RESULTS = { SUCCESS: 'SUCCESS', INVALID: 'INVALID_CREDENTIALS', DISABLED: 'DISABLED' };

// A business "no" is still HTTP 200 with login: false; 4xx/5xx is kept for setup problems
const validate = async ({ username, password }, { client, ip }) => {
  const account = await ldap.verifyCredentials(username, password);

  let result = RESULTS.SUCCESS;
  if (!account) result = RESULTS.INVALID;
  else if (account.disabled) result = RESULTS.DISABLED;

  await audit({ client, action: 'VALIDATE', result, username, userId: account?.id, ip });

  if (result !== RESULTS.SUCCESS) return { login: false, reason: result };
  const { disabled, ...user } = account;
  return { login: true, user };
};

module.exports = { validate, RESULTS };
