// Administrator creates a one-time reset link for someone who forgot their password and email is not set up.
// The owner opens the link and chooses the new password, so the administrator never learns it.
// Usage: npm run user:reset-link -- someone@example.com [minutes]
const ldap = require('../src/ldap/ldap.gateway');
const { sequelize } = require('../src/models');
const audit = require('../src/utils/audit');
const passwordService = require('../src/modules/login/password.service');

const DEFAULT_MINUTES = 60;
const MAX_MINUTES = 24 * 60;

const run = async () => {
  const [email, minutesArg] = process.argv.slice(2);
  const minutes = minutesArg ? Number(minutesArg) : DEFAULT_MINUTES;

  if (!email || !Number.isInteger(minutes) || minutes < 5 || minutes > MAX_MINUTES) {
    console.error(`Usage: npm run user:reset-link -- <email> [minutes between 5 and ${MAX_MINUTES}, default ${DEFAULT_MINUTES}]`);
    process.exit(1);
  }

  const account = await ldap.findByEmail(email);
  if (!account) {
    console.error(`No account has the email ${email}`);
    process.exit(1);
  }
  if (account.disabled) {
    console.error(`${account.email} is deactivated; re-activate it before resetting the password`);
    process.exit(1);
  }

  const { link, expiresAt } = await passwordService.createResetLink(account, { minutes });
  await audit({ action: 'PASSWORD_RESET_LINK', result: 'ADMIN', username: account.email, userId: account.id });

  console.log(`Reset link for ${account.name} <${account.email}>`);
  console.log(`Works once, until ${expiresAt.toLocaleString()}:`);
  console.log('');
  console.log(link);
  console.log('');
  console.log('Send it only to the owner of the account. Older links for this account no longer work.');
};

run()
  .catch((error) => {
    console.error('Failed to create the link:', error.message);
    process.exitCode = 1;
  })
  .finally(() => sequelize.close());
