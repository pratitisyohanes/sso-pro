// Administrator reset of one account's password, for when the email reset is not available
// Usage (read -s hides what you type):
//   read -s -p "New password: " NEW_PASSWORD; echo
//   NEW_PASSWORD="$NEW_PASSWORD" npm run user:reset-password -- someone@example.com
const ldap = require('../src/ldap/ldap.gateway');
const { sequelize, SsoSession } = require('../src/models');
const audit = require('../src/utils/audit');
const { hashSsha } = require('../src/utils/ssha');
const { newPasswordRule } = require('../src/modules/login/login.schema');

const run = async () => {
  const email = process.argv[2];
  const password = process.env.NEW_PASSWORD;
  if (!email || !password) {
    console.error('Usage: NEW_PASSWORD="<password>" npm run user:reset-password -- <email>');
    process.exit(1);
  }

  const check = newPasswordRule.safeParse(password);
  if (!check.success) {
    console.error(check.error.issues[0].message);
    process.exit(1);
  }

  const account = await ldap.findByEmail(email);
  if (!account) {
    console.error(`No account has the email ${email}`);
    process.exit(1);
  }

  await ldap.updatePerson(account.id, { passwordHash: hashSsha(password) });
  // Deleting the sessions also deletes their refresh tokens, so every app asks for the new password
  await SsoSession.destroy({ where: { userId: account.id } });
  await audit({ action: 'PASSWORD_RESET', result: 'ADMIN', username: account.email, userId: account.id });

  console.log(`Password of ${account.email} changed; the account was logged out everywhere.`);
};

run()
  .catch((error) => {
    console.error('Failed to reset the password:', error.message);
    process.exitCode = 1;
  })
  .finally(() => sequelize.close());
