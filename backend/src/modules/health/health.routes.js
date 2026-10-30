const router = require('express').Router();
const asyncHandler = require('../../utils/asyncHandler');
const { sequelize } = require('../../models');
const ldap = require('../../ldap/ldap.gateway');

const check = (promise) =>
  promise.then(
    () => 'up',
    () => 'down',
  );

// Used by the CI health check: 200 only when both the database and the directory answer
router.get(
  '/',
  asyncHandler(async (req, res) => {
    const [database, directory] = await Promise.all([check(sequelize.authenticate()), check(ldap.ping())]);
    const ok = database === 'up' && directory === 'up';
    res.status(ok ? 200 : 503).json({
      success: ok,
      message: ok ? 'OK' : 'Dependency down',
      data: { database, directory, uptime: Math.round(process.uptime()) },
    });
  }),
);

module.exports = router;
