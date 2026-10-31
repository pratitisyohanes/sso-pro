const ldap = require('../ldap/ldap.gateway');

// Admin pages need a finished login (including the second factor), and the directory must still say ADMIN:
// the role copied into the session at login is not trusted, so a demoted or deactivated admin loses access at once
const requireAdmin = async (req, res, next) => {
  try {
    const session = req.ssoSession?.isActive() ? req.ssoSession : null;
    if (!session) return res.redirect('/login');

    const account = await ldap.findById(session.userId);
    if (!account || account.disabled || account.role !== 'ADMIN') {
      return res.status(403).render('message', {
        title: 'Not allowed',
        message: 'Only administrators can open this page.',
        tone: 'error',
      });
    }

    req.admin = account;
    return next();
  } catch (error) {
    return next(error);
  }
};

module.exports = { requireAdmin };
