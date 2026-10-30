const env = require('../config/env');
const { SsoSession } = require('../models');
const { sha256 } = require('../utils/randomToken');

const COOKIE = 'kid_sid';

const cookieOptions = (maxAgeMs) => ({ httpOnly: true, secure: env.COOKIE_SECURE, sameSite: 'lax', path: '/', maxAge: maxAgeMs });

const setSessionCookie = (res, sid, maxAgeMs) => res.cookie(COOKIE, sid, cookieOptions(maxAgeMs));

const clearSessionCookie = (res) => res.clearCookie(COOKIE, { httpOnly: true, secure: env.COOKIE_SECURE, sameSite: 'lax', path: '/' });

// Attach req.ssoSession when the browser carries a valid, unexpired KandangID cookie
const loadSession = async (req, res, next) => {
  try {
    const sid = req.cookies?.[COOKIE];
    if (!sid) return next();

    const session = await SsoSession.findOne({ where: { sidHash: sha256(sid) } });
    if (!session || session.expiresAt <= new Date()) {
      clearSessionCookie(res);
      return next();
    }
    req.ssoSession = session;
    return next();
  } catch (error) {
    return next(error);
  }
};

module.exports = { loadSession, setSessionCookie, clearSessionCookie };
