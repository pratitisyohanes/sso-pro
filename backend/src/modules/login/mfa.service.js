const { authenticator } = require('otplib');
const QRCode = require('qrcode');
const { MfaFactor } = require('../../models');
const env = require('../../config/env');
const { encrypt, decrypt } = require('../../utils/secretBox');

// Accept the previous, current and next 30-second code to allow for clock drift on the phone
authenticator.options = { window: 1 };

const STEP_MS = 30 * 1000;

const findFactor = (userId) => MfaFactor.findByPk(userId);

// Returns the accepted 30-second step, or null; a step at or before the last one is a replayed code
const acceptCode = (factor, code) => {
  const delta = authenticator.checkDelta(code, decrypt(factor.secret));
  if (delta === null) return null;
  const step = Math.floor(Date.now() / STEP_MS) + delta;
  if (factor.lastStep !== null && factor.lastStep !== undefined && step <= Number(factor.lastStep)) return null;
  return step;
};

// Setup keeps one pending secret per user, so reloading the page shows the same QR code
const pendingSetup = async (session) => {
  let factor = await findFactor(session.userId);
  if (!factor) factor = await MfaFactor.create({ userId: session.userId, secret: encrypt(authenticator.generateSecret()), enabled: false });

  const secret = decrypt(factor.secret);
  const otpauthUrl = authenticator.keyuri(session.email, env.MFA_ISSUER, secret);
  return { secret, qrCode: await QRCode.toDataURL(otpauthUrl) };
};

// true when the code is right; also switches the factor on during setup
const checkCode = async (session, code) => {
  const factor = await findFactor(session.userId);
  if (!factor) return false;
  const step = acceptCode(factor, code);
  if (step === null) return false;

  await factor.update({ lastStep: step, ...(!factor.enabled && { enabled: true, setupAt: new Date() }) });
  return true;
};

module.exports = { findFactor, pendingSetup, checkCode };
