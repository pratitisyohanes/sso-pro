const { SignJWT, decodeProtectedHeader } = require('jose');
const crypto = require('crypto');
const { signServiceToken, verifyServiceToken, secondsLeft } = require('../../src/utils/tokens');

describe('service token', () => {
  test('is RS256 with kid and carries the client and its scopes', async () => {
    const token = await signServiceToken({ id: 'booking-api', scopes: ['auth:validate', 'users:read'] });
    expect(decodeProtectedHeader(token)).toMatchObject({ alg: 'RS256', kid: expect.any(String) });

    const payload = await verifyServiceToken(token);
    expect(payload).toMatchObject({ sub: 'booking-api', aud: 'auth-service', scope: 'auth:validate users:read' });
    expect(secondsLeft(token)).toBe(900);
  });

  test('a token signed with another key is rejected', async () => {
    const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const forged = await new SignJWT({ scope: 'users:admin' })
      .setProtectedHeader({ alg: 'RS256' })
      .setIssuer('kandangid')
      .setSubject('attacker')
      .setAudience('auth-service')
      .setExpirationTime('5m')
      .sign(privateKey);
    await expect(verifyServiceToken(forged)).rejects.toThrow();
  });
});
