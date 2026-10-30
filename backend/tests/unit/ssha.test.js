const { hashSsha, verifySsha } = require('../../src/utils/ssha');

describe('SSHA password hash', () => {
  test('uses the {SSHA} prefix slapd understands', () => {
    expect(hashSsha('User12345')).toMatch(/^\{SSHA\}[A-Za-z0-9+/]+=*$/);
  });

  test('random salt gives a different hash for the same password', () => {
    expect(hashSsha('User12345')).not.toBe(hashSsha('User12345'));
  });

  test('verifies the right password only', () => {
    const hashed = hashSsha('User12345');
    expect(verifySsha('User12345', hashed)).toBe(true);
    expect(verifySsha('User12346', hashed)).toBe(false);
  });
});
