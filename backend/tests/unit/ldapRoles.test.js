const { toAccess, roleGroup } = require('../../src/ldap/ldap.roles');

describe('LDAP groups to application access', () => {
  test('cn=admins gives ADMIN', () => {
    expect(toAccess(['admins'])).toEqual({ role: 'ADMIN', disabled: false });
  });

  test('anyone else is USER', () => {
    expect(toAccess(['customers'])).toEqual({ role: 'USER', disabled: false });
    expect(toAccess([])).toEqual({ role: 'USER', disabled: false });
  });

  test('cn=disabled marks the account disabled whatever the role', () => {
    expect(toAccess(['admins', 'disabled'])).toEqual({ role: 'ADMIN', disabled: true });
  });

  test('role maps back to its group', () => {
    expect(roleGroup('ADMIN')).toBe('admins');
    expect(roleGroup('USER')).toBe('customers');
  });
});
