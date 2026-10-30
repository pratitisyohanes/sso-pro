// Group names under ou=groups and what they mean for every application
const GROUPS = {
  ADMINS: 'admins',
  CUSTOMERS: 'customers',
  DISABLED: 'disabled',
};

// Directory groups decide access, the same way office accounts get rights from AD/LDAP groups
const toAccess = (groupNames = []) => ({
  role: groupNames.includes(GROUPS.ADMINS) ? 'ADMIN' : 'USER',
  disabled: groupNames.includes(GROUPS.DISABLED),
});

const roleGroup = (role) => (role === 'ADMIN' ? GROUPS.ADMINS : GROUPS.CUSTOMERS);

module.exports = { GROUPS, toAccess, roleGroup };
