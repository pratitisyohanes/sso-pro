const { Client, EqualityFilter, OrFilter, PresenceFilter, SubstringFilter, Change, Attribute, InvalidCredentialsError } = require('ldapts');
const env = require('../config/env');
const { GROUPS, toAccess, roleGroup } = require('./ldap.roles');

const PEOPLE = `ou=people,${env.LDAP_BASE_DN}`;
const GROUP_BASE = `ou=groups,${env.LDAP_BASE_DN}`;
const PERSON_ATTRIBUTES = ['uid', 'cn', 'mail', 'telephoneNumber'];

const userDn = (uid) => `uid=${uid},${PEOPLE}`;
const groupDn = (name) => `cn=${name},${GROUP_BASE}`;

// ldapts returns a string or an array depending on how many values an attribute has
const first = (value) => (Array.isArray(value) ? value[0] : value);

// One connection per operation, because a bind changes who the connection acts as
const withClient = async (work) => {
  const client = new Client({ url: env.LDAP_URL, timeout: env.LDAP_TIMEOUT_MS, connectTimeout: env.LDAP_TIMEOUT_MS });
  try {
    return await work(client);
  } finally {
    await client.unbind().catch(() => {});
  }
};

const bindService = (client) => client.bind(env.LDAP_BIND_DN, env.LDAP_BIND_PASSWORD);

// EqualityFilter escapes * ( ) \ so user input can never change the filter (no LDAP injection)
const findPerson = async (client, attribute, value) => {
  const { searchEntries } = await client.search(PEOPLE, {
    scope: 'one',
    filter: new EqualityFilter({ attribute, value }),
    attributes: PERSON_ATTRIBUTES,
  });
  return searchEntries.length === 1 ? searchEntries[0] : null;
};

const readGroups = async (client, dn) => {
  const { searchEntries } = await client.search(GROUP_BASE, {
    scope: 'one',
    filter: new EqualityFilter({ attribute: 'member', value: dn }),
    attributes: ['cn'],
  });
  return searchEntries.map((group) => first(group.cn));
};

const toAccount = (entry, groupNames) => ({
  id: first(entry.uid),
  name: first(entry.cn),
  email: first(entry.mail),
  phone: first(entry.telephoneNumber) || null,
  ...toAccess(groupNames),
});

const loadAccount = async (client, entry) => toAccount(entry, await readGroups(client, entry.dn));

// Search-then-bind: find the DN with the service account, then bind as the user to prove the password
const verifyCredentials = (email, password) => {
  // An empty password is an "unauthenticated bind", which LDAP reports as a success
  if (!email || !password) return Promise.resolve(null);

  return withClient(async (client) => {
    await bindService(client);
    const entry = await findPerson(client, 'mail', email.trim().toLowerCase());
    if (!entry) return null;

    try {
      await client.bind(entry.dn, password);
    } catch (error) {
      if (error instanceof InvalidCredentialsError) return null;
      throw error;
    }

    // A normal user may not read ou=groups, so switch back to the service account
    await bindService(client);
    return loadAccount(client, entry);
  });
};

const findById = (uid) =>
  withClient(async (client) => {
    await bindService(client);
    const entry = await findPerson(client, 'uid', uid);
    return entry ? loadAccount(client, entry) : null;
  });

const findByEmail = (email) =>
  withClient(async (client) => {
    await bindService(client);
    const entry = await findPerson(client, 'mail', email.trim().toLowerCase());
    return entry ? loadAccount(client, entry) : null;
  });

const lastName = (name) => name.trim().split(/\s+/).pop();

const memberChange = (operation, dn) => new Change({ operation, modification: new Attribute({ type: 'member', values: [dn] }) });

// New accounts always join cn=customers; a role is never taken from the caller (lesson from ERM register)
const createPerson = ({ id, name, email, phone, passwordHash }) =>
  withClient(async (client) => {
    await bindService(client);
    const dn = userDn(id);
    await client.add(dn, {
      objectClass: ['inetOrgPerson'],
      uid: id,
      cn: name,
      sn: lastName(name),
      mail: email,
      userPassword: passwordHash,
      ...(phone && { telephoneNumber: phone }),
    });
    await client.modify(groupDn(GROUPS.CUSTOMERS), [memberChange('add', dn)]);
    return loadAccount(client, { dn, uid: id, cn: name, mail: email, telephoneNumber: phone });
  });

// replace with an empty value list removes the attribute, which clears the phone number
const updatePerson = (uid, { name, phone, email, passwordHash }) =>
  withClient(async (client) => {
    await bindService(client);
    const changes = [];
    if (email !== undefined) {
      changes.push(new Change({ operation: 'replace', modification: new Attribute({ type: 'mail', values: [email] }) }));
    }
    if (name !== undefined) {
      changes.push(new Change({ operation: 'replace', modification: new Attribute({ type: 'cn', values: [name] }) }));
      changes.push(new Change({ operation: 'replace', modification: new Attribute({ type: 'sn', values: [lastName(name)] }) }));
    }
    if (phone !== undefined) {
      changes.push(new Change({ operation: 'replace', modification: new Attribute({ type: 'telephoneNumber', values: phone ? [phone] : [] }) }));
    }
    if (passwordHash) {
      changes.push(new Change({ operation: 'replace', modification: new Attribute({ type: 'userPassword', values: [passwordHash] }) }));
    }
    if (changes.length) await client.modify(userDn(uid), changes);

    const entry = await findPerson(client, 'uid', uid);
    return loadAccount(client, entry);
  });

// Checks the current password with a bind, without changing anything
const checkPassword = (uid, password) => {
  if (!password) return Promise.resolve(false);
  return withClient(async (client) => {
    try {
      await client.bind(userDn(uid), password);
      return true;
    } catch (error) {
      if (error instanceof InvalidCredentialsError) return false;
      throw error;
    }
  });
};

// Move the user between groups; only adds or removes what actually changes
const setAccess = (uid, { role, disabled }) =>
  withClient(async (client) => {
    await bindService(client);
    const dn = userDn(uid);
    const current = await readGroups(client, dn);
    const wanted = new Set(current);

    if (role) {
      wanted.delete(GROUPS.ADMINS);
      wanted.delete(GROUPS.CUSTOMERS);
      wanted.add(roleGroup(role));
    }
    if (disabled === true) wanted.add(GROUPS.DISABLED);
    if (disabled === false) wanted.delete(GROUPS.DISABLED);

    for (const name of wanted) {
      if (!current.includes(name)) await client.modify(groupDn(name), [memberChange('add', dn)]);
    }
    for (const name of current) {
      if (!wanted.has(name)) await client.modify(groupDn(name), [memberChange('delete', dn)]);
    }

    const entry = await findPerson(client, 'uid', uid);
    return loadAccount(client, entry);
  });

// Removes the account. The entry goes first, because that is what stops the login; the group memberships are tidied afterwards.
// A groupOfNames must keep one member, so the last member of a group cannot be removed; that leftover reference is harmless
const deletePerson = (uid) =>
  withClient(async (client) => {
    await bindService(client);
    const dn = userDn(uid);
    const groups = await readGroups(client, dn);

    await client.del(dn);

    for (const name of groups) {
      try {
        await client.modify(groupDn(name), [memberChange('delete', dn)]);
      } catch (error) {
        console.error(`Could not remove ${dn} from group ${name}:`, error.message);
      }
    }
  });

// Administrator search: part of a name or email (empty lists everyone), sorted by name and cut to `limit`.
// SubstringFilter escapes * ( ) \ in the term, so it cannot change the filter
const searchPeople = (term, limit = 20) =>
  withClient(async (client) => {
    await bindService(client);
    const text = term.trim();
    const filter = text
      ? new OrFilter({ filters: [new SubstringFilter({ attribute: 'mail', any: [text] }), new SubstringFilter({ attribute: 'cn', any: [text] })] })
      : new PresenceFilter({ attribute: 'uid' });
    const { searchEntries } = await client.search(PEOPLE, { scope: 'one', filter, attributes: PERSON_ATTRIBUTES });

    const sorted = searchEntries.sort((a, b) => String(first(a.cn)).localeCompare(String(first(b.cn))));
    return Promise.all(sorted.slice(0, limit).map((entry) => loadAccount(client, entry)));
  });

// Health check: can the service account still bind?
const ping = () => withClient(bindService);

module.exports = { verifyCredentials, findById, findByEmail, searchPeople, createPerson, updatePerson, deletePerson, checkPassword, setAccess, ping };
