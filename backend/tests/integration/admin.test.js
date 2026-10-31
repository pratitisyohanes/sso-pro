const crypto = require('crypto');
const request = require('supertest');

process.env.PUBLIC_URL = 'https://sso.test';

jest.mock('../../src/ldap/ldap.gateway', () => ({
  verifyCredentials: jest.fn(),
  findById: jest.fn(),
  findByEmail: jest.fn(),
  searchPeople: jest.fn(),
  createPerson: jest.fn(),
  updatePerson: jest.fn(),
  deletePerson: jest.fn(),
  checkPassword: jest.fn(),
  setAccess: jest.fn(),
  ping: jest.fn(),
}));

jest.mock('../../src/utils/mailer', () => ({ sendPasswordReset: jest.fn(), sendPasswordChanged: jest.fn() }));

jest.mock('../../src/models', () => ({
  sequelize: { authenticate: jest.fn() },
  Client: { findByPk: jest.fn(), findAll: jest.fn().mockResolvedValue([]) },
  AuthEvent: { create: jest.fn() },
  SsoSession: { findOne: jest.fn(), findByPk: jest.fn(), create: jest.fn(), destroy: jest.fn() },
  AuthorizationCode: { create: jest.fn(), findByPk: jest.fn(), destroy: jest.fn() },
  RefreshToken: { create: jest.fn(), findOne: jest.fn(), update: jest.fn(), destroy: jest.fn() },
  MfaFactor: { findByPk: jest.fn(), create: jest.fn(), destroy: jest.fn() },
  PasswordReset: { count: jest.fn(), update: jest.fn(), create: jest.fn(), findOne: jest.fn(), destroy: jest.fn() },
}));

const ldap = require('../../src/ldap/ldap.gateway');
const { AuthEvent, AuthorizationCode, MfaFactor, PasswordReset, RefreshToken, SsoSession } = require('../../src/models');
const app = require('../../src/app');

const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');

const person = (suffix, values) => ({ id: `0a000000-0000-4000-8000-0000000000${suffix}`, phone: null, disabled: false, ...values });
const admin = person('01', { name: 'Admin Booking', email: 'admin@example.com', role: 'ADMIN' });
const otherAdmin = person('09', { name: 'Second Admin', email: 'second@example.com', role: 'ADMIN' });
const budi = person('02', { name: 'Budi Santoso', email: 'budi@example.com', role: 'USER', phone: '081234567890' });
const siti = person('03', { name: 'Siti Aminah', email: 'siti@example.com', role: 'USER', disabled: true });
const directory = Object.fromEntries([admin, otherAdmin, budi, siti].map((account) => [account.id, account]));

const sessionOf = (account, values = {}) => ({
  id: '11111111-1111-4111-8111-111111111111',
  userId: account.id,
  name: account.name,
  email: account.email,
  role: account.role,
  stage: 'ACTIVE',
  expiresAt: new Date(Date.now() + 60 * 60 * 1000),
  isActive() {
    return this.stage === 'ACTIVE' && this.expiresAt > new Date();
  },
  ...values,
});

const loginAs = (account, values) => SsoSession.findOne.mockResolvedValue(sessionOf(account, values));
const withSession = (req) => req.set('Cookie', 'kid_sid=session-id');

// A page visit gives the CSRF cookie that every form post must send back
const csrf = async () => {
  const page = await withSession(request(app).get('/admin/users'));
  const cookie = page.headers['set-cookie'].find((value) => value.startsWith('kid_csrf=')).split(';')[0];
  return { cookie, token: cookie.split('=')[1] };
};

const post = async (path, fields) => {
  const { cookie, token } = await csrf();
  return request(app).post(path).set('Cookie', [cookie, 'kid_sid=session-id']).type('form').send({ _csrf: token, ...fields });
};

beforeEach(() => {
  jest.clearAllMocks();
  ldap.findById.mockImplementation(async (id) => directory[id] || null);
  ldap.findByEmail.mockResolvedValue(null);
  ldap.searchPeople.mockResolvedValue([admin, budi, siti]);
  ldap.updatePerson.mockImplementation(async (id, changes) => ({ ...directory[id], ...changes }));
  PasswordReset.update.mockResolvedValue([1]);
});

describe('who may open the admin pages', () => {
  test('someone not logged in is sent to the login page', async () => {
    const res = await request(app).get('/admin/users');
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/login');
    expect(ldap.searchPeople).not.toHaveBeenCalled();
  });

  test('a customer is refused', async () => {
    loginAs(budi);
    const res = await withSession(request(app).get('/admin/users'));
    expect(res.status).toBe(403);
    expect(ldap.searchPeople).not.toHaveBeenCalled();
  });

  test('an administrator who was demoted after logging in is refused', async () => {
    loginAs(budi, { role: 'ADMIN' });
    const res = await withSession(request(app).get('/admin/users'));
    expect(res.status).toBe(403);
  });

  test('an administrator who was deactivated after logging in is refused', async () => {
    loginAs({ ...admin }, {});
    ldap.findById.mockImplementation(async (id) => (id === admin.id ? { ...admin, disabled: true } : directory[id] || null));
    const res = await withSession(request(app).get('/admin/users'));
    expect(res.status).toBe(403);
  });

  test('a half-finished login (second factor still to do) is not enough', async () => {
    loginAs(admin, { stage: 'MFA_VERIFY' });
    const res = await withSession(request(app).get('/admin/users'));
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/login');
  });

  test('the home page offers "Manage users" to administrators only', async () => {
    loginAs(admin);
    const asAdmin = await withSession(request(app).get('/'));
    expect(asAdmin.text).toContain('href="/admin/users"');

    loginAs(budi);
    const asCustomer = await withSession(request(app).get('/'));
    expect(asCustomer.text).not.toContain('/admin/users');
  });
});

describe('finding an account', () => {
  beforeEach(() => loginAs(admin));

  test('lists accounts and passes the search text on', async () => {
    const res = await withSession(request(app).get('/admin/users').query({ q: 'bud' }));
    expect(res.status).toBe(200);
    expect(ldap.searchPeople).toHaveBeenCalledWith('bud');
    expect(res.text).toContain('Budi Santoso');
    expect(res.text).toContain('deactivated');
    expect(res.text).toContain(`/admin/users/${budi.id}`);
  });

  test('says so when nothing matches', async () => {
    ldap.searchPeople.mockResolvedValue([]);
    const res = await withSession(request(app).get('/admin/users').query({ q: 'zzz' }));
    expect(res.text).toContain('No account matches');
  });

  test('an id that is not an account gives a 404 page', async () => {
    const unknown = await withSession(request(app).get('/admin/users/0a000000-0000-4000-8000-0000000000ff'));
    expect(unknown.status).toBe(404);
    const garbage = await withSession(request(app).get('/admin/users/not-an-id'));
    expect(garbage.status).toBe(404);
  });
});

describe('reset link', () => {
  beforeEach(() => loginAs(admin));

  test('shows a one-time link for a customer and keeps only its hash', async () => {
    const res = await post(`/admin/users/${budi.id}/reset-link`);
    expect(res.status).toBe(200);

    const link = res.text.match(/value="(https:\/\/sso\.test\/reset\?token=[^"]+)"/)[1];
    const token = new URL(link.replace(/&#34;/g, '"')).searchParams.get('token');
    expect(PasswordReset.create).toHaveBeenCalledWith(expect.objectContaining({ userId: budi.id, tokenHash: sha256(token) }));
    expect(JSON.stringify(PasswordReset.create.mock.calls)).not.toContain(token);

    const minutes = (PasswordReset.create.mock.calls[0][0].expiresAt.getTime() - Date.now()) / 60000;
    expect(minutes).toBeGreaterThan(59);
    expect(minutes).toBeLessThanOrEqual(60);
  });

  test('is written to the audit log with the administrator who made it', async () => {
    await post(`/admin/users/${budi.id}/reset-link`);
    expect(AuthEvent.create).toHaveBeenCalledWith(expect.objectContaining({ action: 'ADMIN_RESET_LINK', userId: budi.id, username: 'budi@example.com by admin@example.com' }));
  });

  test('another administrator cannot be reset from here', async () => {
    const res = await post(`/admin/users/${otherAdmin.id}/reset-link`);
    expect(res.status).toBe(403);
    expect(res.text).toContain('reset on the server');
    expect(PasswordReset.create).not.toHaveBeenCalled();
  });

  test('an administrator can reset their own account', async () => {
    const res = await post(`/admin/users/${admin.id}/reset-link`);
    expect(res.status).toBe(200);
    expect(PasswordReset.create).toHaveBeenCalledWith(expect.objectContaining({ userId: admin.id }));
  });

  test('a deactivated account gets no link', async () => {
    const res = await post(`/admin/users/${siti.id}/reset-link`);
    expect(res.status).toBe(400);
    expect(PasswordReset.create).not.toHaveBeenCalled();
  });

  test('a post without the CSRF token is refused', async () => {
    const res = await withSession(request(app).post(`/admin/users/${budi.id}/reset-link`).type('form').send({}));
    expect(res.status).toBe(403);
    expect(PasswordReset.create).not.toHaveBeenCalled();
  });
});

describe('change email', () => {
  beforeEach(() => loginAs(admin));

  test('saves the new address in lower case and logs the account out everywhere', async () => {
    const res = await post(`/admin/users/${budi.id}/email`, { email: 'Budi.New@Example.com' });
    expect(res.status).toBe(200);
    expect(res.text).toContain('Email changed to budi.new@example.com');
    expect(ldap.updatePerson).toHaveBeenCalledWith(budi.id, { email: 'budi.new@example.com' });
    expect(SsoSession.destroy).toHaveBeenCalledWith({ where: { userId: budi.id } });
    expect(AuthEvent.create).toHaveBeenCalledWith(expect.objectContaining({ action: 'ADMIN_CHANGE_EMAIL', userId: budi.id }));
  });

  test('an address used by another account is refused', async () => {
    ldap.findByEmail.mockResolvedValue(siti);
    const res = await post(`/admin/users/${budi.id}/email`, { email: siti.email });
    expect(res.status).toBe(409);
    expect(res.text).toContain('already used by another account');
    expect(ldap.updatePerson).not.toHaveBeenCalled();
    expect(SsoSession.destroy).not.toHaveBeenCalled();
  });

  test('the address the account already has is refused', async () => {
    const res = await post(`/admin/users/${budi.id}/email`, { email: budi.email });
    expect(res.status).toBe(400);
    expect(ldap.updatePerson).not.toHaveBeenCalled();
  });

  test('something that is not an email keeps the form and changes nothing', async () => {
    const res = await post(`/admin/users/${budi.id}/email`, { email: 'not-an-email' });
    expect(res.status).toBe(422);
    expect(res.text).toContain('Enter a valid email address');
    expect(ldap.updatePerson).not.toHaveBeenCalled();
  });

  test('another administrator cannot be changed from here', async () => {
    const res = await post(`/admin/users/${otherAdmin.id}/email`, { email: 'taken.over@example.com' });
    expect(res.status).toBe(403);
    expect(ldap.updatePerson).not.toHaveBeenCalled();
  });

  test('another administrator shows instructions instead of the forms', async () => {
    const res = await withSession(request(app).get(`/admin/users/${otherAdmin.id}`));
    expect(res.status).toBe(200);
    expect(res.text).toContain('npm run user:reset-link');
    expect(res.text).not.toContain('Create reset link');
  });
});

describe('delete account', () => {
  beforeEach(() => loginAs(admin));

  const remove = (target, confirm) => post(`/admin/users/${target.id}/delete`, { confirm });

  test('removes the login and everything KandangID holds about the account', async () => {
    const res = await remove(budi, 'Budi@Example.com');
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/admin/users?deleted=1');

    expect(ldap.deletePerson).toHaveBeenCalledWith(budi.id);
    const byUser = { where: { userId: budi.id } };
    expect(RefreshToken.destroy).toHaveBeenCalledWith(byUser);
    expect(AuthorizationCode.destroy).toHaveBeenCalledWith(byUser);
    expect(SsoSession.destroy).toHaveBeenCalledWith(byUser);
    expect(PasswordReset.destroy).toHaveBeenCalledWith(byUser);
    expect(MfaFactor.destroy).toHaveBeenCalledWith(byUser);
  });

  test('is written to the audit log with the administrator who did it', async () => {
    await remove(budi, budi.email);
    expect(AuthEvent.create).toHaveBeenCalledWith(expect.objectContaining({ action: 'ADMIN_DELETE_USER', userId: budi.id, username: 'budi@example.com by admin@example.com' }));
  });

  test('a wrong or empty confirmation deletes nothing', async () => {
    const wrong = await remove(budi, 'siti@example.com');
    expect(wrong.status).toBe(422);
    expect(wrong.text).toContain('does not match');
    const empty = await remove(budi, '');
    expect(empty.status).toBe(422);
    expect(ldap.deletePerson).not.toHaveBeenCalled();
    expect(SsoSession.destroy).not.toHaveBeenCalled();
  });

  test('administrators cannot be deleted from the page, not even the one logged in', async () => {
    const other = await remove(otherAdmin, otherAdmin.email);
    expect(other.status).toBe(403);
    const self = await remove(admin, admin.email);
    expect(self.status).toBe(403);
    expect(ldap.deletePerson).not.toHaveBeenCalled();
  });

  test('if the directory refuses, nothing else is cleared and the page says so', async () => {
    ldap.deletePerson.mockRejectedValueOnce(new Error('insufficient access'));
    const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
    const res = await remove(budi, budi.email);
    spy.mockRestore();

    expect(res.status).toBe(503);
    expect(res.text).toContain('Nothing was changed');
    expect(SsoSession.destroy).not.toHaveBeenCalled();
    expect(AuthEvent.create).not.toHaveBeenCalled();
  });

  test('a post without the CSRF token is refused', async () => {
    const res = await withSession(request(app).post(`/admin/users/${budi.id}/delete`).type('form').send({ confirm: budi.email }));
    expect(res.status).toBe(403);
    expect(ldap.deletePerson).not.toHaveBeenCalled();
  });

  test('a customer who is not an administrator cannot reach it', async () => {
    loginAs(budi);
    const res = await post(`/admin/users/${siti.id}/delete`, { confirm: siti.email });
    expect(res.status).toBe(403);
    expect(ldap.deletePerson).not.toHaveBeenCalled();
  });

  test('the form is on a customer page but not on an administrator page', async () => {
    const customer = await withSession(request(app).get(`/admin/users/${budi.id}`));
    expect(customer.text).toContain('Delete account');
    expect(customer.text).toContain(`/admin/users/${budi.id}/delete`);

    const adminPage = await withSession(request(app).get(`/admin/users/${otherAdmin.id}`));
    expect(adminPage.text).not.toContain('Delete account');
    const own = await withSession(request(app).get(`/admin/users/${admin.id}`));
    expect(own.text).not.toContain('Delete account');
  });

  test('the list shows a confirmation after a deletion', async () => {
    const res = await withSession(request(app).get('/admin/users').query({ deleted: '1' }));
    expect(res.text).toContain('Account deleted');
    const plain = await withSession(request(app).get('/admin/users'));
    expect(plain.text).not.toContain('Account deleted');
  });
});
