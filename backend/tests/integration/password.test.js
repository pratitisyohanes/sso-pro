const crypto = require('crypto');
const request = require('supertest');
const { Op } = require('sequelize');

// Email on, so the reset pages are open; set before the app loads its configuration
process.env.SMTP_HOST = 'smtp.test';
process.env.SMTP_USER = 'sender@test.com';
process.env.SMTP_PASSWORD = 'abcd efgh ijkl mnop';
process.env.PUBLIC_URL = 'https://sso.test';

jest.mock('../../src/ldap/ldap.gateway', () => ({
  verifyCredentials: jest.fn(),
  findById: jest.fn(),
  findByEmail: jest.fn(),
  createPerson: jest.fn(),
  updatePerson: jest.fn(),
  checkPassword: jest.fn(),
  setAccess: jest.fn(),
  ping: jest.fn(),
}));

jest.mock('../../src/utils/mailer', () => ({
  sendPasswordReset: jest.fn().mockResolvedValue(undefined),
  sendPasswordChanged: jest.fn().mockResolvedValue(undefined),
}));

jest.mock('../../src/models', () => ({
  sequelize: { authenticate: jest.fn() },
  Client: { findByPk: jest.fn(), findAll: jest.fn().mockResolvedValue([]) },
  AuthEvent: { create: jest.fn() },
  SsoSession: { findOne: jest.fn(), findByPk: jest.fn(), create: jest.fn(), destroy: jest.fn() },
  AuthorizationCode: { create: jest.fn(), findByPk: jest.fn() },
  RefreshToken: { create: jest.fn(), findOne: jest.fn(), update: jest.fn() },
  MfaFactor: { findByPk: jest.fn(), create: jest.fn() },
  PasswordReset: { count: jest.fn(), update: jest.fn(), create: jest.fn(), findOne: jest.fn() },
}));

const ldap = require('../../src/ldap/ldap.gateway');
const mailer = require('../../src/utils/mailer');
const { SsoSession, PasswordReset } = require('../../src/models');
const app = require('../../src/app');

const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');

const budi = { id: '0a000000-0000-4000-8000-000000000002', name: 'Budi Santoso', email: 'budi@example.com', role: 'USER', disabled: false };

const makeSession = () => ({
  id: '11111111-1111-4111-8111-111111111111',
  userId: budi.id,
  name: budi.name,
  email: budi.email,
  role: 'USER',
  stage: 'ACTIVE',
  expiresAt: new Date(Date.now() + 60 * 60 * 1000),
  isActive() {
    return this.stage === 'ACTIVE' && this.expiresAt > new Date();
  },
});

// A page visit gives the CSRF cookie that every form post must send back
const csrf = async () => {
  const page = await request(app).get('/forgot');
  const cookie = page.headers['set-cookie'].find((value) => value.startsWith('kid_csrf=')).split(';')[0];
  return { cookie, token: cookie.split('=')[1] };
};

beforeEach(() => {
  jest.clearAllMocks();
  PasswordReset.count.mockResolvedValue(0);
  PasswordReset.update.mockResolvedValue([1]);
  PasswordReset.findOne.mockResolvedValue(null);
});

describe('forgot password', () => {
  const post = async (email) => {
    const { cookie, token } = await csrf();
    return request(app).post('/forgot').set('Cookie', cookie).type('form').send({ _csrf: token, email });
  };

  test('an email with no account gets the same answer and nothing is created or sent', async () => {
    ldap.findByEmail.mockResolvedValue(null);
    const res = await post('nobody@example.com');
    expect(res.status).toBe(200);
    expect(res.text).toContain('Check your email');
    expect(PasswordReset.create).not.toHaveBeenCalled();
    expect(mailer.sendPasswordReset).not.toHaveBeenCalled();
  });

  test('an account gets a link whose token is stored only as a hash', async () => {
    ldap.findByEmail.mockResolvedValue(budi);
    const res = await post('Budi@Example.com');
    expect(res.status).toBe(200);
    expect(res.text).toContain('Check your email');

    const { link } = mailer.sendPasswordReset.mock.calls[0][0];
    expect(link).toMatch(/^https:\/\/sso\.test\/reset\?token=[\w-]{20,}$/);
    const token = new URL(link).searchParams.get('token');
    expect(PasswordReset.create).toHaveBeenCalledWith(expect.objectContaining({ userId: budi.id, tokenHash: sha256(token) }));
    expect(JSON.stringify(PasswordReset.create.mock.calls)).not.toContain(token);
  });

  test('older links stop working when a new one is requested', async () => {
    ldap.findByEmail.mockResolvedValue(budi);
    await post(budi.email);
    expect(PasswordReset.update).toHaveBeenCalledWith({ usedAt: expect.any(Date) }, { where: { userId: budi.id, usedAt: null } });
  });

  test('after three requests in an hour nothing more is sent, with the same answer', async () => {
    ldap.findByEmail.mockResolvedValue(budi);
    PasswordReset.count.mockResolvedValue(3);
    const res = await post(budi.email);
    expect(res.status).toBe(200);
    expect(res.text).toContain('Check your email');
    expect(PasswordReset.create).not.toHaveBeenCalled();
    expect(mailer.sendPasswordReset).not.toHaveBeenCalled();
  });

  test('a disabled account gets no link', async () => {
    ldap.findByEmail.mockResolvedValue({ ...budi, disabled: true });
    await post(budi.email);
    expect(mailer.sendPasswordReset).not.toHaveBeenCalled();
  });

  test('a failing mail server does not change the answer', async () => {
    ldap.findByEmail.mockResolvedValue(budi);
    mailer.sendPasswordReset.mockRejectedValueOnce(new Error('smtp down'));
    const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
    const res = await post(budi.email);
    expect(res.status).toBe(200);
    expect(res.text).toContain('Check your email');
    spy.mockRestore();
  });

  test('something that is not an email is refused', async () => {
    const res = await post('not-an-email');
    expect(res.status).toBe(422);
    expect(ldap.findByEmail).not.toHaveBeenCalled();
  });

  test('a post without the CSRF token is refused', async () => {
    const res = await request(app).post('/forgot').type('form').send({ email: budi.email });
    expect(res.status).toBe(403);
    expect(ldap.findByEmail).not.toHaveBeenCalled();
  });
});

describe('reset link', () => {
  const TOKEN = 'a-reset-token-long-enough-to-pass';

  test('an unknown or used link shows an error instead of the form', async () => {
    const res = await request(app).get('/reset').query({ token: TOKEN });
    expect(res.status).toBe(400);
    expect(res.text).toContain('invalid or has expired');
    expect(res.text).not.toContain('Choose a new password');
  });

  test('a working link shows the form, looked up by hash', async () => {
    PasswordReset.findOne.mockResolvedValue({ id: 'r-1', userId: budi.id });
    const res = await request(app).get('/reset').query({ token: TOKEN });
    expect(res.status).toBe(200);
    expect(res.text).toContain('Choose a new password');
    expect(PasswordReset.findOne.mock.calls[0][0].where.tokenHash).toBe(sha256(TOKEN));
  });

  const submit = async (fields) => {
    const { cookie, token } = await csrf();
    return request(app).post('/reset').set('Cookie', cookie).type('form').send({ _csrf: token, token: TOKEN, ...fields });
  };

  test('a new password is saved hashed, every session ends and the user is sent to log in', async () => {
    PasswordReset.findOne.mockResolvedValue({ id: 'r-1', userId: budi.id });
    ldap.findById.mockResolvedValue(budi);

    const res = await submit({ password: 'Brandnew123', confirmPassword: 'Brandnew123' });
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/login?notice=password-changed');

    expect(ldap.updatePerson).toHaveBeenCalledWith(budi.id, { passwordHash: expect.stringMatching(/^\{SSHA\}/) });
    expect(JSON.stringify(ldap.updatePerson.mock.calls)).not.toContain('Brandnew123');
    expect(SsoSession.destroy).toHaveBeenCalledWith({ where: { userId: budi.id } });
    expect(PasswordReset.update).toHaveBeenCalledWith({ usedAt: expect.any(Date) }, { where: { id: 'r-1', usedAt: null } });
    expect(mailer.sendPasswordChanged).toHaveBeenCalledWith({ to: budi.email, name: budi.name });
  });

  test('a link already claimed by another request is refused', async () => {
    PasswordReset.findOne.mockResolvedValue({ id: 'r-1', userId: budi.id });
    PasswordReset.update.mockResolvedValue([0]);

    const res = await submit({ password: 'Brandnew123', confirmPassword: 'Brandnew123' });
    expect(res.status).toBe(400);
    expect(ldap.updatePerson).not.toHaveBeenCalled();
  });

  test('a weak password or a mismatch keeps the form and changes nothing', async () => {
    const weak = await submit({ password: 'short', confirmPassword: 'short' });
    expect(weak.status).toBe(422);
    const mismatch = await submit({ password: 'Brandnew123', confirmPassword: 'Different123' });
    expect(mismatch.status).toBe(422);
    expect(mismatch.text).toContain('Passwords do not match');
    expect(ldap.updatePerson).not.toHaveBeenCalled();
  });

  test('a link for an account that is now disabled is refused', async () => {
    PasswordReset.findOne.mockResolvedValue({ id: 'r-1', userId: budi.id });
    ldap.findById.mockResolvedValue({ ...budi, disabled: true });

    const res = await submit({ password: 'Brandnew123', confirmPassword: 'Brandnew123' });
    expect(res.status).toBe(400);
    expect(ldap.updatePerson).not.toHaveBeenCalled();
  });
});

describe('change password', () => {
  const loggedIn = () => SsoSession.findOne.mockResolvedValue(makeSession());

  const submit = async (fields) => {
    const { cookie, token } = await csrf();
    return request(app)
      .post('/account/password')
      .set('Cookie', [cookie, 'kid_sid=session-id'])
      .type('form')
      .send({ _csrf: token, ...fields });
  };

  test('someone who is not logged in is sent to the login page', async () => {
    const res = await request(app).get('/account/password');
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/login');
  });

  test('a logged-in user sees the form', async () => {
    loggedIn();
    const res = await request(app).get('/account/password').set('Cookie', 'kid_sid=session-id');
    expect(res.status).toBe(200);
    expect(res.text).toContain('Current password');
  });

  test('a wrong current password changes nothing', async () => {
    loggedIn();
    ldap.findById.mockResolvedValue(budi);
    ldap.checkPassword.mockResolvedValue(false);

    const res = await submit({ currentPassword: 'wrong', password: 'Brandnew123', confirmPassword: 'Brandnew123' });
    expect(res.status).toBe(400);
    expect(res.text).toContain('Current password is incorrect');
    expect(ldap.updatePerson).not.toHaveBeenCalled();
  });

  test('the same password again is refused before the directory is touched', async () => {
    loggedIn();
    const res = await submit({ currentPassword: 'Samepass123', password: 'Samepass123', confirmPassword: 'Samepass123' });
    expect(res.status).toBe(400);
    expect(res.text).toContain('different from the current one');
    expect(ldap.checkPassword).not.toHaveBeenCalled();
  });

  test('a new password is saved and the other devices are logged out, not this one', async () => {
    const session = makeSession();
    SsoSession.findOne.mockResolvedValue(session);
    ldap.findById.mockResolvedValue(budi);
    ldap.checkPassword.mockResolvedValue(true);

    const res = await submit({ currentPassword: 'User12345', password: 'Brandnew123', confirmPassword: 'Brandnew123' });
    expect(res.status).toBe(200);
    expect(res.text).toContain('Password changed');
    expect(ldap.updatePerson).toHaveBeenCalledWith(budi.id, expect.objectContaining({ passwordHash: expect.stringMatching(/^\{SSHA\}/) }));

    const { where } = SsoSession.destroy.mock.calls[0][0];
    expect(where.userId).toBe(budi.id);
    expect(where.id[Op.ne]).toBe(session.id);
    expect(mailer.sendPasswordChanged).toHaveBeenCalledWith({ to: budi.email, name: budi.name });
  });

  test('a post without the CSRF token is refused', async () => {
    loggedIn();
    const res = await request(app).post('/account/password').set('Cookie', 'kid_sid=session-id').type('form').send({ currentPassword: 'a', password: 'b', confirmPassword: 'b' });
    expect(res.status).toBe(403);
    expect(ldap.updatePerson).not.toHaveBeenCalled();
  });
});

describe('login page links', () => {
  test('offers "Forgot your password?" when email is set up', async () => {
    const res = await request(app).get('/login');
    expect(res.text).toContain('href="/forgot"');
  });

  test('shows the notice after a reset, but only for known codes', async () => {
    const known = await request(app).get('/login').query({ notice: 'password-changed' });
    expect(known.text).toContain('Password changed. Log in with your new password.');
    const unknown = await request(app).get('/login').query({ notice: '<script>alert(1)</script>' });
    expect(unknown.text).not.toContain('<script>alert(1)</script>');
  });
});
