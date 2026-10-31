const crypto = require('crypto');
const request = require('supertest');

// No SMTP_* here, so email is off: people are told to ask the administrator, who creates the link
process.env.SUPPORT_CONTACT = 'WhatsApp 0812-3456-7890';
process.env.PUBLIC_URL = 'https://sso.test';

jest.mock('../../src/ldap/ldap.gateway', () => ({ findByEmail: jest.fn(), ping: jest.fn() }));
jest.mock('../../src/utils/mailer', () => ({ sendPasswordReset: jest.fn(), sendPasswordChanged: jest.fn() }));
jest.mock('../../src/models', () => ({
  sequelize: { authenticate: jest.fn() },
  Client: { findByPk: jest.fn(), findAll: jest.fn().mockResolvedValue([]) },
  AuthEvent: { create: jest.fn() },
  SsoSession: { findOne: jest.fn(), destroy: jest.fn() },
  AuthorizationCode: {},
  RefreshToken: {},
  MfaFactor: {},
  PasswordReset: { count: jest.fn(), update: jest.fn().mockResolvedValue([1]), create: jest.fn(), findOne: jest.fn() },
}));

const ldap = require('../../src/ldap/ldap.gateway');
const mailer = require('../../src/utils/mailer');
const { PasswordReset } = require('../../src/models');
const passwordService = require('../../src/modules/login/password.service');
const app = require('../../src/app');

const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');

describe('forgot password without email', () => {
  test('the login page still offers "Forgot your password?"', async () => {
    const res = await request(app).get('/login');
    expect(res.status).toBe(200);
    expect(res.text).toContain('href="/forgot"');
  });

  test('the forgot page says to ask the administrator and shows the contact', async () => {
    const res = await request(app).get('/forgot');
    expect(res.status).toBe(200);
    expect(res.text).toContain('Contact the administrator');
    expect(res.text).toContain('WhatsApp 0812-3456-7890');
    expect(res.text).not.toContain('<form');
  });

  test('a post to it looks up nobody and sends nothing', async () => {
    const page = await request(app).get('/login');
    const cookie = page.headers['set-cookie'].find((value) => value.startsWith('kid_csrf=')).split(';')[0];
    const res = await request(app).post('/forgot').set('Cookie', cookie).type('form').send({ _csrf: cookie.split('=')[1], email: 'budi@example.com' });
    expect(res.status).toBe(200);
    expect(ldap.findByEmail).not.toHaveBeenCalled();
    expect(mailer.sendPasswordReset).not.toHaveBeenCalled();
    expect(PasswordReset.create).not.toHaveBeenCalled();
  });
});

describe('reset link made by the administrator', () => {
  const account = { id: '0a000000-0000-4000-8000-000000000002', name: 'Budi Santoso', email: 'budi@example.com' };

  test('is a one-time link whose token is stored only as a hash, valid for the asked time', async () => {
    const before = Date.now();
    const { link, expiresAt } = await passwordService.createResetLink(account, { minutes: 60 });

    expect(link).toMatch(/^https:\/\/sso\.test\/reset\?token=[\w-]{20,}$/);
    const token = new URL(link).searchParams.get('token');
    expect(PasswordReset.create).toHaveBeenCalledWith(expect.objectContaining({ userId: account.id, tokenHash: sha256(token) }));
    expect(JSON.stringify(PasswordReset.create.mock.calls)).not.toContain(token);
    expect(expiresAt.getTime() - before).toBeGreaterThanOrEqual(60 * 60 * 1000 - 1000);
  });

  test('cancels the older links of the same account', async () => {
    await passwordService.createResetLink(account);
    expect(PasswordReset.update).toHaveBeenCalledWith({ usedAt: expect.any(Date) }, { where: { userId: account.id, usedAt: null } });
  });
});
