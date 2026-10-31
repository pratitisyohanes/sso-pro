const request = require('supertest');

// No SMTP_* here, so email is off and the reset pages must say so instead of failing
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
  PasswordReset: { count: jest.fn(), update: jest.fn(), create: jest.fn(), findOne: jest.fn() },
}));

const ldap = require('../../src/ldap/ldap.gateway');
const app = require('../../src/app');

describe('password reset with email switched off', () => {
  test('the forgot page explains that it is not set up', async () => {
    const res = await request(app).get('/forgot');
    expect(res.status).toBe(503);
    expect(res.text).toContain('not set up yet');
  });

  test('a post to it does nothing', async () => {
    const page = await request(app).get('/login');
    const cookie = page.headers['set-cookie'].find((value) => value.startsWith('kid_csrf=')).split(';')[0];
    const res = await request(app).post('/forgot').set('Cookie', cookie).type('form').send({ _csrf: cookie.split('=')[1], email: 'budi@example.com' });
    expect(res.status).toBe(503);
    expect(ldap.findByEmail).not.toHaveBeenCalled();
  });

  test('the login page has no "Forgot your password?" link', async () => {
    const res = await request(app).get('/login');
    expect(res.status).toBe(200);
    expect(res.text).not.toContain('/forgot');
  });
});
