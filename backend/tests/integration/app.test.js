const bcrypt = require('bcryptjs');
const request = require('supertest');

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

jest.mock('../../src/models', () => {
  const client = { findByPk: jest.fn() };
  return {
    sequelize: { authenticate: jest.fn() },
    Client: { scope: () => client, findByPk: client.findByPk },
    AuthEvent: { create: jest.fn() },
  };
});

const ldap = require('../../src/ldap/ldap.gateway');
const { Client, AuthEvent } = require('../../src/models');
const app = require('../../src/app');

const SECRET = 'booking-secret-for-tests';
const bookingClient = {
  id: 'booking-api',
  isActive: true,
  scopes: ['auth:validate', 'users:read', 'users:write'],
  secretHash: bcrypt.hashSync(SECRET, 4),
};

const budi = { id: '0a000000-0000-4000-8000-000000000002', name: 'Budi Santoso', email: 'budi@example.com', phone: null, role: 'USER', disabled: false };

const getToken = async (scope) => {
  Client.findByPk.mockResolvedValue(bookingClient);
  const res = await request(app)
    .post('/oauth/token')
    .type('form')
    .send({ grant_type: 'client_credentials', client_id: 'booking-api', client_secret: SECRET, ...(scope && { scope }) });
  return res.body.access_token;
};

beforeEach(() => jest.clearAllMocks());

describe('API docs', () => {
  test('OpenAPI spec lists every route and the client_credentials flow', async () => {
    const res = await request(app).get('/api/docs.json');
    expect(res.status).toBe(200);
    expect(res.body.openapi).toBe('3.0.3');
    expect(Object.keys(res.body.paths)).toEqual(
      expect.arrayContaining(['/oauth/token', '/api/v1/auth/validate', '/api/v1/users', '/api/v1/users/{id}', '/api/v1/users/{id}/status', '/api/v1/health']),
    );
    expect(res.body.components.securitySchemes.clientCredentials.flows.clientCredentials.tokenUrl).toBe('/oauth/token');
  });

  test('Swagger UI page is served', async () => {
    const res = await request(app).get('/api/docs/');
    expect(res.status).toBe(200);
    expect(res.text).toContain('KandangID API Docs');
  });
});

describe('POST /oauth/token', () => {
  test('issues a bearer token for a valid client', async () => {
    Client.findByPk.mockResolvedValue(bookingClient);
    const res = await request(app)
      .post('/oauth/token')
      .type('form')
      .send({ grant_type: 'client_credentials', client_id: 'booking-api', client_secret: SECRET });

    expect(res.status).toBe(200);
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.body).toMatchObject({ token_type: 'Bearer', expires_in: 900, scope: 'auth:validate users:read users:write' });
  });

  test('wrong secret answers invalid_client without leaking the request', async () => {
    Client.findByPk.mockResolvedValue(bookingClient);
    const res = await request(app)
      .post('/oauth/token')
      .send({ grant_type: 'client_credentials', client_id: 'booking-api', client_secret: 'wrong' });

    expect(res.status).toBe(401);
    expect(res.body).toEqual({ error: 'invalid_client', error_description: 'Client authentication failed' });
  });

  test('unknown client gets the same answer as a wrong secret', async () => {
    Client.findByPk.mockResolvedValue(null);
    const res = await request(app).post('/oauth/token').send({ grant_type: 'client_credentials', client_id: 'nobody', client_secret: 'x' });
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('invalid_client');
  });

  test('only client_credentials is supported', async () => {
    Client.findByPk.mockResolvedValue(bookingClient);
    const res = await request(app).post('/oauth/token').send({ grant_type: 'password', client_id: 'booking-api', client_secret: SECRET });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('unsupported_grant_type');
  });

  test('accepts id and secret as HTTP Basic auth, as Swagger UI sends them', async () => {
    Client.findByPk.mockResolvedValue(bookingClient);
    const res = await request(app)
      .post('/oauth/token')
      .auth('booking-api', SECRET)
      .type('form')
      .send({ grant_type: 'client_credentials', scope: 'auth:validate' });

    expect(res.status).toBe(200);
    expect(res.body.scope).toBe('auth:validate');
  });

  test('malformed Basic credentials answer invalid_request', async () => {
    const res = await request(app).post('/oauth/token').set('Authorization', 'Basic bm9jb2xvbg==').send({ grant_type: 'client_credentials' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_request');
  });

  test('a client cannot ask for a scope it does not own', async () => {
    Client.findByPk.mockResolvedValue(bookingClient);
    const res = await request(app)
      .post('/oauth/token')
      .send({ grant_type: 'client_credentials', client_id: 'booking-api', client_secret: SECRET, scope: 'users:admin' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_scope');
  });
});

describe('POST /api/v1/auth/validate', () => {
  test('requires a service token', async () => {
    const res = await request(app).post('/api/v1/auth/validate').send({ username: 'budi@example.com', password: 'x' });
    expect(res.status).toBe(401);
  });

  test('requires the auth:validate scope', async () => {
    const token = await getToken('users:read');
    const res = await request(app).post('/api/v1/auth/validate').set('Authorization', `Bearer ${token}`).send({ username: 'budi@example.com', password: 'x' });
    expect(res.status).toBe(403);
  });

  test('valid credentials return login true and the user without the disabled flag', async () => {
    ldap.verifyCredentials.mockResolvedValue(budi);
    const token = await getToken();
    const res = await request(app)
      .post('/api/v1/auth/validate')
      .set('Authorization', `Bearer ${token}`)
      .send({ username: 'Budi@Example.com', password: 'User12345' });

    expect(res.status).toBe(200);
    expect(res.body.data).toEqual({ login: true, user: { id: budi.id, name: budi.name, email: budi.email, phone: null, role: 'USER' } });
    expect(ldap.verifyCredentials).toHaveBeenCalledWith('budi@example.com', 'User12345');
    expect(AuthEvent.create).toHaveBeenCalledWith(expect.objectContaining({ clientId: 'booking-api', action: 'VALIDATE', result: 'SUCCESS' }));
  });

  test('wrong password is still HTTP 200 with login false', async () => {
    ldap.verifyCredentials.mockResolvedValue(null);
    const token = await getToken();
    const res = await request(app).post('/api/v1/auth/validate').set('Authorization', `Bearer ${token}`).send({ username: 'budi@example.com', password: 'nope' });
    expect(res.status).toBe(200);
    expect(res.body.data).toEqual({ login: false, reason: 'INVALID_CREDENTIALS' });
  });

  test('member of cn=disabled is refused', async () => {
    ldap.verifyCredentials.mockResolvedValue({ ...budi, disabled: true });
    const token = await getToken();
    const res = await request(app).post('/api/v1/auth/validate').set('Authorization', `Bearer ${token}`).send({ username: 'budi@example.com', password: 'User12345' });
    expect(res.body.data).toEqual({ login: false, reason: 'DISABLED' });
  });

  test('directory down answers 503', async () => {
    ldap.verifyCredentials.mockRejectedValue(Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }));
    const token = await getToken();
    const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
    const res = await request(app).post('/api/v1/auth/validate').set('Authorization', `Bearer ${token}`).send({ username: 'budi@example.com', password: 'User12345' });
    spy.mockRestore();
    expect(res.status).toBe(503);
  });
});

describe('users', () => {
  test('register refuses a role field', async () => {
    const token = await getToken();
    const res = await request(app)
      .post('/api/v1/users')
      .set('Authorization', `Bearer ${token}`)
      .send({ name: 'Eve', email: 'eve@example.com', password: 'Secret123', role: 'ADMIN' });
    expect(res.status).toBe(422);
    expect(ldap.createPerson).not.toHaveBeenCalled();
  });

  test('register hashes the password before it reaches LDAP', async () => {
    ldap.findByEmail.mockResolvedValue(null);
    ldap.findById.mockResolvedValue(null);
    ldap.createPerson.mockImplementation(async (data) => ({ ...budi, id: data.id }));
    const token = await getToken();
    const res = await request(app)
      .post('/api/v1/users')
      .set('Authorization', `Bearer ${token}`)
      .send({ name: 'Budi Santoso', email: 'budi@example.com', password: 'User12345' });

    expect(res.status).toBe(201);
    const sent = ldap.createPerson.mock.calls[0][0];
    expect(sent.passwordHash).toMatch(/^\{SSHA\}/);
    expect(sent).not.toHaveProperty('password');
  });

  test('changing access needs users:admin', async () => {
    const token = await getToken();
    const res = await request(app).patch(`/api/v1/users/${budi.id}/status`).set('Authorization', `Bearer ${token}`).send({ role: 'ADMIN' });
    expect(res.status).toBe(403);
    expect(ldap.setAccess).not.toHaveBeenCalled();
  });

  test('new password requires the current one to bind', async () => {
    ldap.findById.mockResolvedValue(budi);
    ldap.checkPassword.mockResolvedValue(false);
    const token = await getToken();
    const res = await request(app)
      .patch(`/api/v1/users/${budi.id}`)
      .set('Authorization', `Bearer ${token}`)
      .send({ currentPassword: 'wrong', newPassword: 'NewPass123' });
    expect(res.status).toBe(400);
    expect(ldap.updatePerson).not.toHaveBeenCalled();
  });
});
