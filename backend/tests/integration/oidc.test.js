const crypto = require('crypto');
const request = require('supertest');
const { jwtVerify, createLocalJWKSet } = require('jose');

jest.mock('../../src/ldap/ldap.gateway', () => ({
  verifyCredentials: jest.fn(),
  findById: jest.fn(),
  findByEmail: jest.fn(),
  createPerson: jest.fn(),
  ping: jest.fn(),
}));

jest.mock('../../src/models', () => {
  const clientScoped = { findByPk: jest.fn() };
  return {
    sequelize: { authenticate: jest.fn(), transaction: jest.fn((work) => work({ LOCK: { UPDATE: 'UPDATE' } })) },
    Client: { findByPk: jest.fn(), findAll: jest.fn(), scope: () => clientScoped },
    AuthEvent: { create: jest.fn() },
    SsoSession: { findOne: jest.fn(), findByPk: jest.fn(), create: jest.fn(), destroy: jest.fn() },
    AuthorizationCode: { create: jest.fn(), findByPk: jest.fn() },
    RefreshToken: { create: jest.fn(), findOne: jest.fn(), update: jest.fn() },
    MfaFactor: { findByPk: jest.fn(), create: jest.fn() },
  };
});

const ldap = require('../../src/ldap/ldap.gateway');
const { Client, SsoSession, AuthorizationCode, RefreshToken, MfaFactor } = require('../../src/models');
const app = require('../../src/app');

const ORIGIN = 'http://localhost:5174';
const posWeb = {
  id: 'pos-web',
  name: 'POS',
  isActive: true,
  redirectUris: [`${ORIGIN}/login/callback`],
  postLogoutRedirectUris: [`${ORIGIN}/`],
  allowedOrigins: [ORIGIN],
};

const verifier = crypto.randomBytes(32).toString('base64url');
const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
const authorizeQuery = {
  client_id: 'pos-web',
  redirect_uri: `${ORIGIN}/login/callback`,
  response_type: 'code',
  scope: 'openid profile email',
  state: 'state-123',
  nonce: 'nonce-456',
  code_challenge: challenge,
  code_challenge_method: 'S256',
};

const makeSession = (values = {}) => ({
  id: '11111111-1111-4111-8111-111111111111',
  userId: '0a000000-0000-4000-8000-000000000001',
  name: 'Admin Booking',
  email: 'admin@booking.com',
  role: 'ADMIN',
  stage: 'ACTIVE',
  mfaAttempts: 0,
  expiresAt: new Date(Date.now() + 60 * 60 * 1000),
  isActive() {
    return this.stage === 'ACTIVE' && this.expiresAt > new Date();
  },
  update: jest.fn(async function update(changes) {
    return Object.assign(this, changes);
  }),
  destroy: jest.fn(),
  ...values,
});

const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');

beforeEach(() => {
  jest.clearAllMocks();
  Client.findByPk.mockImplementation(async (id) => (id === 'pos-web' ? posWeb : null));
  Client.findAll.mockResolvedValue([posWeb]);
  // clearAllMocks keeps resolved values, so reset the ones a test may change
  MfaFactor.findByPk.mockResolvedValue(null);
  SsoSession.findOne.mockResolvedValue(null);
});

describe('discovery', () => {
  test('openid-configuration points to every endpoint', async () => {
    const res = await request(app).get('/.well-known/openid-configuration');
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      issuer: 'http://localhost:5002',
      authorization_endpoint: 'http://localhost:5002/oidc/authorize',
      token_endpoint: 'http://localhost:5002/oidc/token',
      jwks_uri: 'http://localhost:5002/.well-known/jwks.json',
      code_challenge_methods_supported: ['S256'],
    });
  });

  test('jwks publishes one RSA public key with a kid and no private parts', async () => {
    const res = await request(app).get('/.well-known/jwks.json');
    expect(res.body.keys).toHaveLength(1);
    expect(res.body.keys[0]).toMatchObject({ kty: 'RSA', alg: 'RS256', use: 'sig', kid: expect.any(String) });
    expect(res.body.keys[0]).not.toHaveProperty('d');
  });
});

describe('GET /oidc/authorize', () => {
  test('unknown redirect_uri shows an error page and never redirects there', async () => {
    const res = await request(app).get('/oidc/authorize').query({ ...authorizeQuery, redirect_uri: 'https://evil.example/callback' });
    expect(res.status).toBe(400);
    expect(res.text).toContain('not registered');
  });

  test('missing PKCE goes back to the app with an error', async () => {
    const res = await request(app).get('/oidc/authorize').query({ ...authorizeQuery, code_challenge: undefined });
    expect(res.status).toBe(302);
    expect(res.headers.location).toContain(`${ORIGIN}/login/callback?error=invalid_request`);
    expect(res.headers.location).toContain('state=state-123');
  });

  test('without a session the user is sent to the login page', async () => {
    const res = await request(app).get('/oidc/authorize').query(authorizeQuery);
    expect(res.status).toBe(302);
    expect(res.headers.location).toMatch(/^\/login\?return_to=%2Foidc%2Fauthorize%3F/);
  });

  test('prompt=create opens the register page', async () => {
    const res = await request(app).get('/oidc/authorize').query({ ...authorizeQuery, prompt: 'create' });
    expect(res.headers.location).toMatch(/^\/register\?return_to=/);
    expect(decodeURIComponent(res.headers.location)).not.toContain('prompt=create');
  });

  test('with an active session the app gets a code straight away (single sign-on)', async () => {
    SsoSession.findOne.mockResolvedValue(makeSession());
    const res = await request(app).get('/oidc/authorize').set('Cookie', 'kid_sid=abc').query(authorizeQuery);

    expect(res.status).toBe(302);
    const target = new URL(res.headers.location);
    expect(target.origin + target.pathname).toBe(`${ORIGIN}/login/callback`);
    expect(target.searchParams.get('state')).toBe('state-123');
    expect(AuthorizationCode.create).toHaveBeenCalledWith(
      expect.objectContaining({ codeHash: sha256(target.searchParams.get('code')), codeChallenge: challenge, nonce: 'nonce-456' }),
    );
  });
});

describe('POST /oidc/token', () => {
  const codeRow = (values = {}) => ({
    clientId: 'pos-web',
    sessionId: makeSession().id,
    redirectUri: `${ORIGIN}/login/callback`,
    codeChallenge: challenge,
    nonce: 'nonce-456',
    expiresAt: new Date(Date.now() + 30 * 1000),
    usedAt: null,
    update: jest.fn(),
    ...values,
  });

  const exchange = (body) =>
    request(app)
      .post('/oidc/token')
      .set('Origin', ORIGIN)
      .type('form')
      .send({ grant_type: 'authorization_code', code: 'the-code', code_verifier: verifier, client_id: 'pos-web', redirect_uri: `${ORIGIN}/login/callback`, ...body });

  test('code + PKCE verifier give tokens that pos-api can verify', async () => {
    AuthorizationCode.findByPk.mockResolvedValue(codeRow());
    SsoSession.findByPk.mockResolvedValue(makeSession());

    const res = await exchange({});
    expect(res.status).toBe(200);
    expect(res.headers['access-control-allow-origin']).toBe(ORIGIN);
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.body).toMatchObject({ token_type: 'Bearer', expires_in: 900, refresh_token: expect.any(String) });

    const jwks = createLocalJWKSet((await request(app).get('/.well-known/jwks.json')).body);
    const { payload: access } = await jwtVerify(res.body.access_token, jwks, { issuer: 'http://localhost:5002', audience: 'pos-api' });
    expect(access).toMatchObject({ sub: '0a000000-0000-4000-8000-000000000001', role: 'ADMIN', name: 'Admin Booking', azp: 'pos-web' });

    const { payload: id } = await jwtVerify(res.body.id_token, jwks, { audience: 'pos-web' });
    expect(id.nonce).toBe('nonce-456');
    expect(RefreshToken.create).toHaveBeenCalled();
  });

  test('wrong code_verifier is refused', async () => {
    AuthorizationCode.findByPk.mockResolvedValue(codeRow());
    const res = await exchange({ code_verifier: 'x'.repeat(43) });
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: 'invalid_grant', error_description: 'PKCE verification failed' });
  });

  test('a code used twice is refused and its tokens are revoked', async () => {
    AuthorizationCode.findByPk.mockResolvedValue(codeRow({ usedAt: new Date() }));
    const res = await exchange({});
    expect(res.body.error).toBe('invalid_grant');
    expect(RefreshToken.update).toHaveBeenCalledWith(expect.objectContaining({ revokedAt: expect.any(Date) }), expect.anything());
  });

  test('a code for another redirect_uri is refused', async () => {
    AuthorizationCode.findByPk.mockResolvedValue(codeRow());
    const res = await exchange({ redirect_uri: 'http://localhost:5173/login/callback' });
    expect(res.body.error).toBe('invalid_grant');
  });

  test('refresh rotates the token and re-reads LDAP', async () => {
    const row = { clientId: 'pos-web', sessionId: makeSession().id, expiresAt: new Date(Date.now() + 1e6), revokedAt: null, update: jest.fn() };
    RefreshToken.findOne.mockResolvedValue(row);
    SsoSession.findByPk.mockResolvedValue(makeSession());
    ldap.findById.mockResolvedValue({ id: makeSession().userId, name: 'Admin Booking', email: 'admin@booking.com', role: 'ADMIN', disabled: false });

    const res = await request(app).post('/oidc/token').type('form').send({ grant_type: 'refresh_token', refresh_token: 'old', client_id: 'pos-web' });
    expect(res.status).toBe(200);
    expect(row.update).toHaveBeenCalledWith({ revokedAt: expect.any(Date) }, expect.anything());
    expect(ldap.findById).toHaveBeenCalled();
  });

  test('reusing a rotated refresh token ends the whole session', async () => {
    RefreshToken.findOne.mockResolvedValue({ clientId: 'pos-web', sessionId: 'sess-1', revokedAt: new Date(), expiresAt: new Date(Date.now() + 1e6) });
    const res = await request(app).post('/oidc/token').type('form').send({ grant_type: 'refresh_token', refresh_token: 'old', client_id: 'pos-web' });
    expect(res.body.error).toBe('invalid_grant');
    expect(SsoSession.destroy).toHaveBeenCalledWith(expect.objectContaining({ where: { id: 'sess-1' } }));
  });

  test('refresh is refused once the user is moved to cn=disabled', async () => {
    RefreshToken.findOne.mockResolvedValue({ clientId: 'pos-web', sessionId: 'sess-1', revokedAt: null, expiresAt: new Date(Date.now() + 1e6), update: jest.fn() });
    SsoSession.findByPk.mockResolvedValue(makeSession({ id: 'sess-1' }));
    ldap.findById.mockResolvedValue({ id: 'u', name: 'x', email: 'x', role: 'USER', disabled: true });
    const res = await request(app).post('/oidc/token').type('form').send({ grant_type: 'refresh_token', refresh_token: 'old', client_id: 'pos-web' });
    expect(res.body).toEqual({ error: 'invalid_grant', error_description: 'Account is deactivated' });
  });
});

describe('login page', () => {
  const csrfFrom = (res) => res.headers['set-cookie'].find((cookie) => cookie.startsWith('kid_csrf=')).split(';')[0];

  test('shows the form with the app name and a CSRF token', async () => {
    const returnTo = `/oidc/authorize?${new URLSearchParams(authorizeQuery)}`;
    const res = await request(app).get('/login').query({ return_to: returnTo });
    expect(res.status).toBe(200);
    expect(res.text).toContain('to continue to <strong>POS</strong>');
    expect(res.text).toMatch(/name="_csrf" value="[\w-]+"/);
  });

  test('a post without the CSRF token is refused', async () => {
    const res = await request(app).post('/login').type('form').send({ email: 'budi@example.com', password: 'User12345' });
    expect(res.status).toBe(403);
    expect(ldap.verifyCredentials).not.toHaveBeenCalled();
  });

  test('wrong password shows the error on the page', async () => {
    const page = await request(app).get('/login');
    const cookie = csrfFrom(page);
    ldap.verifyCredentials.mockResolvedValue(null);

    const res = await request(app).post('/login').set('Cookie', cookie).type('form').send({ _csrf: cookie.split('=')[1], email: 'budi@example.com', password: 'nope' });
    expect(res.status).toBe(401);
    expect(res.text).toContain('Invalid email or password');
  });

  test('right password sets the session cookie and returns to authorize', async () => {
    const page = await request(app).get('/login');
    const cookie = csrfFrom(page);
    ldap.verifyCredentials.mockResolvedValue({ id: 'u-2', name: 'Budi Santoso', email: 'budi@example.com', role: 'USER', disabled: false });
    const returnTo = `/oidc/authorize?${new URLSearchParams(authorizeQuery)}`;

    const res = await request(app)
      .post('/login')
      .set('Cookie', cookie)
      .type('form')
      .send({ _csrf: cookie.split('=')[1], email: 'budi@example.com', password: 'User12345', return_to: returnTo });
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe(returnTo);
    const sessionCookie = res.headers['set-cookie'].find((value) => value.startsWith('kid_sid='));
    expect(sessionCookie).toMatch(/HttpOnly/);
    expect(sessionCookie).toMatch(/SameSite=Lax/);
    expect(SsoSession.create).toHaveBeenCalledWith(expect.objectContaining({ stage: 'ACTIVE', userId: 'u-2' }));
  });

  test('an account with two-factor on goes to the code page, not straight back to the app', async () => {
    MfaFactor.findByPk.mockResolvedValue({ enabled: true });
    const page = await request(app).get('/login');
    const cookie = csrfFrom(page);
    ldap.verifyCredentials.mockResolvedValue({ id: 'u-1', name: 'Admin', email: 'admin@booking.com', role: 'ADMIN', disabled: false });
    const returnTo = `/oidc/authorize?${new URLSearchParams(authorizeQuery)}`;

    const res = await request(app)
      .post('/login')
      .set('Cookie', cookie)
      .type('form')
      .send({ _csrf: cookie.split('=')[1], email: 'admin@booking.com', password: 'Admin12345', return_to: returnTo });
    expect(res.headers.location).toBe(`/mfa?return_to=${encodeURIComponent(returnTo)}`);
    expect(SsoSession.create).toHaveBeenCalledWith(expect.objectContaining({ stage: 'MFA_VERIFY' }));
  });

  test('return_to outside /oidc/authorize is ignored (no open redirect)', async () => {
    const page = await request(app).get('/login');
    const cookie = csrfFrom(page);
    ldap.verifyCredentials.mockResolvedValue({ id: 'u-2', name: 'Budi', email: 'budi@example.com', role: 'USER', disabled: false });
    const res = await request(app)
      .post('/login')
      .set('Cookie', cookie)
      .type('form')
      .send({ _csrf: cookie.split('=')[1], email: 'budi@example.com', password: 'User12345', return_to: 'https://evil.example' });
    expect(res.headers.location).toBe('/');
  });
});

describe('logout', () => {
  test('ends the session and returns to a registered address', async () => {
    const session = makeSession();
    SsoSession.findOne.mockResolvedValue(session);
    const res = await request(app)
      .get('/oidc/logout')
      .set('Cookie', 'kid_sid=abc')
      .query({ client_id: 'pos-web', post_logout_redirect_uri: `${ORIGIN}/` });
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe(`${ORIGIN}/`);
    expect(SsoSession.destroy).toHaveBeenCalledWith({ where: { id: session.id } });
  });

  test('an unregistered return address shows the logged-out page instead', async () => {
    const res = await request(app).get('/oidc/logout').query({ client_id: 'pos-web', post_logout_redirect_uri: 'https://evil.example/' });
    expect(res.status).toBe(200);
    expect(res.text).toContain('You are logged out');
  });
});
