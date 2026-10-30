const ref = (name) => ({ $ref: `#/components/schemas/${name}` });

const ok = (description, data) => ({
  description,
  content: { 'application/json': { schema: ref('SuccessResponse'), example: { success: true, message: description, data } } },
});

const errors = (...codes) => Object.fromEntries(codes.map((code) => [code, { $ref: `#/components/responses/E${code}` }]));

const jsonBody = (schemaName, example) => ({
  required: true,
  content: { 'application/json': { schema: ref(schemaName), example } },
});

const userId = { name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' }, example: '0a000000-0000-4000-8000-000000000002' };

// Each operation lists the scope it needs; Swagger UI asks for it in the Authorize dialog
const needs = (scope) => [{ clientCredentials: [scope] }, { bearerAuth: [] }];

const SCOPES = {
  'auth:validate': 'Check a username and password against LDAP',
  'users:read': 'Read a directory account',
  'users:write': 'Register accounts and change name, phone or password',
  'users:admin': 'Change role and disabled status (group membership)',
};

const budi = { id: '0a000000-0000-4000-8000-000000000002', name: 'Budi Santoso', email: 'budi@example.com', phone: '081234567890', role: 'USER' };

const spec = {
  openapi: '3.0.3',
  info: {
    title: 'KandangID auth-service',
    version: '1.0.0',
    description:
      'Central password check for KandangMart, modelled on the office login gateway. An application first proves who it is with ' +
      'OAuth2 client_credentials (POST /oauth/token), then sends the user\'s email and password to POST /api/v1/auth/validate. ' +
      'auth-service runs search-then-bind against OpenLDAP; group membership decides the role (cn=admins = ADMIN) and cn=disabled blocks login.\n\n' +
      '**How to try it here:** click **Authorize**, fill client_id `booking-api` and the client_secret printed by `npm run client:create`, ' +
      'tick the scopes you need, then use "Try it out" on any endpoint. Demo accounts: budi@example.com / User12345, admin@booking.com / Admin12345.',
  },
  servers: [{ url: '/', description: 'Current host (only reachable from this machine)' }],
  tags: [
    { name: 'OAuth', description: 'Who is calling: application identity' },
    { name: 'Auth', description: 'Is this password right: LDAP search-then-bind' },
    { name: 'Users', description: 'Directory accounts under ou=people and their groups' },
    { name: 'Health', description: 'Database and LDAP status' },
  ],
  components: {
    securitySchemes: {
      clientCredentials: {
        type: 'oauth2',
        description: 'Swagger UI fetches the token from /oauth/token for you after Authorize.',
        flows: { clientCredentials: { tokenUrl: '/oauth/token', scopes: SCOPES } },
      },
      bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT', description: 'Or paste an access_token from POST /oauth/token' },
    },
    schemas: {
      SuccessResponse: { type: 'object', properties: { success: { type: 'boolean' }, message: { type: 'string' }, data: {} } },
      ErrorResponse: {
        type: 'object',
        properties: {
          success: { type: 'boolean', example: false },
          message: { type: 'string' },
          errors: { type: 'array', items: { type: 'object', properties: { field: { type: 'string' }, message: { type: 'string' } } } },
        },
      },
      OAuthError: {
        type: 'object',
        properties: { error: { type: 'string', example: 'invalid_client' }, error_description: { type: 'string', example: 'Client authentication failed' } },
      },
      TokenRequest: {
        type: 'object',
        required: ['grant_type'],
        properties: {
          grant_type: { type: 'string', enum: ['client_credentials'] },
          client_id: { type: 'string', example: 'booking-api', description: 'Or send id and secret as HTTP Basic auth' },
          client_secret: { type: 'string' },
          scope: { type: 'string', example: 'auth:validate users:read', description: 'Optional; at most the scopes the client owns' },
        },
      },
      TokenResponse: {
        type: 'object',
        properties: {
          access_token: { type: 'string', description: 'RS256 JWT, aud=auth-service, sub=client id' },
          token_type: { type: 'string', example: 'Bearer' },
          expires_in: { type: 'integer', example: 900 },
          scope: { type: 'string', example: 'auth:validate users:read users:write' },
        },
      },
      ValidateInput: {
        type: 'object',
        required: ['username', 'password'],
        properties: { username: { type: 'string', format: 'email' }, password: { type: 'string' } },
      },
      Account: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid', description: 'LDAP uid; equals users.id in booking_db' },
          name: { type: 'string' },
          email: { type: 'string' },
          phone: { type: 'string', nullable: true },
          role: { type: 'string', enum: ['ADMIN', 'USER'] },
          disabled: { type: 'boolean', description: 'Member of cn=disabled' },
        },
      },
      CreateUserInput: {
        type: 'object',
        required: ['name', 'email', 'password'],
        additionalProperties: false,
        properties: {
          id: { type: 'string', format: 'uuid', description: 'Optional, to import an existing booking user' },
          name: { type: 'string' },
          email: { type: 'string', format: 'email' },
          phone: { type: 'string' },
          password: { type: 'string', minLength: 8, description: 'At least one letter and one number' },
        },
      },
      UpdateUserInput: {
        type: 'object',
        additionalProperties: false,
        properties: {
          name: { type: 'string' },
          phone: { type: 'string', nullable: true },
          currentPassword: { type: 'string', description: 'Required with newPassword; checked with an LDAP bind' },
          newPassword: { type: 'string' },
        },
      },
      UpdateStatusInput: {
        type: 'object',
        additionalProperties: false,
        properties: { role: { type: 'string', enum: ['ADMIN', 'USER'] }, disabled: { type: 'boolean' } },
      },
    },
    responses: Object.fromEntries(
      [
        [400, 'Business rule violated (for example wrong current password)'],
        [401, 'Service token missing, invalid or expired'],
        [403, 'Client is missing the required scope'],
        [404, 'User not found in the directory'],
        [409, 'Email or id already exists'],
        [422, 'Input validation failed'],
        [429, 'Too many attempts'],
        [503, 'LDAP or database is not reachable'],
      ].map(([code, description]) => [`E${code}`, { description, content: { 'application/json': { schema: ref('ErrorResponse') } } }]),
    ),
  },
  paths: {
    '/oauth/token': {
      post: {
        tags: ['OAuth'],
        summary: 'Get a service token (client_credentials)',
        description: 'Same role as pub.apigateway.oauth2/getAccessToken at the office. Answers in the OAuth 2.0 shape, not the { success, data } envelope.',
        requestBody: {
          required: true,
          content: {
            'application/x-www-form-urlencoded': { schema: ref('TokenRequest') },
            'application/json': { schema: ref('TokenRequest'), example: { grant_type: 'client_credentials', client_id: 'booking-api', client_secret: '<secret from client:create>' } },
          },
        },
        responses: {
          200: { description: 'Token issued', content: { 'application/json': { schema: ref('TokenResponse') } } },
          400: { description: 'invalid_request, unsupported_grant_type or invalid_scope', content: { 'application/json': { schema: ref('OAuthError') } } },
          401: { description: 'invalid_client: unknown client, wrong secret or inactive', content: { 'application/json': { schema: ref('OAuthError') } } },
          429: { description: 'Too many token requests for this client' },
        },
      },
    },
    '/api/v1/auth/validate': {
      post: {
        tags: ['Auth'],
        summary: 'Check an email and password against LDAP',
        description:
          'Same contract as telkom-auth/authValidate. A wrong password or a blocked account is still HTTP 200 with login: false; ' +
          'HTTP errors are kept for setup problems. Every call is written to auth_events.',
        security: needs('auth:validate'),
        requestBody: jsonBody('ValidateInput', { username: 'budi@example.com', password: 'User12345' }),
        responses: {
          200: {
            description: 'Checked',
            content: {
              'application/json': {
                schema: ref('SuccessResponse'),
                examples: {
                  valid: { summary: 'Password is right', value: { success: true, message: 'Credentials are valid', data: { login: true, user: budi } } },
                  invalid: { summary: 'Wrong email or password', value: { success: true, message: 'Credentials are not valid', data: { login: false, reason: 'INVALID_CREDENTIALS' } } },
                  disabled: { summary: 'Member of cn=disabled', value: { success: true, message: 'Credentials are not valid', data: { login: false, reason: 'DISABLED' } } },
                },
              },
            },
          },
          ...errors(401, 403, 422, 429, 503),
        },
      },
    },
    '/api/v1/users': {
      post: {
        tags: ['Users'],
        summary: 'Register: new entry in ou=people and cn=customers',
        description: 'The password is hashed to {SSHA} before it reaches LDAP. A role field is refused; new accounts are always customers.',
        security: needs('users:write'),
        requestBody: jsonBody('CreateUserInput', { name: 'Rina Wulandari', email: 'rina@example.com', phone: '081311112222', password: 'Rina12345' }),
        responses: { 201: ok('User created', { ...budi, id: 'c2f04b1e-5d3a-4c8e-9a1b-7e6f5d4c3b2a', name: 'Rina Wulandari', email: 'rina@example.com', disabled: false }), ...errors(401, 403, 409, 422, 503) },
      },
    },
    '/api/v1/users/{id}': {
      get: {
        tags: ['Users'],
        summary: 'Read one account with its role and disabled flag',
        security: needs('users:read'),
        parameters: [userId],
        responses: { 200: ok('User detail', { ...budi, disabled: false }), ...errors(401, 403, 404, 422, 503) },
      },
      patch: {
        tags: ['Users'],
        summary: 'Change name, phone or password',
        security: needs('users:write'),
        parameters: [userId],
        requestBody: jsonBody('UpdateUserInput', { phone: '081299990000' }),
        responses: { 200: ok('User updated', { ...budi, phone: '081299990000', disabled: false }), ...errors(400, 401, 403, 404, 422, 503) },
      },
    },
    '/api/v1/users/{id}/status': {
      patch: {
        tags: ['Users'],
        summary: 'Change role or disabled status (group membership)',
        description: 'Moves the entry between cn=admins and cn=customers, and in or out of cn=disabled. booking-api does not own this scope.',
        security: needs('users:admin'),
        parameters: [userId],
        requestBody: jsonBody('UpdateStatusInput', { disabled: true }),
        responses: { 200: ok('User access updated', { ...budi, disabled: true }), ...errors(401, 403, 404, 422, 503) },
      },
    },
    '/api/v1/health': {
      get: {
        tags: ['Health'],
        summary: 'Database and LDAP status',
        responses: {
          200: { description: 'Both answer', content: { 'application/json': { example: { success: true, message: 'OK', data: { database: 'up', directory: 'up', uptime: 42 } } } } },
          503: { description: 'One of them is down', content: { 'application/json': { example: { success: false, message: 'Dependency down', data: { database: 'up', directory: 'down', uptime: 42 } } } } },
        },
      },
    },
  },
};

module.exports = spec;
