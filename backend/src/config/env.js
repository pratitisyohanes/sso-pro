require('dotenv').config();
const { z } = require('zod');
const applyDatabaseUrl = require('./databaseUrl');

applyDatabaseUrl();

// An empty value in .env ("SMTP_HOST=") means "not set"
const blankAsUndefined = (schema) => z.preprocess((value) => (value === '' ? undefined : value), schema);

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  // Only other services on this machine call auth-service, so it never listens on a public address
  HOST: z.string().default('127.0.0.1'),
  PORT: z.coerce.number().int().positive().default(5002),
  DATABASE_URL: z.string().min(1, 'Set DATABASE_URL or DB_HOST, DB_PORT, DB_DATABASE, DB_USERNAME, DB_PASSWORD'),
  DB_SSL: z.enum(['true', 'false']).default('false').transform((value) => value === 'true'),

  LDAP_URL: z.string().regex(/^ldaps?:\/\//, 'LDAP_URL must look like ldap://127.0.0.1:389'),
  LDAP_BASE_DN: z.string().min(1).default('dc=kandang,dc=local'),
  // Service account that may search and write ou=people and ou=groups
  LDAP_BIND_DN: z.string().min(1),
  LDAP_BIND_PASSWORD: z.string().min(1),
  LDAP_TIMEOUT_MS: z.coerce.number().int().min(500).max(30000).default(5000),

  JWT_PRIVATE_KEY_PATH: z.string().default('./keys/private.pem'),
  // Changes when the key is rotated so verifiers can pick the right public key
  JWT_KEY_ID: z.string().min(1).default('kid-2026-10'),
  TOKEN_ISSUER: z.string().min(1).default('kandangid'),
  SERVICE_TOKEN_EXPIRES: z.string().default('15m'),

  // Stage 2 (OIDC single sign-on): the address browsers use for KandangID; also the "iss" of user tokens
  PUBLIC_URL: z.string().url('PUBLIC_URL must be a URL like http://localhost:5002').default('http://localhost:5002'),
  // APIs that accept user access tokens; each one checks that its own name is in "aud"
  USER_AUDIENCE: z.string().default('booking-api,pos-api'),
  ACCESS_TOKEN_EXPIRES: z.string().default('15m'),
  REFRESH_TOKEN_DAYS: z.coerce.number().int().min(1).max(90).default(7),
  // Idle limit of the SSO session; every token refresh moves it forward
  SESSION_HOURS: z.coerce.number().int().min(1).max(72).default(8),
  COOKIE_SECURE: z.enum(['true', 'false']).default('false').transform((value) => value === 'true'),

  // Two-factor authentication now happens on the KandangID login page
  MFA_ENFORCE_ADMIN: z.enum(['true', 'false']).default('false').transform((value) => value === 'true'),
  MFA_ENCRYPTION_KEY: z.preprocess(
    (value) => (value === '' ? undefined : value),
    z.string().regex(/^[0-9a-f]{64}$/i, 'MFA_ENCRYPTION_KEY must be 64 hex characters').optional(),
  ),
  MFA_ISSUER: z.string().min(1).default('ELEFEZ FARM'),

  // Password reset by email. Leave SMTP_HOST empty to switch the feature off.
  // Gmail: smtp.gmail.com with port 465 and SMTP_SECURE=true (or port 587 with SMTP_SECURE=false), using an App Password
  SMTP_HOST: blankAsUndefined(z.string().min(1).optional()),
  SMTP_PORT: z.coerce.number().int().positive().default(465),
  SMTP_SECURE: z.enum(['true', 'false']).default('true').transform((value) => value === 'true'),
  SMTP_USER: blankAsUndefined(z.string().min(1).optional()),
  SMTP_PASSWORD: blankAsUndefined(z.string().min(1).optional()),
  MAIL_FROM: blankAsUndefined(z.string().min(1).optional()),
});

const requireTogether = (data, ctx) => {
  if (data.MFA_ENFORCE_ADMIN && !data.MFA_ENCRYPTION_KEY) {
    ctx.addIssue({ code: 'custom', path: ['MFA_ENCRYPTION_KEY'], message: 'MFA_ENCRYPTION_KEY is required when MFA_ENFORCE_ADMIN=true' });
  }
  if (data.SMTP_HOST) {
    ['SMTP_USER', 'SMTP_PASSWORD'].forEach((key) => {
      if (!data[key]) ctx.addIssue({ code: 'custom', path: [key], message: `${key} is required when SMTP_HOST is set` });
    });
  }
};

// Fail fast on startup when required environment variables are missing
const parsed = envSchema.superRefine(requireTogether).safeParse(process.env);
if (!parsed.success) {
  console.error('Invalid environment variables:', parsed.error.flatten().fieldErrors);
  process.exit(1);
}

// Google shows an App Password in groups of four ("abcd efgh ijkl mnop"); the spaces are not part of it
const smtpPassword = parsed.data.SMTP_PASSWORD?.replace(/\s+/g, '');

module.exports = {
  ...parsed.data,
  PUBLIC_URL: parsed.data.PUBLIC_URL.replace(/\/+$/, ''),
  USER_AUDIENCES: parsed.data.USER_AUDIENCE.split(',').map((name) => name.trim()).filter(Boolean),
  SMTP_PASSWORD: smtpPassword,
  MAIL_ENABLED: Boolean(parsed.data.SMTP_HOST && parsed.data.SMTP_USER && smtpPassword),
  MAIL_FROM: parsed.data.MAIL_FROM || (parsed.data.SMTP_USER ? `"${parsed.data.MFA_ISSUER}" <${parsed.data.SMTP_USER}>` : undefined),
};
