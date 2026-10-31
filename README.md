# KandangID (sso-pro)

Central login service for the two KandangMart apps: **Booking** (`../fin-pro`) and **POS** (`../pos-pro`).
Accounts live in an OpenLDAP directory. Apps never read passwords themselves.

**Stage 1: office pattern (server to server).** booking-api proves who it is with OAuth2 `client_credentials`,
then sends email and password to `POST /api/v1/auth/validate`; auth-service runs search-then-bind against LDAP.

**Stage 2: single sign-on (OpenID Connect).** The Booking and POS web apps send the browser to the KandangID login page.
After one login, the second app opens without asking for the password again (authorization code + PKCE).
Two-factor login (TOTP) happens on the KandangID page. booking-api and pos-api verify the RS256 tokens with the public keys at
`/.well-known/jwks.json`.

## Tech Stack

| Layer | Technology |
| --- | --- |
| Runtime | Node.js 20, Express 4 |
| Login pages | EJS (server-rendered), one inline stylesheet, one small script for the show/hide password button |
| Email | `nodemailer` over SMTP (Gmail with an App Password), only for password reset |
| Directory | OpenLDAP (`osixia/openldap` on the laptop, `slapd` on the VPS), client `ldapts` |
| Tokens | `jose` (RS256, JWKS) |
| Second factor | `otplib` (TOTP) + `qrcode`, secrets encrypted with AES-256-GCM |
| Database | PostgreSQL `sso_db`, Sequelize 6 |
| Testing | Jest + Supertest (LDAP and DB mocked) |

## Architecture

```
Browser ── booking-web :5173 / pos-web :5174
   │  1. redirect /oidc/authorize (client_id, redirect_uri, state, nonce, PKCE)
   ▼
KandangID :5002  /login → /mfa → cookie kid_sid ─── sso_db (sessions, codes, refresh tokens, MFA)
   │  2. redirect /login/callback?code&state           │ search-then-bind
   │  3. POST /oidc/token → access + id + refresh       ▼
   ▼                                              OpenLDAP :389
booking-api :5000 / pos-api :5001  ← Bearer RS256 token, checked with /.well-known/jwks.json
booking-api ── /oauth/token + /api/v1/users ──▶ KandangID   (profile and password changes)
```

## Getting Started

Docker Desktop must be running.

```bash
# 1. Directory
cd ldap
docker compose up -d
docker exec kandang-ldap ldapadd -x -H ldap://localhost -D "cn=admin,dc=kandang,dc=local" -w admin-local-only -f /ldif/bootstrap.ldif
docker exec kandang-ldap ldapmodify -Y EXTERNAL -H ldapi:/// -f /ldif/acl.ldif
# Git Bash: prefix both docker exec lines with MSYS_NO_PATHCONV=1

# 2. auth-service
cd ../backend
npm install
cp .env.example .env
createdb -U postgres sso_db
npm run db:migrate
npm run keys:generate
npm run client:create -- booking-api "Booking API" "auth:validate users:read users:write"
npm run client:web -- booking-web "Booking" "http://localhost:5173"
npm run client:web -- pos-web "POS" "http://localhost:5174"
npm run dev                # http://localhost:5002 (login pages), Swagger UI at /api/docs

# 3. booking-api (fin-pro/backend/.env)
AUTH_PROVIDER=sso
AUTH_SERVICE_URL=http://127.0.0.1:5002
AUTH_CLIENT_ID=booking-api
AUTH_CLIENT_SECRET=<printed by client:create>
SSO_JWKS_URL=http://127.0.0.1:5002/.well-known/jwks.json
SSO_ISSUER=http://localhost:5002

# 4. pos-api (pos-pro/backend/.env)
SSO_JWKS_URL=http://127.0.0.1:5002/.well-known/jwks.json
SSO_ISSUER=http://localhost:5002

# 5. Web apps (fin-pro/frontend/.env and pos-pro/frontend/.env)
VITE_SSO_URL=http://localhost:5002
VITE_SSO_CLIENT_ID=booking-web     # pos-web in the POS app
```

Use `localhost` everywhere (not `127.0.0.1`) in browser-facing values: `SSO_ISSUER` must equal `PUBLIC_URL` exactly.

Create a test account on the KandangID register page (`/register`), or from either web app.

## Pages and endpoints

| Method | Path | Who calls it | Purpose |
| --- | --- | --- | --- |
| GET | `/` | browser | KandangID home: who is logged in, links to the apps, logout |
| GET/POST | `/login` | browser | Email + password (LDAP bind), CSRF-protected |
| GET/POST | `/mfa` | browser | Code from the authenticator app, or QR setup for admins |
| GET/POST | `/register` | browser | New LDAP entry in `cn=customers`, then logged in |
| GET/POST | `/forgot` | browser | Asks for an email and sends a reset link; without `SMTP_HOST` it says to contact the administrator |
| GET/POST | `/reset?token=…` | browser | Sets a new password from the emailed link; the link works once for 30 minutes |
| GET/POST | `/account/password` | browser | Change password while logged in; other devices are logged out |
| GET/POST | `/admin/users…` | browser (administrators) | Find an account, create its reset link, change its email |
| GET | `/oidc/authorize` | browser | Start of the OIDC flow; an active session gets a code without a form |
| POST | `/oidc/token` | web app (fetch) | `authorization_code` (PKCE) and `refresh_token` (rotation) |
| GET | `/oidc/userinfo` | web app | Claims of the current access token |
| GET | `/oidc/logout` | browser | Ends the KandangID session and its refresh tokens |
| GET | `/.well-known/openid-configuration` | anyone | Discovery document |
| GET | `/.well-known/jwks.json` | booking-api, pos-api | Public keys for RS256 tokens |
| POST | `/oauth/token` | booking-api | `client_credentials` → service token (15 min) |
| POST | `/api/v1/auth/validate` | booking-api | Stage 1 password check |
| GET/POST/PATCH | `/api/v1/users…` | booking-api | Profile, password, role and disabled status |
| GET | `/api/v1/health` | CI | Database and LDAP status |
| GET | `/api/docs` | developer | Swagger UI for the server-to-server API |

In production Nginx (`deploy/nginx/sso.pratitis.net.conf`) answers 404 for `/oauth/` and `/api/`; those stay reachable on 127.0.0.1 only.

## Forgot password and change password

- **Change password** (`/account/password`) needs the current password and a login session. Afterwards every other session of that account ends.
- **Forgot password** works in two modes, chosen by `SMTP_HOST` in `backend/.env`. In both, the user opens a one-time link and chooses the new password; only the SHA-256 of the token is stored, a new link cancels older ones, and every session of the account ends after the reset.
  - **Without email** (default): the page tells the user to ask the administrator (`SUPPORT_CONTACT` is shown there). The administrator creates the link on the VPS and sends it to the owner by any channel:

    ```bash
    npm run user:reset-link -- someone@example.com        # link works for 60 minutes
    npm run user:reset-link -- someone@example.com 15     # or choose 5 to 1440 minutes
    ```

  - **With email** (Gmail): turn on 2-Step Verification, create an App Password at <https://myaccount.google.com/apppasswords>, then set `SMTP_HOST=smtp.gmail.com`, `SMTP_USER` and `SMTP_PASSWORD` (see `.env.example`) and restart. The page then asks for an email and sends the link itself: it expires after 30 minutes, an account gets at most 3 links per hour, and the page answers the same whether or not the email exists, so it cannot be used to find out who has an account.
- **Administrator page** (`/admin/users`, the "Manage users" button on the KandangID home page): an administrator finds an account by name or email, creates a one-time reset link (60 minutes) to send to its owner, changes its email (which also logs the account out everywhere), or deletes it after typing its email to confirm. Deleting removes the LDAP entry plus the sessions, tokens and two-factor secret KandangID holds; the audit log keeps its history. Booking keeps its own copy of the profile because its bookings point at it. Administrator accounts cannot be deleted from the page. Access is checked against the directory on every request, so a demoted or deactivated admin loses it at once. Another administrator's account cannot be changed from the page; use `npm run user:reset-link` on the server for that. Every action is written to the audit log with the administrator who did it.
- **Set a password directly** (the administrator types it, last resort):

```bash
read -s -p "New password: " NEW_PASSWORD; echo
NEW_PASSWORD="$NEW_PASSWORD" npm run user:reset-password -- someone@example.com
```

## Project Structure

```
sso-pro/
├── ldap/                docker-compose.yml, ldif/bootstrap.ldif, ldif/acl.ldif
├── backend/
│   ├── src/
│   │   ├── config/      env (Zod), database, keys (RS256 + JWKS)
│   │   ├── docs/        openapi.js (Swagger spec)
│   │   ├── ldap/        ldap.gateway.js (all LDAP calls), ldap.roles.js (groups → role)
│   │   ├── models/      Client, AuthEvent, SsoSession, AuthorizationCode, RefreshToken, MfaFactor
│   │   ├── modules/
│   │   │   ├── oauth/   client_credentials (stage 1)
│   │   │   ├── auth/    /api/v1/auth/validate (stage 1)
│   │   │   ├── users/   directory accounts
│   │   │   ├── oidc/    authorize, token, userinfo, logout, discovery (stage 2)
│   │   │   └── login/   login, MFA and register pages (stage 2)
│   │   ├── views/       EJS pages: login, mfa, register, home, message
│   │   ├── middlewares/ authenticateClient, ssoSession, csrf, oidcCors, rateLimiter, validate, errorHandler
│   │   └── utils/       tokens, ssha, secretBox, randomToken, audit, OAuthError
│   ├── scripts/         generate-keys, create-client, create-web-client, hash-password
│   └── tests/
├── deploy/nginx/sso.pratitis.net.conf
└── .github/workflows/deploy.yml
```
