const express = require('express');
const { loadSession } = require('../../middlewares/ssoSession');
const { oidcCors } = require('../../middlewares/oidcCors');
const { tokenLimiter } = require('../../middlewares/rateLimiter');
const controller = require('./oidc.controller');

// Discovery documents: public, read by apps and by booking-api / pos-api for the public keys
const wellKnown = express.Router();
wellKnown.get('/openid-configuration', controller.discovery);
wellKnown.get('/jwks.json', controller.jwks);

// OpenID Connect endpoints used by the browser apps
const oidc = express.Router();
oidc.get('/authorize', loadSession, controller.authorize);
// The token body is form-encoded as the spec says; called with fetch from booking-web and pos-web
oidc.options('/token', oidcCors);
oidc.post('/token', oidcCors, express.urlencoded({ extended: false }), tokenLimiter, controller.token);
oidc.options('/userinfo', oidcCors);
oidc.get('/userinfo', oidcCors, controller.userinfo);
oidc.get('/logout', loadSession, controller.logout);

module.exports = { wellKnown, oidc };
