const path = require('path');
const express = require('express');
const helmet = require('helmet');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const swaggerUi = require('swagger-ui-express');
const env = require('./config/env');
const openapiSpec = require('./docs/openapi');
const routes = require('./routes');
const { wellKnown, oidc } = require('./modules/oidc/oidc.routes');
const loginPages = require('./modules/login/login.routes');
const adminPages = require('./modules/admin/admin.routes');
const notFound = require('./middlewares/notFound');
const errorHandler = require('./middlewares/errorHandler');

const app = express();

// Behind Nginx in production: needed for the real client IP and for Secure cookies over HTTPS
app.set('trust proxy', 1);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.disable('x-powered-by');

// Mounted before helmet because Swagger UI needs inline scripts
app.get('/api/docs.json', (req, res) => res.json(openapiSpec));
app.use(
  '/api/docs',
  swaggerUi.serve,
  swaggerUi.setup(openapiSpec, { customSiteTitle: 'KandangID API Docs', swaggerOptions: { persistAuthorization: true } }),
);

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        // After the login form the browser follows redirects to the registered apps; return_to is already limited to /oidc/authorize
        'form-action': null,
        // The login page must never be shown inside another site's frame (clickjacking)
        'frame-ancestors': ["'none'"],
        // Plain http on the laptop would break if the browser upgraded every request to https
        'upgrade-insecure-requests': env.COOKIE_SECURE ? [] : null,
      },
    },
  }),
);
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieParser());
app.use(express.json({ limit: '100kb' }));
if (env.NODE_ENV !== 'test') app.use(morgan(env.NODE_ENV === 'production' ? 'combined' : 'dev'));

// Stage 1: server-to-server API for booking-api
app.use('/oauth', require('./modules/oauth/oauth.routes'));
app.use('/api/v1', routes);

// Stage 2: single sign-on for the browser apps
app.use('/.well-known', wellKnown);
app.use('/oidc', oidc);
app.use('/admin', adminPages);
app.use('/', loginPages);

app.use(notFound);
app.use(errorHandler);

module.exports = app;
