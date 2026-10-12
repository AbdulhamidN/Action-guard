const express = require('express');
const helmet = require('helmet');
const authRouter = require('./routes/auth');
const meRouter = require('./routes/me');
const eventsRouter = require('./routes/events');
const sequencesRouter = require('./routes/sequences');
const riskRouter = require('./routes/risk');
const sessionsRouter = require('./routes/sessions');
const policyRouter = require('./routes/policy');
const accountActionsRouter = require('./routes/accountActions');
const coolingOffRouter = require('./routes/coolingOff');
const { setDelayHandler } = require('./middleware/pep');
const { coolingOffDelayHandler } = require('./services/coolingOffService');
const {
  authRateLimiter,
  sensitiveActionRateLimiter,
  apiRateLimiter
} = require('./middleware/rateLimiter');
const {
  validateRequestEnvelope,
  jsonBodyErrorHandler
} = require('./middleware/validation');

// Connect cooling-off delay handler to PEP
setDelayHandler(coolingOffDelayHandler);

const app = express();

app.disable('x-powered-by');

// 1. Helmet security headers
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'none'"],
        baseUri: ["'none'"],
        formAction: ["'none'"],
        frameAncestors: ["'none'"],
        objectSrc: ["'none'"]
      }
    },
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    crossOriginResourcePolicy: { policy: 'same-origin' },
    dnsPrefetchControl: { allow: false },
    frameguard: { action: 'deny' },
    hidePoweredBy: true,
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: false
    },
    ieNoOpen: true,
    noSniff: true,
    originAgentCluster: true,
    permittedCrossDomainPolicies: { permittedPolicies: 'none' },
    referrerPolicy: { policy: 'no-referrer' },
    xssFilter: true
  })
);

// 2. Body parsing with explicit size limit (default 64kb)
app.use(
  express.json({
    limit: process.env.JSON_BODY_LIMIT || '64kb'
  })
);

// 3. Malformed JSON / 413 error handling and request-envelope / prototype-pollution validation
app.use(jsonBodyErrorHandler);
app.use(validateRequestEnvelope);

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok'
  });
});

// 4 & 5. Tiered rate limiting followed by authentication, PEP, risk evaluation, and cooling-off enforcement
// Authentication & session routes (PEP route layer)
app.use('/api/v1/auth', authRateLimiter, authRouter);

// Protected user route
app.use('/api/v1/me', apiRateLimiter, meRouter);

// Security events query route (PEP route layer)
app.use('/api/v1/events', apiRateLimiter, eventsRouter);

// Action sequences query route
app.use('/api/v1/sequences', apiRateLimiter, sequencesRouter);

// Risk evaluation routes (PDP advisory layer)
app.use('/api/v1/risk', apiRateLimiter, riskRouter);

// Sessions query routes (PDP session state inspection & step-up elevation; step-up/api limiters applied per route)
app.use('/api/v1/sessions', sessionsRouter);

// Policy decision routes (PDP advisory layer)
app.use('/api/v1/policy', apiRateLimiter, policyRouter);

// Protected sensitive account action routes (PEP enforcement layer)
app.use('/api/v1/account', sensitiveActionRateLimiter, accountActionsRouter);

// Cooling-off delayed action routes (PEP cooling-off layer)
app.use('/api/v1/cooling-off', sensitiveActionRateLimiter, coolingOffRouter);

module.exports = app;
