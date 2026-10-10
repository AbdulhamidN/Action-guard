const express = require('express');
const helmet = require('helmet');
const authRouter = require('./routes/auth');
const meRouter = require('./routes/me');
const eventsRouter = require('./routes/events');
const sequencesRouter = require('./routes/sequences');
const riskRouter = require('./routes/risk');
const sessionsRouter = require('./routes/sessions');

const app = express();

app.use(helmet());
app.use(express.json());

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok'
  });
});

// Authentication & session routes (PEP route layer)
app.use('/api/v1/auth', authRouter);

// Protected user route
app.use('/api/v1/me', meRouter);

// Security events query route (PEP route layer)
app.use('/api/v1/events', eventsRouter);

// Action sequences query route
app.use('/api/v1/sequences', sequencesRouter);

// Risk evaluation routes (PDP advisory layer)
app.use('/api/v1/risk', riskRouter);

// Sessions query routes (PDP session state inspection)
app.use('/api/v1/sessions', sessionsRouter);

module.exports = app;
