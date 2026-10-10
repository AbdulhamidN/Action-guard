const http = require('http');
const app = require('./app');
const {
  startBaselineRecalculationSchedule,
  stopBaselineRecalculationSchedule
} = require('./jobs/baselineRecalculationJob');
const {
  initSocketServer,
  closeSocketServer
} = require('./realtime/socketServer');

const PORT = process.env.PORT || 3000;

const server = http.createServer(app);
initSocketServer(server);

server.listen(PORT, () => {
  console.log(`ActionGuard server running on port ${PORT}`);

  if (process.env.BASELINE_RECALCULATION_AUTO_START !== 'false') {
    startBaselineRecalculationSchedule();
    console.log('[Scheduler] Baseline recalculation job scheduled.');
  }
});

async function gracefulShutdown(signal) {
  console.log(`Received ${signal}. Shutting down gracefully...`);
  stopBaselineRecalculationSchedule();
  try {
    await closeSocketServer();
  } catch (err) {
    console.warn('Error closing socket server:', err.message);
  }
  if (server.listening) {
    server.close(() => {
      console.log('ActionGuard HTTP server closed.');
      process.exit(0);
    });
  } else {
    console.log('ActionGuard HTTP server closed.');
    process.exit(0);
  }
}


process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

