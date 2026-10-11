const http = require('http');
const app = require('./app');
const {
  startBaselineRecalculationSchedule,
  stopBaselineRecalculationSchedule
} = require('./jobs/baselineRecalculationJob');
const {
  startCoolingOffWorker,
  stopCoolingOffWorker
} = require('./jobs/coolingOffWorker');
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

  if (process.env.COOLING_OFF_WORKER_AUTO_START !== 'false') {
    startCoolingOffWorker();
    console.log('[Scheduler] Cooling-off enforcement worker started.');
  }
});

async function gracefulShutdown(signal) {
  console.log(`Received ${signal}. Shutting down gracefully...`);
  stopBaselineRecalculationSchedule();
  stopCoolingOffWorker();
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
