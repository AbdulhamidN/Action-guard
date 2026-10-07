const app = require('./app');
const {
  startBaselineRecalculationSchedule,
  stopBaselineRecalculationSchedule
} = require('./jobs/baselineRecalculationJob');

const PORT = process.env.PORT || 3000;

const server = app.listen(PORT, () => {
  console.log(`ActionGuard server running on port ${PORT}`);

  if (process.env.BASELINE_RECALCULATION_AUTO_START !== 'false') {
    startBaselineRecalculationSchedule();
    console.log('[Scheduler] Baseline recalculation job scheduled.');
  }
});

function gracefulShutdown(signal) {
  console.log(`Received ${signal}. Shutting down gracefully...`);
  stopBaselineRecalculationSchedule();
  server.close(() => {
    console.log('ActionGuard HTTP server closed.');
    process.exit(0);
  });
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
