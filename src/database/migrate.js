const fs = require('fs');
const path = require('path');
const sequelize = require('./index');

async function runMigrations() {
  console.log('[Migration] Starting database migrations...');
  const queryInterface = sequelize.getQueryInterface();

  const migrationsDir = path.join(__dirname, 'migrations');
  const files = fs.readdirSync(migrationsDir).filter(f => f.endsWith('.js')).sort();

  for (const file of files) {
    console.log(`[Migration] Applying ${file}...`);
    const migration = require(path.join(migrationsDir, file));
    await migration.up(queryInterface, sequelize);
    console.log(`[Migration] Applied ${file} successfully.`);
  }

  console.log('[Migration] All migrations executed successfully.');
}

if (require.main === module) {
  runMigrations()
    .then(async () => {
      await sequelize.close();
      process.exit(0);
    })
    .catch(async (err) => {
      console.error('[Migration] Migration failed:', err);
      await sequelize.close();
      process.exit(1);
    });
}

module.exports = { runMigrations };
