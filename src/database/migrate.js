const fs = require('fs');
const path = require('path');
const sequelize = require('./index');

async function runMigrations() {
  console.log('[Migration] Starting database migrations...');
  const queryInterface = sequelize.getQueryInterface();

  const migrationsDir = path.join(__dirname, 'migrations');
  const files = fs.readdirSync(migrationsDir).filter(f => f.endsWith('.js')).sort();

  for (const file of files) {
    try {
      console.log(`[Migration] Applying ${file}...`);
      const migration = require(path.join(migrationsDir, file));
      await migration.up(queryInterface, sequelize);
      console.log(`[Migration] Applied ${file} successfully.`);
    } catch (migErr) {
      const isAlreadyExists =
        migErr.name === 'SequelizeDatabaseError' &&
        (migErr.message.includes('already exists') ||
         migErr.original?.code === 'ER_TABLE_EXISTS_ERROR' ||
         migErr.original?.code === 'ER_DUP_KEYNAME');
      if (isAlreadyExists) {
        console.log(`[Migration] ${file} already applied or partially present, continuing.`);
      } else {
        throw migErr;
      }
    }
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
