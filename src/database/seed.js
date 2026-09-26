const fs = require('fs');
const path = require('path');
const sequelize = require('./index');

async function runSeeds() {
  if (process.env.NODE_ENV === 'production') {
    throw new Error('Refusing to execute development seeds in production environment!');
  }

  console.log('[Seed] Starting database seeding (development only)...');
  const queryInterface = sequelize.getQueryInterface();

  const seedersDir = path.join(__dirname, 'seeders');
  const files = fs.readdirSync(seedersDir).filter(f => f.endsWith('.js')).sort();

  for (const file of files) {
    console.log(`[Seed] Applying ${file}...`);
    const seeder = require(path.join(seedersDir, file));
    await seeder.up(queryInterface, sequelize);
    console.log(`[Seed] Applied ${file} successfully.`);
  }

  console.log('[Seed] Database seeding completed successfully.');
}

if (require.main === module) {
  runSeeds()
    .then(async () => {
      await sequelize.close();
      process.exit(0);
    })
    .catch(async (err) => {
      console.error('[Seed] Seeding failed:', err);
      await sequelize.close();
      process.exit(1);
    });
}

module.exports = { runSeeds };
