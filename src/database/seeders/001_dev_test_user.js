/**
 * DEVELOPMENT ONLY SEED DATA
 * WARNING: Do not execute in production environments!
 * This seed creates a single test user for local development and verification.
 */

module.exports = {
  up: async (queryInterface) => {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('Refusing to execute development seed in production environment!');
    }

    const testUser = {
      id: 'dev-test-user-00000000-000000000001',
      email: 'dev-seed-user@actionguard.test',
      // Dummy hash for development/test purposes only
      password_hash: '$2b$10$devdummyhashforseedonlynotforproduction0000000000000000',
      created_at: new Date(),
      updated_at: new Date()
    };

    // Upsert or insert if not exists
    const existing = await queryInterface.rawSelect(
      'users',
      {
        where: { email: testUser.email }
      },
      ['id']
    );

    if (!existing) {
      await queryInterface.bulkInsert('users', [testUser]);
      console.log(`[Seed: DEV ONLY] Inserted development test user: ${testUser.email}`);
    } else {
      console.log(`[Seed: DEV ONLY] Development test user already exists: ${testUser.email}`);
    }
  },

  down: async (queryInterface) => {
    await queryInterface.bulkDelete('users', {
      email: 'dev-seed-user@actionguard.test'
    });
  }
};
