'use strict';

const { DataTypes } = require('sequelize');

/**
 * Migration 012: Trusted Devices Lifecycle & Indexing Foundation (Module 12d-1)
 *
 * 1. Extends devices table with lifecycle fields:
 *    - label (VARCHAR(100), nullable)
 *    - trusted_at (DATETIME(3), nullable)
 *    - expires_at (DATETIME(3), nullable)
 *    - revoked_at (DATETIME(3), nullable)
 *    - last_used_at (DATETIME(3), nullable)
 * 2. Checks and safely consolidates any pre-existing duplicate (user_id, fingerprint) pairs
 *    preserving highest trust status before adding unique index.
 * 3. Adds indexes:
 *    - idx_devices_user_fingerprint (UNIQUE on user_id, fingerprint)
 *    - idx_devices_user_trusted (user_id, is_trusted, expires_at)
 *    - idx_devices_user_last_used (user_id, last_used_at)
 *
 * Database Dialect & Transactional Invariant Note:
 * MySQL executes implicit commits on Data Definition Language (DDL) statements (ALTER TABLE,
 * CREATE TABLE, CREATE/DROP INDEX). Consequently, transactional atomicity across mixed DDL/DML
 * operations cannot be provided by SQL transactions in MySQL.
 * To guarantee safety and non-destructive failure recovery, this migration is designed with
 * strict idempotency, pre-verification checks, durable archiving prior to duplicate removal,
 * comprehensive data verification before dropping the archive, and fail-closed integrity checks on retry.
 */
module.exports = {
  up: async (queryInterface) => {
    // 1. Add lifecycle columns to devices idempotently
    const columns = await queryInterface.describeTable('devices');

    if (!columns.label) {
      await queryInterface.addColumn('devices', 'label', {
        type: DataTypes.STRING(100),
        allowNull: true,
        defaultValue: null
      });
    }

    if (!columns.trusted_at) {
      await queryInterface.addColumn('devices', 'trusted_at', {
        type: DataTypes.DATE(3),
        allowNull: true,
        defaultValue: null
      });
    }

    if (!columns.expires_at) {
      await queryInterface.addColumn('devices', 'expires_at', {
        type: DataTypes.DATE(3),
        allowNull: true,
        defaultValue: null
      });
    }

    if (!columns.revoked_at) {
      await queryInterface.addColumn('devices', 'revoked_at', {
        type: DataTypes.DATE(3),
        allowNull: true,
        defaultValue: null
      });
    }

    if (!columns.last_used_at) {
      await queryInterface.addColumn('devices', 'last_used_at', {
        type: DataTypes.DATE(3),
        allowNull: true,
        defaultValue: null
      });
    }

    // 2. Ensure durable archive table exists before consolidating duplicates
    const ARCHIVE_TABLE = 'devices_duplicate_archive_012';
    const tables = await queryInterface.showAllTables();
    const tableNames = tables.map((t) => (typeof t === 'string' ? t : t.tableName || Object.values(t)[0]));

    if (!tableNames.includes(ARCHIVE_TABLE)) {
      await queryInterface.createTable(ARCHIVE_TABLE, {
        id: {
          type: DataTypes.STRING(64),
          primaryKey: true,
          allowNull: false
        },
        user_id: {
          type: DataTypes.STRING(64),
          allowNull: false
        },
        fingerprint: {
          type: DataTypes.STRING(255),
          allowNull: false
        },
        is_trusted: {
          type: DataTypes.BOOLEAN,
          allowNull: false,
          defaultValue: false
        },
        first_seen_at: {
          type: DataTypes.DATE,
          allowNull: false
        },
        canonical_device_id: {
          type: DataTypes.STRING(64),
          allowNull: false
        },
        archived_at: {
          type: DataTypes.DATE(3),
          allowNull: false,
          defaultValue: DataTypes.NOW
        },
        archive_reason: {
          type: DataTypes.STRING(100),
          allowNull: false,
          defaultValue: 'migration_012_deduplication'
        }
      });
    }

    // 3. Check for duplicate (user_id, fingerprint) records before creating unique index
    const [duplicates] = await queryInterface.sequelize.query(`
      SELECT user_id, fingerprint, COUNT(*) as cnt
      FROM devices
      GROUP BY user_id, fingerprint
      HAVING cnt > 1
    `);

    if (duplicates && duplicates.length > 0) {
      for (const dup of duplicates) {
        // Deterministic ordering: prioritize trusted rows, earliest first_seen_at, then deterministic id tie-breaker
        const [rows] = await queryInterface.sequelize.query(
          `SELECT id, user_id, fingerprint, is_trusted, first_seen_at
           FROM devices
           WHERE user_id = :userId AND fingerprint = :fingerprint
           ORDER BY is_trusted DESC, first_seen_at ASC, id ASC`,
          {
            replacements: { userId: dup.user_id, fingerprint: dup.fingerprint }
          }
        );

        if (rows && rows.length > 1) {
          const canonicalRow = rows[0];
          const duplicateRows = rows.slice(1);

          // Archive each duplicate row before deleting from devices
          for (const dupRow of duplicateRows) {
            const [existingArchive] = await queryInterface.sequelize.query(
              `SELECT id, user_id, fingerprint, is_trusted, first_seen_at, canonical_device_id, archived_at
               FROM ${ARCHIVE_TABLE}
               WHERE id = :id`,
              { replacements: { id: dupRow.id } }
            );

            if (existingArchive && existingArchive.length > 0) {
              const ea = existingArchive[0];
              const isEaMatch =
                ea.user_id === dupRow.user_id &&
                ea.fingerprint === dupRow.fingerprint &&
                Boolean(ea.is_trusted) === Boolean(dupRow.is_trusted) &&
                new Date(ea.first_seen_at).getTime() === new Date(dupRow.first_seen_at).getTime() &&
                ea.canonical_device_id === canonicalRow.id;

              if (!isEaMatch) {
                throw new Error(
                  `Archive integrity violation: record '${dupRow.id}' already exists in ${ARCHIVE_TABLE} with conflicting data (mismatched user, fingerprint, trust state, first_seen_at, or canonical reference). Aborting migration.`
                );
              }
              // Preserves original archive entry on retry without altering archived_at or canonical_device_id
            } else {
              await queryInterface.sequelize.query(
                `INSERT INTO ${ARCHIVE_TABLE}
                 (id, user_id, fingerprint, is_trusted, first_seen_at, canonical_device_id, archived_at, archive_reason)
                 SELECT id, user_id, fingerprint, is_trusted, first_seen_at, :canonicalId, NOW(3), 'migration_012_deduplication'
                 FROM devices
                 WHERE id = :id`,
                {
                  replacements: {
                    id: dupRow.id,
                    canonicalId: canonicalRow.id
                  }
                }
              );
            }
          }

          // Only after successful archive insertion, remove duplicate IDs from devices
          const duplicateIds = duplicateRows.map((r) => r.id);
          await queryInterface.sequelize.query(
            'DELETE FROM devices WHERE id IN (:ids)',
            {
              replacements: { ids: duplicateIds }
            }
          );
        }
      }
    }

    // 4. Add indexes
    const indexes = await queryInterface.showIndex('devices').catch(() => []);
    const indexNames = indexes.map((idx) => idx.name);

    if (!indexNames.includes('idx_devices_user_fingerprint')) {
      await queryInterface.addIndex('devices', ['user_id', 'fingerprint'], {
        name: 'idx_devices_user_fingerprint',
        unique: true
      });
    }

    if (!indexNames.includes('idx_devices_user_trusted')) {
      await queryInterface.addIndex('devices', ['user_id', 'is_trusted', 'expires_at'], {
        name: 'idx_devices_user_trusted'
      });
    }

    if (!indexNames.includes('idx_devices_user_last_used')) {
      await queryInterface.addIndex('devices', ['user_id', 'last_used_at'], {
        name: 'idx_devices_user_last_used'
      });
    }

    // Clean up fallback index if present from a prior rollback
    const postIndexes = await queryInterface.showIndex('devices').catch(() => []);
    if (postIndexes.some((idx) => idx.name === 'devices_user_id_fk')) {
      await queryInterface.removeIndex('devices', 'devices_user_id_fk').catch(() => {});
    }
  },

  down: async (queryInterface) => {
    // 1. Ensure foreign key constraint on user_id remains satisfied throughout index removal
    await queryInterface.addIndex('devices', ['user_id'], { name: 'devices_user_id_fk' }).catch(() => {});

    // 2. Remove unique and compound indexes before restoring duplicates
    const indexes = await queryInterface.showIndex('devices').catch(() => []);
    const indexNames = indexes.map((idx) => idx.name);

    if (indexNames.includes('idx_devices_user_last_used')) {
      await queryInterface.removeIndex('devices', 'idx_devices_user_last_used');
    }

    if (indexNames.includes('idx_devices_user_trusted')) {
      await queryInterface.removeIndex('devices', 'idx_devices_user_trusted');
    }

    // Dropping unique index MUST occur before restoring duplicate rows into devices
    if (indexNames.includes('idx_devices_user_fingerprint')) {
      await queryInterface.removeIndex('devices', 'idx_devices_user_fingerprint');
    }

    // 3. Documented restoration / recovery path: restore archived duplicate records back to devices
    const ARCHIVE_TABLE = 'devices_duplicate_archive_012';
    const tables = await queryInterface.showAllTables();
    const tableNames = tables.map((t) => (typeof t === 'string' ? t : t.tableName || Object.values(t)[0]));

    if (tableNames.includes(ARCHIVE_TABLE)) {
      // Pre-check: Ensure unique constraint covering fingerprint is not active before restoring duplicates
      const postDropIndexes = await queryInterface.showIndex('devices').catch(() => []);
      const uniqueConflict = postDropIndexes.find(
        (idx) => idx.unique && idx.fields.some((f) => f.attribute === 'fingerprint')
      );
      if (uniqueConflict) {
        throw new Error(
          `Restoration conflict: unique constraint '${uniqueConflict.name}' covering fingerprint is still active on devices table. Aborting rollback to preserve archive.`
        );
      }

      const [archivedRows] = await queryInterface.sequelize.query(
        `SELECT id, user_id, fingerprint, is_trusted, first_seen_at FROM ${ARCHIVE_TABLE}`
      );

      if (archivedRows && archivedRows.length > 0) {
        for (const row of archivedRows) {
          // Detect primary key conflicts and verify whether existing row data is identical
          const [existing] = await queryInterface.sequelize.query(
            'SELECT id, user_id, fingerprint, is_trusted, first_seen_at FROM devices WHERE id = :id',
            { replacements: { id: row.id } }
          );

          if (existing && existing.length > 0) {
            const existingRow = existing[0];
            const isMatch =
              existingRow.user_id === row.user_id &&
              existingRow.fingerprint === row.fingerprint &&
              Boolean(existingRow.is_trusted) === Boolean(row.is_trusted) &&
              new Date(existingRow.first_seen_at).getTime() === new Date(row.first_seen_at).getTime();

            if (!isMatch) {
              throw new Error(
                `Restoration conflict: device with id '${row.id}' already exists in devices with conflicting data. Aborting rollback to preserve archive.`
              );
            }
            // Existing row is identical, already restored
          } else {
            try {
              await queryInterface.sequelize.query(
                `INSERT INTO devices (id, user_id, fingerprint, is_trusted, first_seen_at)
                 SELECT id, user_id, fingerprint, is_trusted, first_seen_at
                 FROM ${ARCHIVE_TABLE}
                 WHERE id = :id`,
                {
                  replacements: {
                    id: row.id
                  }
                }
              );
            } catch (insertErr) {
              if (insertErr.name === 'SequelizeUniqueConstraintError' || insertErr.code === 'ER_DUP_ENTRY') {
                throw new Error(
                  `Restoration conflict: unique constraint violation on restoring device '${row.id}'. Aborting rollback to preserve archive.`
                );
              }
              throw insertErr;
            }
          }
        }

        // Independently verify that EVERY archived record is present in devices and matches before dropping archive
        for (const row of archivedRows) {
          const [verified] = await queryInterface.sequelize.query(
            'SELECT id, user_id, fingerprint, is_trusted, first_seen_at FROM devices WHERE id = :id',
            { replacements: { id: row.id } }
          );

          if (!verified || verified.length === 0) {
            throw new Error(
              `Restoration verification failed: device '${row.id}' not found in devices table after restoration. Aborting rollback to preserve archive.`
            );
          }

          const v = verified[0];
          const isVerifiedMatch =
            v.user_id === row.user_id &&
            v.fingerprint === row.fingerprint &&
            Boolean(v.is_trusted) === Boolean(row.is_trusted) &&
            new Date(v.first_seen_at).getTime() === new Date(row.first_seen_at).getTime();

          if (!isVerifiedMatch) {
            throw new Error(
              `Restoration verification failed: device '${row.id}' in devices table does not match archived record. Aborting rollback to preserve archive.`
            );
          }
        }
      }

      // Drop archive table ONLY after all rows are restored and independently verified
      await queryInterface.dropTable(ARCHIVE_TABLE);
    }

    // 4. Remove columns
    const columns = await queryInterface.describeTable('devices');

    if (columns.last_used_at) {
      await queryInterface.removeColumn('devices', 'last_used_at');
    }

    if (columns.revoked_at) {
      await queryInterface.removeColumn('devices', 'revoked_at');
    }

    if (columns.expires_at) {
      await queryInterface.removeColumn('devices', 'expires_at');
    }

    if (columns.trusted_at) {
      await queryInterface.removeColumn('devices', 'trusted_at');
    }

    if (columns.label) {
      await queryInterface.removeColumn('devices', 'label');
    }
  }
};
