'use strict';

/**
 * Migration 011: Dashboard Overview and Admin Query Indexes
 *
 * Adds narrow covering indexes to eliminate table scans on:
 * 1. policy_decisions (enforcement_outcome, decided_at, session_id) - for overview outcome aggregates and contained sessions
 * 2. risk_assessments (risk_tier, evaluated_at) - for overview risk tier aggregates
 * 3. sessions (is_active, expires_at, user_id) - for active sessions count and user session aggregates
 */
module.exports = {
  up: async (queryInterface) => {
    // 1. policy_decisions time-leading covering index
    const policyIndexes = await queryInterface.showIndex('policy_decisions').catch(() => []);
    const policyIndexNames = policyIndexes.map((idx) => idx.name);

    if (!policyIndexNames.includes('idx_policy_decisions_decided_outcome')) {
      await queryInterface.addIndex('policy_decisions', ['decided_at', 'enforcement_outcome', 'effective_decision', 'session_id'], {
        name: 'idx_policy_decisions_decided_outcome'
      });
    }

    // 2. risk_assessments time-leading covering index for overview
    const riskIndexes = await queryInterface.showIndex('risk_assessments').catch(() => []);
    const riskIndexNames = riskIndexes.map((idx) => idx.name);

    if (!riskIndexNames.includes('idx_risk_assessments_evaluated_tier')) {
      await queryInterface.addIndex('risk_assessments', ['evaluated_at', 'risk_tier'], {
        name: 'idx_risk_assessments_evaluated_tier'
      });
    }

    // 3. risk_assessments covering index for latest-risk-tier per user
    if (!riskIndexNames.includes('idx_risk_assessments_user_eval_tier')) {
      await queryInterface.addIndex('risk_assessments', ['user_id', 'evaluated_at', 'id', 'risk_tier'], {
        name: 'idx_risk_assessments_user_eval_tier'
      });
    }

    // 4. sessions active covering index
    const sessionIndexes = await queryInterface.showIndex('sessions').catch(() => []);
    const sessionIndexNames = sessionIndexes.map((idx) => idx.name);

    if (!sessionIndexNames.includes('idx_sessions_active_expires_user')) {
      await queryInterface.addIndex('sessions', ['is_active', 'expires_at', 'user_id'], {
        name: 'idx_sessions_active_expires_user'
      });
    }
  },

  down: async (queryInterface) => {
    const sessionIndexes = await queryInterface.showIndex('sessions').catch(() => []);
    const sessionIndexNames = sessionIndexes.map((idx) => idx.name);
    if (sessionIndexNames.includes('idx_sessions_active_expires_user')) {
      await queryInterface.removeIndex('sessions', 'idx_sessions_active_expires_user');
    }

    const riskIndexes = await queryInterface.showIndex('risk_assessments').catch(() => []);
    const riskIndexNames = riskIndexes.map((idx) => idx.name);
    if (riskIndexNames.includes('idx_risk_assessments_user_eval_tier')) {
      await queryInterface.removeIndex('risk_assessments', 'idx_risk_assessments_user_eval_tier');
    }
    if (riskIndexNames.includes('idx_risk_assessments_evaluated_tier')) {
      await queryInterface.removeIndex('risk_assessments', 'idx_risk_assessments_evaluated_tier');
    }

    const policyIndexes = await queryInterface.showIndex('policy_decisions').catch(() => []);
    const policyIndexNames = policyIndexes.map((idx) => idx.name);
    if (policyIndexNames.includes('idx_policy_decisions_decided_outcome')) {
      await queryInterface.removeIndex('policy_decisions', 'idx_policy_decisions_decided_outcome');
    }
    if (policyIndexNames.includes('idx_policy_decisions_outcome_decided_session')) {
      await queryInterface.removeIndex('policy_decisions', 'idx_policy_decisions_outcome_decided_session');
    }
    if (policyIndexNames.includes('idx_risk_assessments_tier_evaluated')) {
      await queryInterface.removeIndex('risk_assessments', 'idx_risk_assessments_tier_evaluated');
    }
  }
};
