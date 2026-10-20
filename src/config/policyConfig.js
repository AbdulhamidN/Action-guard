/**
 * Policy Configuration Entry Point (Module 8 & Module 9)
 *
 * Exposes the currently active, validated, and deeply frozen policy configuration.
 * Powered by policyLoader, which loads the active policy from versioned JSON files
 * (defaulting to policies/default-v1.json).
 *
 * Maintains 100% backward-compatible export shape for existing callers.
 */

const { loadActivePolicy } = require('../services/policyLoader');

const policyConfig = loadActivePolicy();

module.exports = policyConfig;
