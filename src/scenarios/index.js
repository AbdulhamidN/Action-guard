'use strict';

/**
 * Module 13.1 — Scenario Engine & Deterministic Demo Fixtures
 *
 * Public API for running scenarios, inspecting observed decisions, and safe cleanup.
 */

const {
  SCENARIOS,
  getScenarioDefinition,
  listScenarioDefinitions,
  validateScenarioDefinition
} = require('./definitions');
const { runScenario, compareFalsePositive } = require('./scenarioRunner');
const { cleanupScenarioRun } = require('./cleanup');

module.exports = {
  SCENARIOS,
  getScenarioDefinition,
  listScenarioDefinitions,
  validateScenarioDefinition,
  runScenario,
  compareFalsePositive,
  cleanupScenarioRun
};
