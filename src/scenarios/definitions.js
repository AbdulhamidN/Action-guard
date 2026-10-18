'use strict';

const { SecurityEvent } = require('../database/models');

/**
 * Authoritative Scenario Definitions (Module 13.1 — Attack Simulation & Demo Scenarios)
 *
 * Defines deterministic scenario sequences using only valid ActionGuard event types
 * and supported signals.
 *
 * Rules:
 * - Deterministic, realistic event sequences.
 * - All event types must be recognized in SecurityEvent.SUPPORTED_EVENT_TYPES.
 * - No hardcoded risk scores or predetermined outcomes.
 * - Real pipeline calculates all evaluations.
 */

const SCENARIOS = Object.freeze({
  scenario_a: Object.freeze({
    id: 'scenario_a',
    alias: 'scenario_a_normal_user',
    name: 'Scenario A: Normal User Activity',
    scenario_type: 'benign',
    description:
      'Legitimate user establishes a session from a known corporate workstation in their home country, conducts routine session activity, and performs a representative profile update.',
    expected_interpretation:
      'Legitimate user with consistent device and geographical signals. Risk should remain low throughout, resulting in allow decisions without security friction.',
    expected_outcome: {
      target_decision: 'allow',
      max_acceptable_decision: 'monitor'
    },
    baseline_events: [
      {
        event_type: 'login_success',
        time_offset_ms: -3600000, // 1 hour prior
        context: {
          device_fingerprint: 'fp_demo_known_workstation_01',
          ip_address: '198.51.100.10',
          geo_country: 'US',
          geo_region: 'CA',
          user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ActionGuardDemo/1.0'
        },
        metadata: {
          action_sensitivity: 'low'
        }
      }
    ],
    steps: [
      {
        step_number: 1,
        name: 'Normal session login from recognized workstation',
        event_type: 'login_success',
        time_offset_ms: 0,
        context: {
          device_fingerprint: 'fp_demo_known_workstation_01',
          ip_address: '198.51.100.10',
          geo_country: 'US',
          geo_region: 'CA',
          user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ActionGuardDemo/1.0'
        },
        metadata: {
          action_sensitivity: 'low'
        }
      },
      {
        step_number: 2,
        name: 'Routine profile update (phone number change)',
        event_type: 'phone_number_change',
        time_offset_ms: 60000, // 1 minute later
        context: {
          device_fingerprint: 'fp_demo_known_workstation_01',
          ip_address: '198.51.100.10',
          geo_country: 'US',
          geo_region: 'CA',
          user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ActionGuardDemo/1.0'
        },
        metadata: {
          action_sensitivity: 'medium'
        },
        route: '/api/v1/account/phone',
        route_payload: {
          phone_number: '+14155552671'
        }
      },
      {
        step_number: 3,
        name: 'Subsequent normal session activity',
        event_type: 'login_success',
        time_offset_ms: 120000, // 2 minutes later
        context: {
          device_fingerprint: 'fp_demo_known_workstation_01',
          ip_address: '198.51.100.10',
          geo_country: 'US',
          geo_region: 'CA',
          user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ActionGuardDemo/1.0'
        },
        metadata: {
          action_sensitivity: 'low'
        }
      }
    ]
  }),

  scenario_b: Object.freeze({
    id: 'scenario_b',
    alias: 'scenario_b_simulated_takeover',
    name: 'Scenario B: Simulated Account Takeover',
    scenario_type: 'simulated_takeover',
    description:
      'Attacker accesses the account from an unrecognized device and foreign geographic location, rapidly modifies account recovery credentials, and attempts a high-impact operation.',
    expected_interpretation:
      'Suspicious progression exhibiting device novelty, country novelty, and seq_takeover_progression pattern. Risk score escalates to High/Critical, triggering policy containment and account lock.',
    expected_outcome: {
      min_protective_decision: 'reverify',
      target_decision: 'block'
    },
    baseline_events: [
      {
        event_type: 'login_success',
        time_offset_ms: -3600000, // 1 hour prior in US
        context: {
          device_fingerprint: 'fp_demo_known_workstation_01',
          ip_address: '198.51.100.10',
          geo_country: 'US',
          geo_region: 'CA',
          user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ActionGuardDemo/1.0'
        },
        metadata: {
          action_sensitivity: 'low'
        }
      }
    ],
    steps: [
      {
        step_number: 1,
        name: 'Attacker login from unrecognized device in foreign location',
        event_type: 'login_success',
        time_offset_ms: 0,
        context: {
          device_fingerprint: 'fp_attacker_external_device_99',
          ip_address: '203.0.113.50',
          geo_country: 'RU',
          geo_region: 'MOW',
          user_agent: 'Mozilla/5.0 (X11; Linux x86_64) AttackerProbe/1.0'
        },
        metadata: {
          action_sensitivity: 'low'
        }
      },
      {
        step_number: 2,
        name: 'Attacker attempts credential tampering (recovery email change)',
        event_type: 'recovery_email_change',
        time_offset_ms: 30000, // 30 seconds later
        context: {
          device_fingerprint: 'fp_attacker_external_device_99',
          ip_address: '203.0.113.50',
          geo_country: 'RU',
          geo_region: 'MOW',
          user_agent: 'Mozilla/5.0 (X11; Linux x86_64) AttackerProbe/1.0'
        },
        metadata: {
          action_sensitivity: 'high'
        },
        route: '/api/v1/account/recovery-email',
        route_payload: {
          recovery_email: 'attacker-exfil@external-threat.test'
        }
      },
      {
        step_number: 3,
        name: 'Attacker attempts high-impact operation (seq_takeover_progression trigger)',
        event_type: 'high_impact_action',
        time_offset_ms: 60000, // 60 seconds later (within 900s window)
        context: {
          device_fingerprint: 'fp_attacker_external_device_99',
          ip_address: '203.0.113.50',
          geo_country: 'RU',
          geo_region: 'MOW',
          user_agent: 'Mozilla/5.0 (X11; Linux x86_64) AttackerProbe/1.0'
        },
        metadata: {
          action_sensitivity: 'critical'
        },
        route: '/api/v1/account/high-impact',
        route_payload: {
          action: 'exfiltrate_customer_database'
        }
      }
    ]
  }),

  fp_benign_new_device: Object.freeze({
    id: 'fp_benign_new_device',
    alias: 'fp_benign_new_device',
    name: 'False-Positive Check: Benign New Device',
    scenario_type: 'false_positive',
    description:
      'Legitimate user logs in from a newly acquired smartphone or tablet from their usual home location without any hostile sequence or impossible travel.',
    expected_interpretation:
      'Presents unrecognized_device (+10 points) but lacks hostile sequence or travel anomaly. The system must not falsely block the legitimate user.',
    expected_outcome: {
      target_decision: 'allow',
      max_acceptable_decision: 'monitor'
    },
    baseline_events: [
      {
        event_type: 'login_success',
        time_offset_ms: -3600000,
        context: {
          device_fingerprint: 'fp_demo_known_workstation_01',
          ip_address: '198.51.100.10',
          geo_country: 'US',
          geo_region: 'CA',
          user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        },
        metadata: {
          action_sensitivity: 'low'
        }
      }
    ],
    steps: [
      {
        step_number: 1,
        name: 'Legitimate login from newly acquired mobile device',
        event_type: 'login_success',
        time_offset_ms: 0,
        context: {
          device_fingerprint: 'fp_user_new_tablet_02',
          ip_address: '198.51.100.10',
          geo_country: 'US',
          geo_region: 'CA',
          user_agent: 'Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X)'
        },
        metadata: {
          action_sensitivity: 'low'
        }
      }
    ]
  }),

  fp_benign_travel_login: Object.freeze({
    id: 'fp_benign_travel_login',
    alias: 'fp_benign_travel_login',
    name: 'False-Positive Check: Feasible Travel Login',
    scenario_type: 'false_positive',
    description:
      'Legitimate user travels internationally and logs in 24 hours later from the UK using their recognized laptop. Feasible travel time means impossible_travel is false.',
    expected_interpretation:
      'Presents unrecognized_country (+10 points) but no impossible_travel anomaly or hostile sequence. The system should allow the login without false containment.',
    expected_outcome: {
      target_decision: 'allow',
      max_acceptable_decision: 'monitor'
    },
    baseline_events: [
      {
        event_type: 'login_success',
        time_offset_ms: -86400000, // 24 hours earlier in US
        context: {
          device_fingerprint: 'fp_demo_known_workstation_01',
          ip_address: '198.51.100.10',
          geo_country: 'US',
          geo_region: 'CA',
          user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        },
        metadata: {
          action_sensitivity: 'low'
        }
      }
    ],
    steps: [
      {
        step_number: 1,
        name: 'Legitimate login following feasible transatlantic travel',
        event_type: 'login_success',
        time_offset_ms: 0,
        context: {
          device_fingerprint: 'fp_demo_known_workstation_01',
          ip_address: '198.51.100.80',
          geo_country: 'GB',
          geo_region: 'ENG',
          user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        },
        metadata: {
          action_sensitivity: 'low'
        }
      }
    ]
  }),

  fp_benign_profile_update: Object.freeze({
    id: 'fp_benign_profile_update',
    alias: 'fp_benign_profile_update',
    name: 'False-Positive Check: Routine Account Modification',
    scenario_type: 'false_positive',
    description:
      'Legitimate user on their recognized workstation performs a single phone number update without rapid cascade or anomalous context.',
    expected_interpretation:
      'A single profile change from a known device in the home country. Risk remains low, resulting in allow without step-up challenge or blocking.',
    expected_outcome: {
      target_decision: 'allow',
      max_acceptable_decision: 'monitor'
    },
    baseline_events: [
      {
        event_type: 'login_success',
        time_offset_ms: -1800000, // 30 minutes earlier
        context: {
          device_fingerprint: 'fp_demo_known_workstation_01',
          ip_address: '198.51.100.10',
          geo_country: 'US',
          geo_region: 'CA',
          user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        },
        metadata: {
          action_sensitivity: 'low'
        }
      }
    ],
    steps: [
      {
        step_number: 1,
        name: 'Single routine phone number update from known device',
        event_type: 'phone_number_change',
        time_offset_ms: 0,
        context: {
          device_fingerprint: 'fp_demo_known_workstation_01',
          ip_address: '198.51.100.10',
          geo_country: 'US',
          geo_region: 'CA',
          user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        },
        metadata: {
          action_sensitivity: 'medium'
        },
        route: '/api/v1/account/phone',
        route_payload: {
          phone_number: '+14155559876'
        }
      }
    ]
  })
});

/**
 * Validates a scenario definition against project invariants.
 *
 * @param {object} scenario
 * @throws {Error} If scenario is invalid
 */
function validateScenarioDefinition(scenario) {
  if (!scenario || typeof scenario !== 'object') {
    throw new Error('Scenario definition must be a non-null object');
  }

  if (typeof scenario.id !== 'string' || scenario.id.trim() === '') {
    throw new Error('Scenario definition must have a non-empty string id');
  }

  const validTypes = ['benign', 'simulated_takeover', 'false_positive'];
  if (!validTypes.includes(scenario.scenario_type)) {
    throw new Error(
      `Scenario '${scenario.id}' has invalid scenario_type '${scenario.scenario_type}'. Must be one of: ${validTypes.join(', ')}`
    );
  }

  if (!Array.isArray(scenario.steps) || scenario.steps.length === 0) {
    throw new Error(`Scenario '${scenario.id}' must have a non-empty steps array`);
  }

  const supportedTypes = SecurityEvent.SUPPORTED_EVENT_TYPES;
  let prevOffset = -Infinity;

  for (let i = 0; i < scenario.steps.length; i++) {
    const step = scenario.steps[i];
    if (!step || typeof step !== 'object') {
      throw new Error(`Scenario '${scenario.id}' step[${i}] must be an object`);
    }

    if (!supportedTypes.includes(step.event_type)) {
      throw new Error(
        `Scenario '${scenario.id}' step[${i}] has unsupported event_type '${step.event_type}'`
      );
    }

    if (typeof step.time_offset_ms !== 'number' || !Number.isFinite(step.time_offset_ms)) {
      throw new Error(`Scenario '${scenario.id}' step[${i}] must have numeric time_offset_ms`);
    }

    if (step.time_offset_ms < prevOffset) {
      throw new Error(
        `Scenario '${scenario.id}' steps must be in chronological order (step ${i} offset ${step.time_offset_ms} < prev ${prevOffset})`
      );
    }
    prevOffset = step.time_offset_ms;
  }

  if (scenario.baseline_events) {
    if (!Array.isArray(scenario.baseline_events)) {
      throw new Error(`Scenario '${scenario.id}' baseline_events must be an array`);
    }
    for (let i = 0; i < scenario.baseline_events.length; i++) {
      const bEvent = scenario.baseline_events[i];
      if (!supportedTypes.includes(bEvent.event_type)) {
        throw new Error(
          `Scenario '${scenario.id}' baseline_events[${i}] has unsupported event_type '${bEvent.event_type}'`
        );
      }
    }
  }

  return true;
}

/**
 * Retrieves a scenario definition by ID or alias.
 *
 * @param {string} scenarioId
 * @returns {object|null}
 */
function getScenarioDefinition(scenarioId) {
  if (!scenarioId || typeof scenarioId !== 'string') {
    return null;
  }
  const normalized = scenarioId.trim().toLowerCase();
  for (const key of Object.keys(SCENARIOS)) {
    const sc = SCENARIOS[key];
    if (sc.id === normalized || sc.alias === normalized) {
      return sc;
    }
  }
  return null;
}

/**
 * Returns all registered scenario definitions.
 *
 * @returns {Array<object>}
 */
function listScenarioDefinitions() {
  return Object.values(SCENARIOS);
}

module.exports = {
  SCENARIOS,
  validateScenarioDefinition,
  getScenarioDefinition,
  listScenarioDefinitions
};
