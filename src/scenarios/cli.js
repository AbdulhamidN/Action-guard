'use strict';

/**
 * CLI Tool for ActionGuard Scenario Engine (Module 13.1)
 *
 * Usage:
 *   node src/scenarios/cli.js --scenario=scenario_a
 *   node src/scenarios/cli.js --scenario=scenario_b
 *   node src/scenarios/cli.js --scenario=fp_benign_new_device
 *   node src/scenarios/cli.js --list
 *   node src/scenarios/cli.js --cleanup --runId=<run_id>
 */

const {
  runScenario,
  compareFalsePositive,
  cleanupScenarioRun,
  listScenarioDefinitions
} = require('./index');

function parseArgs(args) {
  const parsed = {};
  for (const arg of args) {
    if (arg.startsWith('--')) {
      const eqIdx = arg.indexOf('=');
      if (eqIdx !== -1) {
        const key = arg.slice(2, eqIdx);
        const val = arg.slice(eqIdx + 1);
        parsed[key] = val;
      } else {
        parsed[arg.slice(2)] = true;
      }
    }
  }
  return parsed;
}

function printDivider() {
  console.log('='.repeat(78));
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.list) {
    console.log('\nAvailable ActionGuard Demo Scenarios:');
    printDivider();
    const scenarios = listScenarioDefinitions();
    for (const s of scenarios) {
      console.log(`- ${s.id.padEnd(26)} [${s.scenario_type.padEnd(18)}] : ${s.name}`);
    }
    console.log('\nRun a scenario with: node src/scenarios/cli.js --scenario=<id>\n');
    return;
  }

  if (args.cleanup && !args.scenario) {
    const runId = args.runId || args.run_id;
    const userId = args.userId || args.user_id;
    if (!runId && !userId) {
      console.error('\n[Error] Must specify --runId=<id> or --userId=<id> to clean up demo data.\n');
      process.exit(1);
    }
    console.log(`\nCleaning up records for ${runId ? `runId: ${runId}` : `userId: ${userId}`}...`);
    const res = await cleanupScenarioRun({ runId, userId });
    console.log('[Cleanup Result]:', JSON.stringify(res.removed, null, 2));
    console.log('\nDemo data successfully cleaned up.\n');
    return;
  }

  const scenarioId = args.scenario;
  if (!scenarioId) {
    console.log('\nActionGuard Scenario Runner');
    printDivider();
    console.log('Options:');
    console.log('  --scenario=<id>       Execute scenario (scenario_a, scenario_b, fp_benign_new_device, etc.)');
    console.log('  --runId=<id>          Explicit run identifier (optional)');
    console.log('  --cleanup             Clean up data immediately after scenario execution');
    console.log('  --list                List all available scenarios');
    console.log('  --cleanup --runId=... Clean up records owned by a specific run');
    console.log('\nExample:');
    console.log('  node src/scenarios/cli.js --scenario=scenario_a\n');
    return;
  }

  console.log(`\n[ActionGuard Scenario Runner] Starting: ${scenarioId}...`);
  printDivider();

  const options = {
    runId: args.runId || args.run_id,
    cleanupAfter: Boolean(args.cleanup)
  };

  try {
    const isFalsePositive = scenarioId.startsWith('fp_');
    if (isFalsePositive) {
      const report = await compareFalsePositive(scenarioId, options);
      console.log(`Scenario: ${report.scenario_name} (${report.scenario_id})`);
      console.log(`Expected Interpretation: ${report.expected_interpretation}`);
      console.log(`Max Acceptable Decision: ${report.expected_max_acceptable_decision}`);
      console.log('\n--- Real System Observed Outcome ---');
      console.log(`Risk Score:          ${report.observed_system_outcome.risk_score}`);
      console.log(`Risk Tier:           ${report.observed_system_outcome.risk_tier}`);
      console.log(`Policy Decision:     ${report.observed_system_outcome.policy_decision}`);
      console.log(`Enforcement Outcome: ${report.observed_system_outcome.enforcement_outcome}`);
      console.log(`Contributing Signals:`, report.observed_system_outcome.contributing_signals);
      console.log(`Session Contained:   ${report.observed_system_outcome.is_contained}`);
      console.log(`\nAcceptable (Non-False-Positive): ${report.is_acceptable ? 'YES (PASSED)' : 'NO (FLAGGED)'}`);
    } else {
      const summary = await runScenario(scenarioId, options);
      console.log(`Scenario:   ${summary.scenario_name} [${summary.scenario_type}]`);
      console.log(`Run ID:     ${summary.run_id}`);
      console.log(`Demo User:  ${summary.user_email}`);
      console.log(`Steps Run:  ${summary.steps_executed}`);
      console.log('\n--- Step Execution Details ---');
      for (const step of summary.steps) {
        const obs = step.observed_pipeline;
        console.log(
          `Step ${step.step_number}: ${step.event_type.padEnd(22)} | Score: ${String(obs.risk_score).padStart(3)} (${obs.risk_tier.padEnd(8)}) | Decision: ${obs.policy_decision.padEnd(8)} | Outcome: ${obs.enforcement_outcome}`
        );
        if (obs.contributing_signals.length > 0) {
          console.log(
            `        Signals: ${obs.contributing_signals.map((s) => `${s.signal} (+${s.weight})`).join(', ')}`
          );
        }
      }
      console.log('\n--- Final Observed Outcome ---');
      console.log(`Final Risk Score:    ${summary.final_outcome.risk_score}`);
      console.log(`Final Risk Tier:     ${summary.final_outcome.risk_tier}`);
      console.log(`Final Decision:      ${summary.final_outcome.policy_decision}`);
      console.log(`Enforcement Outcome: ${summary.final_outcome.enforcement_outcome}`);
      console.log(`Account Contained:   ${summary.final_outcome.is_contained}`);
      if (summary.cleaned_up) {
        console.log('\nDemo run records were cleaned up.');
      } else {
        console.log(`\nTo clean up demo records for this run:\n  node src/scenarios/cli.js --cleanup --runId=${summary.run_id}`);
      }
    }
    printDivider();
    console.log('Execution completed successfully.\n');
  } catch (err) {
    console.error('\n[Scenario Execution Failed]:', err.message);
    process.exit(1);
  }
}

if (require.main === module) {
  main()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
}

module.exports = { main };
