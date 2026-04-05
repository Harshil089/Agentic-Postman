#!/usr/bin/env node
const path = require('path');
const automation = require('../../security-dataset-automation');

function parseArgs(argv) {
  const args = {};
  for (let i = 2; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith('--')) continue;
    const key = token.slice(2);
    const value = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : 'true';
    args[key] = value;
    if (value !== 'true') i += 1;
  }
  return args;
}

const args = parseArgs(process.argv);
const defaults = automation.resolveDefaultPaths(path.resolve(__dirname, '..', '..'));
const report = automation.runBenchmark({
  datasetPath: args.dataset || defaults.dataset,
  fixturesPath: args.fixtures || defaults.fixtures,
  outPath: args.out || defaults.benchmarkOut
});

console.log(JSON.stringify({
  ok: true,
  average_score: report.average_score,
  fixture_count: report.fixture_count
}, null, 2));
