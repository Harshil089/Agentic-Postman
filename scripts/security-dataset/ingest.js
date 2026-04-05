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
const result = automation.ingestDataset({
  baseDatasetPath: args.base || defaults.dataset,
  feedPath: args.feed || defaults.feed,
  outPath: args.out || defaults.dataset
});

console.log(JSON.stringify({
  ok: true,
  families: result.families,
  output: result.output
}, null, 2));
