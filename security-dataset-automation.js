const fs = require('fs');
const path = require('path');

function readJsonFile(filePath, fallback) {
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

function dedupeFamilies(families = []) {
  const map = new Map();
  families.forEach(entry => {
    if (!entry || typeof entry !== 'object') return;
    const id = String(entry.family_id || '').trim();
    if (!id) return;
    const prev = map.get(id);
    if (!prev) {
      map.set(id, { ...entry });
      return;
    }
    const merged = { ...prev, ...entry };
    merged.tags = [...new Set([...(prev.tags || []), ...(entry.tags || [])])].slice(0, 24);
    merged.endpoint_keywords = [...new Set([...(prev.endpoint_keywords || []), ...(entry.endpoint_keywords || [])])].slice(0, 24);
    const examples = [...(prev.cve_examples || []), ...(entry.cve_examples || [])];
    const seenCve = new Set();
    merged.cve_examples = examples.filter(example => {
      const key = String(example?.id || '').trim().toUpperCase();
      if (!key || seenCve.has(key)) return false;
      seenCve.add(key);
      return true;
    }).slice(0, 40);
    map.set(id, merged);
  });
  return [...map.values()].sort((a, b) => String(a.family_id).localeCompare(String(b.family_id)));
}

function dedupeDataset(dataset = {}) {
  return {
    families: dedupeFamilies(Array.isArray(dataset.families) ? dataset.families : [])
  };
}

function ingestDataset({ baseDatasetPath, feedPath, outPath }) {
  const base = readJsonFile(baseDatasetPath, { families: [] });
  const feed = readJsonFile(feedPath, { families: [] });
  const merged = dedupeDataset({
    families: [
      ...(Array.isArray(base.families) ? base.families : []),
      ...(Array.isArray(feed.families) ? feed.families : [])
    ]
  });

  fs.writeFileSync(outPath, `${JSON.stringify(merged, null, 2)}\n`, 'utf8');
  return {
    families: merged.families.length,
    output: outPath
  };
}

function benchmarkDataset(dataset = {}, fixtures = []) {
  const families = Array.isArray(dataset.families) ? dataset.families : [];
  const familyIds = new Set(families.map(entry => entry.family_id).filter(Boolean));

  const results = (Array.isArray(fixtures) ? fixtures : []).map(item => {
    const expected = Array.isArray(item.expected_family_ids) ? item.expected_family_ids : [];
    const matched = expected.filter(id => familyIds.has(id));
    const score = expected.length ? matched.length / expected.length : 1;
    return {
      id: item.id || 'fixture',
      expected,
      matched,
      score
    };
  });

  const average = results.length
    ? results.reduce((sum, entry) => sum + entry.score, 0) / results.length
    : 1;
  return {
    average_score: Number(average.toFixed(4)),
    fixture_count: results.length,
    results
  };
}

function runBenchmark({ datasetPath, fixturesPath, outPath }) {
  const dataset = readJsonFile(datasetPath, { families: [] });
  const fixtures = readJsonFile(fixturesPath, []);
  const report = benchmarkDataset(dataset, fixtures);
  fs.writeFileSync(outPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
  return report;
}

function resolveDefaultPaths(rootDir = __dirname) {
  return {
    dataset: path.join(rootDir, 'security-cve-dataset.json'),
    feed: path.join(rootDir, 'security-cve-feed.json'),
    fixtures: path.join(rootDir, 'security-benchmark-fixtures.json'),
    benchmarkOut: path.join(rootDir, 'security-benchmark-report.json')
  };
}

module.exports = {
  dedupeFamilies,
  dedupeDataset,
  ingestDataset,
  benchmarkDataset,
  runBenchmark,
  resolveDefaultPaths
};
