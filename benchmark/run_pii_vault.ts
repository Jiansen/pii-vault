import * as fs from 'fs';
import * as path from 'path';
import { Analyzer } from '../typescript/src/analyzer';
import { RegexRecognizer, RecognizerDef } from '../typescript/src/recognizer';

interface DatasetEntry {
  id: number;
  text: string;
  entities: { type: string; start: number; end: number; text: string }[];
}

interface DetectedEntity {
  type: string;
  start: number;
  end: number;
  text: string;
  score: number;
}

function loadRecognizers(): RegexRecognizer[] {
  const specDir = path.join(__dirname, '..', 'spec', 'recognizers');
  return fs.readdirSync(specDir)
    .filter(f => f.endsWith('.json'))
    .map(f => new RegexRecognizer(JSON.parse(fs.readFileSync(path.join(specDir, f), 'utf-8')) as RecognizerDef));
}

function run() {
  const threshold = parseFloat(process.argv[2] || '0.0');
  const dataset: DatasetEntry[] = JSON.parse(fs.readFileSync(path.join(__dirname, 'dataset.json'), 'utf-8'));
  const recognizers = loadRecognizers();
  const analyzer = new Analyzer(recognizers);

  const results: { id: number; detected: DetectedEntity[] }[] = [];
  const t0 = performance.now();

  for (const entry of dataset) {
    const analysisResult = analyzer.analyze(entry.text, [], threshold);
    const detected: DetectedEntity[] = analysisResult.entities.map(e => ({
      type: e.entityType.name,
      start: e.start,
      end: e.end,
      text: entry.text.substring(e.start, e.end),
      score: e.score,
    }));
    results.push({ id: entry.id, detected });
  }

  const elapsed = performance.now() - t0;

  const suffix = threshold > 0 ? `_t${threshold.toFixed(1).replace('.', '')}` : '';
  const output = {
    tool: 'pii-vault',
    version: '0.2.0',
    score_threshold: threshold,
    dataset_size: dataset.length,
    elapsed_ms: Math.round(elapsed),
    results,
  };

  const outPath = path.join(__dirname, `results_pii_vault${suffix}.json`);
  fs.writeFileSync(outPath, JSON.stringify(output, null, 2));
  console.log(`pii-vault (threshold=${threshold}): ${dataset.length} samples in ${elapsed.toFixed(0)}ms → ${outPath}`);
}

run();
