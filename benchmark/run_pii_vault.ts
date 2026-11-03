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

const LONG_DOC_REPEATS = 20;
const LONG_DOC_RUNS = 5;

function median(xs: number[]): number {
  const s = [...xs].sort((a, b) => a - b);
  const n = s.length;
  return n % 2 === 1 ? s[(n - 1) / 2] : (s[n / 2 - 1] + s[n / 2]) / 2;
}

const round3 = (x: number) => Math.round(x * 1000) / 1000;

function run() {
  const threshold = parseFloat(process.argv[2] || '0.0');
  const iterations = parseInt(process.argv[3] || '200', 10);
  const dataset: DatasetEntry[] = JSON.parse(fs.readFileSync(path.join(__dirname, 'dataset.json'), 'utf-8'));
  const tLoad = performance.now();
  const recognizers = loadRecognizers();
  const analyzer = new Analyzer(recognizers);
  const loadMs = performance.now() - tLoad;

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

  // Warm passes (same work as above, without building the output) for steady-state timing.
  const passes: number[] = [];
  let sink = 0;
  for (let i = 0; i < iterations; i++) {
    const t = performance.now();
    for (const entry of dataset) sink += analyzer.analyze(entry.text, [], threshold).entities.length;
    passes.push(performance.now() - t);
  }

  // ASCII-only samples: the Rust context window slices by byte offset and panics inside CJK text.
  const ascii = dataset.map(e => e.text).filter(t => /^[\x00-\x7f]*$/.test(t));
  const longDoc = Array(LONG_DOC_REPEATS).fill(ascii.join('\n')).join('\n');
  let longDocEntities = 0;
  const longDocTimes: number[] = [];
  for (let i = 0; i < LONG_DOC_RUNS; i++) {
    const t = performance.now();
    longDocEntities = analyzer.analyze(longDoc, [], threshold).entities.length;
    longDocTimes.push(performance.now() - t);
  }
  const medianPass = median(passes);

  const suffix = threshold > 0 ? `_t${threshold.toFixed(1).replace('.', '')}` : '';
  const output = {
    tool: 'pii-vault',
    implementation: 'typescript',
    version: '0.3.3',
    score_threshold: threshold,
    dataset_size: dataset.length,
    elapsed_ms: Math.round(elapsed),
    timing: {
      recognizers: recognizers.length,
      load_ms: round3(loadMs),
      first_pass_ms: round3(elapsed),
      iterations,
      mean_pass_ms: round3(passes.reduce((a, b) => a + b, 0) / Math.max(passes.length, 1)),
      median_pass_ms: round3(medianPass),
      min_pass_ms: round3(Math.min(...passes)),
      samples_per_sec: Math.round(dataset.length / (medianPass / 1000)),
      long_doc_utf16_len: longDoc.length,
      long_doc_entities: longDocEntities,
      long_doc_median_ms: round3(median(longDocTimes)),
    },
    results,
  };

  const outPath = path.join(__dirname, `results_pii_vault${suffix}.json`);
  fs.writeFileSync(outPath, JSON.stringify(output, null, 2));
  console.log(`pii-vault (threshold=${threshold}): ${dataset.length} samples in ${elapsed.toFixed(0)}ms, median warm pass ${medianPass.toFixed(3)}ms over ${iterations} iterations, long doc ${median(longDocTimes).toFixed(2)}ms → ${outPath}`);
  if (sink < 0) console.log(sink);
}

run();
