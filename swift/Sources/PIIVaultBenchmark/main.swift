// Precision + speed benchmark over benchmark/dataset.json. Mirrors benchmark/run_pii_vault.ts and
// rust/examples/benchmark.rs so the three implementations can be compared with
// benchmark/compare_impls.py.
//
//   swift run -c release PIIVaultBenchmark [threshold] [iterations]

import Foundation
import PIIVault

let threshold = CommandLine.arguments.count > 1 ? Double(CommandLine.arguments[1]) ?? 0 : 0
let iterations = CommandLine.arguments.count > 2 ? Int(CommandLine.arguments[2]) ?? 200 : 200
let longDocRepeats = 20
let longDocRuns = 5

let repoRoot = ProcessInfo.processInfo.environment["PII_VAULT_ROOT"].map { URL(fileURLWithPath: $0) }
    ?? URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
let benchmarkDir = repoRoot.appendingPathComponent("benchmark")

struct Sample: Decodable {
    let id: Int
    let text: String
}

func milliseconds(_ d: Duration) -> Double {
    Double(d.components.seconds) * 1000 + Double(d.components.attoseconds) / 1e15
}

func median(_ xs: [Double]) -> Double {
    let s = xs.sorted()
    return s.count % 2 == 1 ? s[s.count / 2] : (s[s.count / 2 - 1] + s[s.count / 2]) / 2
}

func round3(_ x: Double) -> Double { (x * 1000).rounded() / 1000 }

let clock = ContinuousClock()
let dataset = try JSONDecoder().decode([Sample].self, from: Data(contentsOf: benchmarkDir.appendingPathComponent("dataset.json")))

var analyzer: Analyzer!
let loadMs = milliseconds(try clock.measure {
    analyzer = try Analyzer(rulesDirectory: repoRoot.appendingPathComponent("spec/recognizers"))
})

var results: [[String: Any]] = []
let firstPassMs = milliseconds(clock.measure {
    for sample in dataset {
        let detected = analyzer.analyze(sample.text, scoreThreshold: threshold).entities.map { e -> [String: Any] in
            ["type": e.entityType.name, "start": e.start, "end": e.end, "text": e.text(in: sample.text) ?? "", "score": e.score]
        }
        results.append(["id": sample.id, "detected": detected])
    }
})

var passes: [Double] = []
var sink = 0
for _ in 0..<iterations {
    passes.append(milliseconds(clock.measure {
        for sample in dataset {
            sink &+= analyzer.analyze(sample.text, scoreThreshold: threshold).entities.count
        }
    }))
}

// ASCII-only samples: the Rust context window slices by byte offset and panics inside CJK text.
let asciiTexts = dataset.map(\.text).filter { $0.allSatisfy(\.isASCII) }
let longDoc = Array(repeating: asciiTexts.joined(separator: "\n"), count: longDocRepeats).joined(separator: "\n")
var longDocEntities = 0
var longDocTimes: [Double] = []
for _ in 0..<longDocRuns {
    longDocTimes.append(milliseconds(clock.measure {
        longDocEntities = analyzer.analyze(longDoc, scoreThreshold: threshold).entities.count
    }))
}

// Same document through analyzeConcurrently (recognizers in parallel); results must be identical.
let sequentialLongDoc = analyzer.analyze(longDoc, scoreThreshold: threshold).entities
var concurrentLongDocTimes: [Double] = []
for _ in 0..<longDocRuns {
    var entities: [RecognizerResult] = []
    concurrentLongDocTimes.append(milliseconds(clock.measure {
        entities = analyzer.analyzeConcurrently(longDoc, scoreThreshold: threshold).entities
    }))
    precondition(entities == sequentialLongDoc, "analyzeConcurrently diverged from analyze")
}

let medianPass = median(passes)
let output: [String: Any] = [
    "tool": "pii-vault-swift",
    "implementation": "swift",
    "version": "0.3.3",
    "score_threshold": threshold,
    "dataset_size": dataset.count,
    "elapsed_ms": round3(firstPassMs),
    "timing": [
        "recognizers": analyzer.recognizerCount,
        "load_ms": round3(loadMs),
        "first_pass_ms": round3(firstPassMs),
        "iterations": iterations,
        "mean_pass_ms": round3(passes.reduce(0, +) / Double(max(passes.count, 1))),
        "median_pass_ms": round3(medianPass),
        "min_pass_ms": round3(passes.min() ?? 0),
        "samples_per_sec": (Double(dataset.count) / (medianPass / 1000)).rounded(),
        "long_doc_utf16_len": (longDoc as NSString).length,
        "long_doc_entities": longDocEntities,
        "long_doc_median_ms": round3(median(longDocTimes)),
        "concurrent_long_doc_median_ms": round3(median(concurrentLongDocTimes)),
        "cores": ProcessInfo.processInfo.activeProcessorCount,
    ],
    "results": results,
]

let suffix = threshold > 0 ? "_t" + String(format: "%.1f", threshold).replacingOccurrences(of: ".", with: "") : ""
let outURL = benchmarkDir.appendingPathComponent("results_swift\(suffix).json")
try JSONSerialization.data(withJSONObject: output, options: [.prettyPrinted, .sortedKeys]).write(to: outURL)
print(String(format: "swift (threshold=%.1f): load %.2fms, first pass %.2fms, median pass %.3fms over %d iterations, long doc %.2fms (concurrent %.2fms) → %@",
             threshold, loadMs, firstPassMs, medianPass, iterations, median(longDocTimes), median(concurrentLongDocTimes), outURL.path))
if sink < 0 { print(sink) }
