//! Precision + speed benchmark over benchmark/dataset.json. Mirrors benchmark/run_pii_vault.ts and
//! swift/Sources/PIIVaultBenchmark so the implementations can be compared with
//! benchmark/compare_impls.py.
//!
//!   cargo run --release -p pii-vault --example benchmark -- [threshold] [iterations]

use pii_vault::{load_recognizers_from_dir, Analyzer};
use serde_json::{json, Value};
use std::path::Path;
use std::time::Instant;

const LONG_DOC_REPEATS: usize = 20;
const LONG_DOC_RUNS: usize = 5;

fn ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

fn median(xs: &[f64]) -> f64 {
    let mut s = xs.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = s.len();
    if n % 2 == 1 { s[n / 2] } else { (s[n / 2 - 1] + s[n / 2]) / 2.0 }
}

fn round3(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}

/// The dataset's offsets are UTF-16 code units (as in TypeScript and Swift); Rust reports bytes.
fn utf16_offset(text: &str, byte_offset: usize) -> usize {
    text[..byte_offset].encode_utf16().count()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let threshold: f64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(0.0);
    let iterations: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(200);

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let bench_dir = root.join("benchmark");
    let dataset: Vec<Value> =
        serde_json::from_str(&std::fs::read_to_string(bench_dir.join("dataset.json")).unwrap()).unwrap();

    let t = Instant::now();
    let analyzer = Analyzer::new(load_recognizers_from_dir(&root.join("spec/recognizers")));
    let load_ms = ms(t);

    let mut results = Vec::new();
    let t = Instant::now();
    for entry in &dataset {
        let text = entry["text"].as_str().unwrap();
        let detected: Vec<Value> = analyzer
            .analyze(text, &[], threshold)
            .entities
            .iter()
            .map(|e| {
                json!({
                    "type": e.entity_type.as_str(),
                    "start": utf16_offset(text, e.start),
                    "end": utf16_offset(text, e.end),
                    "text": &text[e.start..e.end],
                    "score": e.score,
                })
            })
            .collect();
        results.push(json!({ "id": entry["id"], "detected": detected }));
    }
    let first_pass_ms = ms(t);

    let mut passes = Vec::with_capacity(iterations);
    let mut sink = 0usize;
    for _ in 0..iterations {
        let t = Instant::now();
        for entry in &dataset {
            sink = sink.wrapping_add(analyzer.analyze(entry["text"].as_str().unwrap(), &[], threshold).entities.len());
        }
        passes.push(ms(t));
    }

    // ASCII-only samples: the context window slices by byte offset and panics inside CJK text.
    let ascii: Vec<&str> = dataset.iter().map(|e| e["text"].as_str().unwrap()).filter(|t| t.is_ascii()).collect();
    let long_doc = vec![ascii.join("\n"); LONG_DOC_REPEATS].join("\n");
    let mut long_doc_entities = 0;
    let mut long_doc_times = Vec::new();
    for _ in 0..LONG_DOC_RUNS {
        let t = Instant::now();
        long_doc_entities = analyzer.analyze(&long_doc, &[], threshold).entities.len();
        long_doc_times.push(ms(t));
    }

    let median_pass = median(&passes);
    let output = json!({
        "tool": "pii-vault-rust",
        "implementation": "rust",
        "version": env!("CARGO_PKG_VERSION"),
        "score_threshold": threshold,
        "dataset_size": dataset.len(),
        "elapsed_ms": round3(first_pass_ms),
        "timing": {
            "recognizers": analyzer.recognizer_count(),
            "load_ms": round3(load_ms),
            "first_pass_ms": round3(first_pass_ms),
            "iterations": iterations,
            "mean_pass_ms": round3(passes.iter().sum::<f64>() / passes.len().max(1) as f64),
            "median_pass_ms": round3(median_pass),
            "min_pass_ms": round3(passes.iter().cloned().fold(f64::INFINITY, f64::min)),
            "samples_per_sec": (dataset.len() as f64 / (median_pass / 1000.0)).round() as u64,
            "long_doc_utf16_len": long_doc.encode_utf16().count(),
            "long_doc_entities": long_doc_entities,
            "long_doc_median_ms": round3(median(&long_doc_times)),
        },
        "results": results,
    });

    let suffix = if threshold > 0.0 { format!("_t{}", format!("{:.1}", threshold).replace('.', "")) } else { String::new() };
    let out = bench_dir.join(format!("results_rust{}.json", suffix));
    std::fs::write(&out, serde_json::to_string_pretty(&output).unwrap()).unwrap();
    println!(
        "rust (threshold={:.1}): load {:.2}ms, first pass {:.2}ms, median pass {:.3}ms over {} iterations, long doc {:.2}ms → {}",
        threshold, load_ms, first_pass_ms, median_pass, iterations, median(&long_doc_times), out.display()
    );
    if sink == usize::MAX {
        println!("{}", sink);
    }
}
