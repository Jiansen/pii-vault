"""Compare the Rust, Swift and TypeScript implementations on the precision benchmark.

Reads results_{rust,swift,pii_vault}[_tXX].json (pii_vault = TypeScript), scores each with the
same matcher as compare.py, and prints accuracy, timing, and every sample where the
implementations disagree.

Usage:
    cargo run --release -p pii-vault --example benchmark -- 0.0
    (cd swift && swift run -c release PIIVaultBenchmark 0.0)
    npx tsx benchmark/run_pii_vault.ts 0.0
    python benchmark/compare_impls.py [threshold ...]   # default: 0.0 0.5
"""

import json
import sys

from compare import BENCHMARK_DIR, evaluate, load_dataset, load_results

IMPLEMENTATIONS = [("Rust", "results_rust"), ("Swift", "results_swift"), ("TypeScript", "results_pii_vault")]


def suffix(threshold):
    return f"_t{threshold:.1f}".replace(".", "") if threshold > 0 else ""


def detections(result):
    return {r["id"]: sorted((d["type"], d["start"], d["end"]) for d in r["detected"]) for r in result["results"]}


def report(dataset, threshold):
    loaded = [(name, load_results(f"{stem}{suffix(threshold)}.json")) for name, stem in IMPLEMENTATIONS]
    missing = [name for name, r in loaded if r is None]
    loaded = [(name, r) for name, r in loaded if r is not None]
    print(f"\n## threshold = {threshold}\n")
    if missing:
        print(f"_missing results: {', '.join(missing)}_\n")
    if not loaded:
        return {}

    summary = {}
    print("| Impl | Precision | Recall | F1 | TP | FP | FN |")
    print("|---|---:|---:|---:|---:|---:|---:|")
    for name, r in loaded:
        o = evaluate(dataset, r)["overall"]
        summary[name] = {"accuracy": {k: round(v, 4) for k, v in o.items()}, "timing": r.get("timing", {})}
        print(f"| {name} | {o['precision']:.1%} | {o['recall']:.1%} | {o['f1']:.1%} | {o['tp']} | {o['fp']} | {o['fn']} |")

    print("\n| Impl | Load rules (ms) | First pass (ms) | Median warm pass (ms) | Samples/s | Long doc (ms) | Long doc entities |")
    print("|---|---:|---:|---:|---:|---:|---:|")
    for name, r in loaded:
        t = r.get("timing", {})
        print(
            f"| {name} | {t.get('load_ms', '-')} | {t.get('first_pass_ms', r['elapsed_ms'])} | {t.get('median_pass_ms', '-')} "
            f"| {t.get('samples_per_sec', '-'):,} | {t.get('long_doc_median_ms', '-')} | {t.get('long_doc_entities', '-')} |"
        )
    for name, r in loaded:
        t = r.get("timing", {})
        if "concurrent_long_doc_median_ms" in t:
            print(f"\n_{name} `analyzeConcurrently` on the long doc: {t['concurrent_long_doc_median_ms']} ms "
                  f"({t['long_doc_median_ms'] / t['concurrent_long_doc_median_ms']:.1f}x, {t.get('cores', '?')} cores)._")
    if loaded and "timing" in loaded[0][1]:
        t = loaded[0][1]["timing"]
        print(f"\n_{t['iterations']} warm passes over {len(dataset)} samples; long doc = {t['long_doc_utf16_len']:,} UTF-16 units._")

    by_impl = {name: detections(r) for name, r in loaded}
    texts = {e["id"]: e["text"] for e in dataset}
    diffs = [i for i in texts if len({json.dumps(d.get(i, [])) for d in by_impl.values()}) > 1]
    print(f"\nSamples where implementations disagree: {len(diffs)}")
    for i in diffs:
        print(f"\n- #{i}: {texts[i]!r}")
        for name, d in by_impl.items():
            spans = ", ".join(f"{t}[{s}:{e}]={texts[i][s:e]!r}" for t, s, e in d.get(i, []))
            print(f"  - {name}: {spans or '(none)'}")
    return summary


def main():
    thresholds = [float(a) for a in sys.argv[1:]] or [0.0, 0.5]
    dataset = load_dataset()
    out = {str(t): report(dataset, t) for t in thresholds}
    (BENCHMARK_DIR / "comparison_impls.json").write_text(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
