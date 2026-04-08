"""Compare pii-vault vs Presidio benchmark results.

Computes per-entity-type and overall precision, recall, F1.
Entity matching: type match + character overlap >= 50%.

Usage:
    python benchmark/compare.py
"""

import json
from collections import defaultdict
from pathlib import Path

BENCHMARK_DIR = Path(__file__).parent


def load_dataset():
    return json.loads((BENCHMARK_DIR / "dataset.json").read_text())


def load_results(filename):
    path = BENCHMARK_DIR / filename
    if not path.exists():
        return None
    return json.loads(path.read_text())


def overlap_ratio(s1, e1, s2, e2):
    overlap = max(0, min(e1, e2) - max(s1, s2))
    span = max(e1 - s1, e2 - s2)
    return overlap / span if span > 0 else 0


TYPE_ALIASES = {
    "IBAN_CODE": "IBAN_CODE",
    "IBAN": "IBAN_CODE",
}

COMPATIBLE_TYPES = {
    ("PHONE_NUMBER", "CN_PHONE"),
    ("CN_PHONE", "PHONE_NUMBER"),
    ("DE_STEUER_ID", "DE_TAX_ID"),
    ("DE_TAX_ID", "DE_STEUER_ID"),
}


def normalize_type(t):
    return TYPE_ALIASES.get(t, t)


def evaluate(dataset, results):
    """Return per-type and overall precision/recall/F1."""
    tp_per_type = defaultdict(int)
    fp_per_type = defaultdict(int)
    fn_per_type = defaultdict(int)

    result_map = {r["id"]: r["detected"] for r in results["results"]}

    for entry in dataset:
        eid = entry["id"]
        ground_truth = entry["entities"]
        detected = result_map.get(eid, [])

        gt_matched = set()
        det_matched = set()

        for di, d in enumerate(detected):
            d_type = normalize_type(d["type"])
            for gi, g in enumerate(ground_truth):
                g_type = normalize_type(g["type"])
                types_match = d_type == g_type or (d_type, g_type) in COMPATIBLE_TYPES
                if types_match and overlap_ratio(d["start"], d["end"], g["start"], g["end"]) >= 0.5:
                    if gi not in gt_matched:
                        tp_per_type[g_type] += 1
                        gt_matched.add(gi)
                        det_matched.add(di)
                        break

        for di, d in enumerate(detected):
            if di not in det_matched:
                fp_per_type[normalize_type(d["type"])] += 1

        for gi, g in enumerate(ground_truth):
            if gi not in gt_matched:
                fn_per_type[normalize_type(g["type"])] += 1

    all_types = sorted(set(list(tp_per_type.keys()) + list(fp_per_type.keys()) + list(fn_per_type.keys())))

    per_type = {}
    total_tp = total_fp = total_fn = 0

    for t in all_types:
        tp = tp_per_type[t]
        fp = fp_per_type[t]
        fn = fn_per_type[t]
        total_tp += tp
        total_fp += fp
        total_fn += fn

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        per_type[t] = {"tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall, "f1": f1}

    overall_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
    overall_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
    overall_f1 = (
        2 * overall_precision * overall_recall / (overall_precision + overall_recall)
        if (overall_precision + overall_recall) > 0
        else 0
    )

    return {
        "per_type": per_type,
        "overall": {
            "tp": total_tp,
            "fp": total_fp,
            "fn": total_fn,
            "precision": overall_precision,
            "recall": overall_recall,
            "f1": overall_f1,
        },
    }


def print_report(name, eval_result, elapsed_ms):
    print(f"\n{'='*60}")
    print(f"  {name}")
    print(f"{'='*60}")
    o = eval_result["overall"]
    print(f"  Overall: P={o['precision']:.1%}  R={o['recall']:.1%}  F1={o['f1']:.1%}  (TP={o['tp']} FP={o['fp']} FN={o['fn']})")
    print(f"  Time: {elapsed_ms}ms")
    print()
    print(f"  {'Entity Type':<25} {'Prec':>6} {'Rec':>6} {'F1':>6}  {'TP':>3} {'FP':>3} {'FN':>3}")
    print(f"  {'-'*25} {'-'*6} {'-'*6} {'-'*6}  {'-'*3} {'-'*3} {'-'*3}")

    for t, v in sorted(eval_result["per_type"].items()):
        print(f"  {t:<25} {v['precision']:>5.1%} {v['recall']:>5.1%} {v['f1']:>5.1%}  {v['tp']:>3} {v['fp']:>3} {v['fn']:>3}")


def main():
    dataset = load_dataset()
    print(f"Dataset: {len(dataset)} samples")

    total_entities = sum(len(e["entities"]) for e in dataset)
    negatives = sum(1 for e in dataset if not e["entities"])
    print(f"Ground truth: {total_entities} entities, {negatives} negative samples")

    pv = load_results("results_pii_vault.json")
    pr = load_results("results_presidio.json")

    comparisons = []
    if pv:
        eval_pv = evaluate(dataset, pv)
        print_report("pii-vault", eval_pv, pv["elapsed_ms"])
        comparisons.append(("pii-vault", eval_pv, pv["elapsed_ms"]))
    else:
        print("\n⚠ results_pii_vault.json not found. Run: npx ts-node benchmark/run_pii_vault.ts")

    if pr:
        eval_pr = evaluate(dataset, pr)
        print_report("Presidio", eval_pr, pr["elapsed_ms"])
        comparisons.append(("Presidio", eval_pr, pr["elapsed_ms"]))
    else:
        print("\n⚠ results_presidio.json not found. Run: python benchmark/run_presidio.py")

    if len(comparisons) == 2:
        print(f"\n{'='*60}")
        print("  HEAD-TO-HEAD COMPARISON")
        print(f"{'='*60}")
        print(f"  {'Metric':<12} {'pii-vault':>12} {'Presidio':>12} {'Delta':>12}")
        print(f"  {'-'*12} {'-'*12} {'-'*12} {'-'*12}")
        for metric in ["precision", "recall", "f1"]:
            pv_val = comparisons[0][1]["overall"][metric]
            pr_val = comparisons[1][1]["overall"][metric]
            delta = pv_val - pr_val
            sign = "+" if delta > 0 else ""
            print(f"  {metric:<12} {pv_val:>11.1%} {pr_val:>11.1%} {sign}{delta:>10.1%}")
        pv_ms = comparisons[0][2]
        pr_ms = comparisons[1][2]
        speedup = pr_ms / pv_ms if pv_ms > 0 else 0
        print(f"  {'time':<12} {pv_ms:>10}ms {pr_ms:>10}ms {speedup:>10.1f}x")

    report = {
        "dataset_size": len(dataset),
        "total_entities": total_entities,
        "negative_samples": negatives,
    }
    for name, ev, ms in comparisons:
        key = name.lower().replace("-", "_")
        report[key] = {**ev["overall"], "elapsed_ms": ms, "per_type": ev["per_type"]}
        for k in ["precision", "recall", "f1"]:
            report[key][k] = round(report[key][k], 4)
            for t in report[key]["per_type"]:
                report[key]["per_type"][t][k] = round(report[key]["per_type"][t][k], 4)

    (BENCHMARK_DIR / "comparison.json").write_text(json.dumps(report, indent=2, ensure_ascii=False))
    print(f"\nFull report → benchmark/comparison.json")


if __name__ == "__main__":
    main()
