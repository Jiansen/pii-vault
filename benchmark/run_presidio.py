"""Run Presidio Analyzer on the benchmark dataset.

Setup:
    pip install presidio-analyzer presidio-anonymizer spacy
    python -m spacy download en_core_web_lg
"""

import json
import time
from pathlib import Path

try:
    from presidio_analyzer import AnalyzerEngine
except ImportError:
    print("Install: pip install presidio-analyzer spacy && python -m spacy download en_core_web_lg")
    raise SystemExit(1)


def main():
    dataset_path = Path(__file__).parent / "dataset.json"
    dataset = json.loads(dataset_path.read_text())

    analyzer = AnalyzerEngine()

    results = []
    t0 = time.perf_counter()

    for entry in dataset:
        presidio_results = analyzer.analyze(
            text=entry["text"],
            language="en",
            score_threshold=0.0,
        )
        detected = [
            {
                "type": r.entity_type,
                "start": r.start,
                "end": r.end,
                "text": entry["text"][r.start : r.end],
                "score": round(r.score, 4),
            }
            for r in presidio_results
        ]
        results.append({"id": entry["id"], "detected": detected})

    elapsed_ms = (time.perf_counter() - t0) * 1000

    output = {
        "tool": "presidio",
        "version": "latest",
        "dataset_size": len(dataset),
        "elapsed_ms": round(elapsed_ms),
        "results": results,
    }

    out_path = Path(__file__).parent / "results_presidio.json"
    out_path.write_text(json.dumps(output, indent=2, ensure_ascii=False))
    print(f"presidio: {len(dataset)} samples in {elapsed_ms:.0f}ms → {out_path}")


if __name__ == "__main__":
    main()
