# PII Vault Precision Benchmark

100-sample benchmark dataset with ground truth annotations for evaluating PII detection precision, recall, and F1.

## Dataset

`dataset.json`: 100 text samples containing:
- **68 positive samples** with 88 annotated PII entities across 30+ entity types
- **32 negative samples** (no PII) including similar-looking patterns that should NOT be detected
- Multi-language coverage: English, Chinese, German, French, Spanish, Italian, Japanese, Korean, etc.

## Results: pii-vault v0.2.0

| Threshold | Precision | Recall | F1 | FP | FN | Time |
|-----------|-----------|--------|------|----|----|------|
| 0.0 | 82.1% | 88.6% | 85.2% | 17 | 10 | 30ms |
| 0.3 | 83.0% | 88.6% | 85.7% | 16 | 10 | 35ms |
| **0.5 (recommended)** | **92.7%** | **86.4%** | **89.4%** | **6** | **12** | 45ms |

### Perfect detection (100% P + R at threshold 0.0)

EMAIL_ADDRESS, AU_ABN, AU_ACN, AU_MEDICARE, AU_TFN, BR_CPF, CA_SIN, CN_PASSPORT, CN_PHONE, DE_HANDELSREGISTER, DE_STEUER_ID, DE_TAX_ID, DE_VAT_ID, ES_NIE, ES_NIF, FI_PERSONAL_ID, IN_PAN, IN_PASSPORT, IP_ADDRESS (recall), IT_FISCAL_CODE, JP_MY_NUMBER, KR_RRN, MAC_ADDRESS, PL_PESEL, SE_PERSONAL_NUMBER, SG_NRIC, UK_DRIVING_LICENCE, UK_NHS, URL, US_BANK_ROUTING, US_DRIVER_LICENSE, US_ITIN, UUID

### Known weaknesses

- **PHONE_NUMBER**: Generic phone regex matches digit substrings in other PII (IBAN, credit cards, CN ID). 38.9% precision at threshold 0.0, improved at 0.5.
- **JP_PASSPORT, UK_NINO, FR_NIR, DE_ID_CARD, CN_BANK_CARD**: 0% recall — recognizer patterns need refinement or context words not present in test data.

## Running

### pii-vault (TypeScript)

```bash
npx tsx benchmark/run_pii_vault.ts [threshold]
# Default threshold: 0.0
# Recommended: npx tsx benchmark/run_pii_vault.ts 0.5
```

### Presidio (Python)

```bash
pip install presidio-analyzer spacy
python -m spacy download en_core_web_lg
python benchmark/run_presidio.py
```

### Compare

```bash
python benchmark/compare.py
```

## Cross-implementation comparison

The same benchmark runs against the Rust, Swift and TypeScript implementations. Each runner loads
`spec/recognizers`, analyzes the dataset once (scored output), then times 200 warm passes and a
long document (the ASCII-only samples joined and repeated 20×, 106k UTF-16 units; ASCII-only
because the Rust context window panics when its ±100-byte slice lands inside a multi-byte
character). Offsets are reported in UTF-16 units, the unit `dataset.json` uses.

```bash
cargo run --release -p pii-vault --example benchmark -- 0.0      # → results_rust.json
(cd swift && swift run -c release PIIVaultBenchmark 0.0)         # → results_swift.json
npx tsx benchmark/run_pii_vault.ts 0.0                           # → results_pii_vault.json
python3 benchmark/compare_impls.py 0.0 0.5
```

Results (Apple Silicon, single thread, 2026-10-26; medians, stable within ~3% across runs), with
all 71 recognizers loaded (47 PII + 24 secret rules):

| Threshold | Impl | P | R | F1 | Load rules | First pass | Warm pass | Long doc |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| 0.0 | Rust | 81.2% | 88.6% | 84.8% | 14.4 ms | 3.7 ms | 0.80 ms | **10.6 ms** |
| 0.0 | Swift | 81.2% | 88.6% | 84.8% | 6.3 ms | 8.4 ms | 7.88 ms | 124 ms (17 ms concurrent) |
| 0.0 | TypeScript | 81.2% | 88.6% | 84.8% | 1.6 ms | 10.2 ms | **0.54 ms** | 25 ms |
| 0.5 | Rust | 91.6% | 86.4% | 88.9% | 14.4 ms | 3.8 ms | 0.79 ms | **9.6 ms** |
| 0.5 | Swift | 91.6% | 86.4% | 88.9% | 6.0 ms | 8.4 ms | 7.89 ms | 123 ms (16 ms concurrent) |
| 0.5 | TypeScript | 91.6% | 86.4% | 88.9% | 1.6 ms | 10.4 ms | **0.55 ms** | 29 ms |

The one extra false positive compared with the PII-only rule set is sample 97,
`AWS access key: AKIAIOSFODNN7EXAMPLE (not real)`: the dataset has no secret labels, and that
string is AWS's documented example key, which AWS_ACCESS_KEY_ID correctly matches. The 47 PII
rules alone scored P 82.1% / R 88.6% (t=0.0) and P 92.7% / R 86.4% (t=0.5) with warm passes of
0.64 ms (Rust), 5.65 ms (Swift) and 0.37 ms (TypeScript).

All three return identical detections on every sample. Speed differences come from the regex
engines: V8 JIT-compiles regexes (lowest per-call overhead, best on short texts; compilation is
deferred to the first pass), Rust's `regex` uses lazy DFAs (linear time, best on long text,
compiles eagerly at load), and Swift's `NSRegularExpression` is ICU's backtracking bytecode
interpreter with a fixed per-call cost (~70% of Swift's time is inside ICU). Swift's native
`Regex` measured ~10× slower than ICU on these patterns, so it is not used.

"Concurrent" is Swift's `Analyzer.analyzeConcurrently`, which runs each rule pattern as a separate
work item on all 14 cores and returns results identical to `analyze` (the runner checks this).
Its floor is the slowest single pattern (email, ~13 ms on this document). The other columns are
single-threaded in all three implementations.

## Entity Matching

- Type match required (with compatible types: CN_PHONE ↔ PHONE_NUMBER)
- Character overlap ≥ 50% for position matching
- Each ground truth entity matched at most once
