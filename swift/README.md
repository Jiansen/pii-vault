# PIIVault (Swift)

Swift port of the [Rust implementation](../rust): loads the shared JSON rules in
[`spec/recognizers`](../spec/recognizers), finds PII, and tells you which ranges to redact.
Foundation only (`NSRegularExpression`), no third-party dependencies. macOS 13+.

## Add to an app

```swift
// Package.swift
.package(path: "../pii-vault/swift")   // or a git URL
// target dependency
.product(name: "PIIVault", package: "PIIVault")
```

In an Xcode app project: File → Add Package Dependencies → Add Local… → select `swift/`.
Ship the rule files with the app: add `spec/recognizers` to the target as a folder reference
(so it is copied into the bundle as a directory and stays in sync with the spec) and load it
with `Analyzer(rulesDirectory:)`. `spec/recognizers` is the single source of truth shared by all
implementations; don't bundle `docs/recognizers.json`, which is a hand-maintained copy for the web
demo and lags behind the spec.

## Usage

```swift
import PIIVault

// Load rules once and share the analyzer: it is immutable and Sendable.
let rules = Bundle.main.url(forResource: "recognizers", withExtension: nil)!
let analyzer = try Analyzer(rulesDirectory: rules)
// or: Analyzer(recognizers: try RecognizerLoader.load(file: url))  // one file, object or array

let text = "Email alice@company.com, SSN 123-45-6789"
let result = analyzer.analyze(text, scoreThreshold: 0.5)

// What to redact
for e in result.entities {
    print(e.entityType, e.score, e.text(in: text) ?? "", e.nsRange)   // EMAIL_ADDRESS 0.9 alice@company.com {6, 17}
}
let ranges: [NSRange] = result.redactionRanges   // overlapping detections merged

// Long documents: same result, every rule pattern on its own core (blocks the caller,
// so run it off the main thread). Short texts (< 256 UTF-16 units) fall back to sequential.
let big = try String(contentsOf: fileURL, encoding: .utf8)
let report = await Task.detached { analyzer.analyzeConcurrently(big, scoreThreshold: 0.5) }.value

// Or rewrite the text
let vault = Vault()
let anon = Anonymizer.anonymize(text, entities: result.entities,
                                operators: [.emailAddress: .vault, .usSSN: .mask(maskingChar: "*", charsToMask: 7, fromEnd: false)],
                                vault: vault)
anon.text                       // "Email [EMAIL_ADDRESS:1a2b3c4d], SSN *******6789"
vault.detokenize(anon.text)     // original email restored
let saved = try vault.toJSON()  // same JSON format as the Rust Vault
```

### Offsets

`RecognizerResult.start`/`end` are **UTF-16 offsets**, so `nsRange` works directly with
`NSString`, `NSAttributedString`, `NSTextView`/`UITextView` and PDFKit. Use `range(in:)` for a
`Range<String.Index>`. (Rust reports UTF-8 byte offsets; TypeScript reports UTF-16 like Swift.)

### Custom recognizers

Conform to `Recognizer` (`name`, `supportedEntities`, `analyze(_:entities:)`) and pass it to
`Analyzer(recognizers:)` alongside the loaded ones.

## API overview

| Type | Purpose |
|---|---|
| `RecognizerLoader` | `load(directory:)`, `load(file:)`, `load(json:)`. Throws on a malformed file or bad regex (Rust logs and skips). Directory files load in name order. |
| `RecognizerDefinition`, `RegexRecognizer` | The rule format and its compiled form. Unknown validator names are ignored, as in Rust/TS. |
| `Analyzer` | `analyze(_:entities:scoreThreshold:)` → `AnalyzerResult` (`entities`, `redactionRanges`). `analyzeConcurrently(...)` returns the identical result with patterns run in parallel (~6× on a 106k-character document, 14 cores). |
| `Anonymizer`, `Operator` | `.replace`, `.mask`, `.hash` (FNV-1a), `.redact`, `.vault`. |
| `Vault` | Salted reversible tokens, `toJSON()` / `fromJSON(_:)`, v1 vault compatible. Not thread-safe: keep one per actor/queue. |
| `Checksum` | The validators (Luhn, IBAN, CN ID, DE tax ID, AU ABN/TFN/ACN/Medicare, UK driving licence, UK NHS, US ABA routing, BR CPF/CNPJ, PL PESEL, NL BSN, Verhoeff). |

### Differences from the Rust implementation

- Offsets are UTF-16 (see above); the context window is ±100 UTF-16 units instead of ±100 bytes.
- The loader throws instead of silently dropping a broken rule file (hidden files are skipped).
- `Anonymizer` replaces each group of partially overlapping entities as one span, using the
  highest-scoring entity's operator. Rust splices them one by one with stale offsets.
- `Vault` compares originals byte-for-byte like Rust (not with `String`'s canonical equivalence),
  and `mask` counts grapheme clusters where Rust counts scalars.
- Regex engine is ICU (`NSRegularExpression`). Like Rust's `regex`, `\d`, `\w`, `\b` are
  Unicode-aware (TypeScript's are ASCII-only). ICU's own `\b` never sees a boundary next to
  format characters (zero-width space, soft hyphen, LRM, BOM…), which would hide e.g.
  `"123-45-6789\u{200B}"`; rules are therefore compiled with `\b` rewritten into `\w`
  lookarounds that behave like Rust (see `rewriteWordBoundaries`). All spec patterns produce
  identical detections to Rust and TypeScript on the benchmark dataset.

## Tests and benchmark

```bash
swift test                                           # 93 tests (Swift Testing)
swift run -c release PIIVaultBenchmark [threshold] [iterations]
python3 ../benchmark/compare_impls.py                # compare with Rust and TypeScript
```

See [benchmark/README.md](../benchmark/README.md#cross-implementation-comparison) for results.
