# PII Vault

**Presidio-compatible PII detection, anonymization, and reversible tokenization.**

[![Crates.io](https://img.shields.io/crates/v/pii-vault)](https://crates.io/crates/pii-vault)
[![npm](https://img.shields.io/npm/v/pii-vault)](https://www.npmjs.com/package/pii-vault)
[![PyPI](https://img.shields.io/pypi/v/pii-vault)](https://pypi.org/project/pii-vault/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE-MIT)

Spec-driven PII and secret detection with **74 recognizers** (50 PII across 15+ countries, 24 API-key/token types), **16 checksum validators**, and **reversible vault tokenization** for LLM de-anonymization. Zero runtime dependencies beyond regex.

## Install

| Language | Status | Install |
|----------|--------|---------|
| **Rust** | Full implementation (64 tests) | `cargo add pii-vault` |
| **TypeScript** | Full implementation (67 tests) | `npm install pii-vault` |
| **Swift** | Full implementation (93 tests), macOS 13+ | SwiftPM: [`swift/`](swift/README.md) |
| **WASM** | Working (1.2MB bundle) | [Live demo](https://jiansen.github.io/pii-vault/) |
| Python | Placeholder — PyO3 bindings planned | `pip install pii-vault` |
| Go | Placeholder — planned | `go get github.com/Jiansen/pii-vault/go` |

## Features

- **50 PII recognizers** covering 15+ countries (US, UK, CN, IN, AU, DE, IT, ES, KR, SG, FI, SE, PL, JP, FR, CA, BR, NL)
- **24 secret recognizers** for API keys and tokens (AWS, GitHub, GitLab, Slack, Stripe, OpenAI, private keys, JWT, …), ported from [detect-secrets](https://github.com/Yelp/detect-secrets) (Apache-2.0); each rule's `note` documents its source and any deviation
- **16 checksum validators**: Luhn, IBAN, Chinese ID, German Tax ID, AU ABN/TFN/ACN/Medicare, UK Driving Licence, UK NHS, US ABA routing, Brazilian CPF/CNPJ, Polish PESEL, Dutch BSN, Verhoeff (Aadhaar)
- **Presidio-aligned regex patterns** for core entity types (email, credit card, IP, crypto)
- **Shared spec**: Recognizer patterns defined as JSON, consumed by all language implementations
- **Vault**: Deterministic, reversible tokenization with collision handling and context disambiguation
- **5 anonymization strategies**: Replace, Mask, Hash, Redact, Vault
- **Context-aware scoring**: Boost detection confidence when context words appear nearby, as whole words or their plural with "s" ("call" counts in "Calls: …" but "tel" not in "hotel"; Chinese, Japanese, Korean and Thai words match anywhere)
- **Zero runtime dependencies** beyond regex and JSON parsing
- **224 tests** across Rust, TypeScript and Swift

## Quick Start

### Rust

```toml
[dependencies]
pii-vault = "0.2"
```

```rust
use pii_vault::{Analyzer, Anonymizer, Operator, Vault, load_recognizers_from_dir};
use std::collections::HashMap;
use std::path::Path;

// Load recognizers from spec/
let recognizers = load_recognizers_from_dir(Path::new("spec/recognizers"));
let analyzer = Analyzer::new(recognizers);

// Analyze text
let text = "Email alice@company.com, SSN 123-45-6789";
let result = analyzer.analyze(text, &[], 0.0);

// Anonymize with vault (reversible)
let mut vault = Vault::new();
let mut ops = HashMap::new();
ops.insert("EMAIL_ADDRESS".to_string(), Operator::Vault);
ops.insert("US_SSN".to_string(), Operator::Vault);

let anon = Anonymizer::anonymize(text, &result.entities, &ops, &Operator::default(), Some(&mut vault));
println!("{}", anon.text);
// "Email [EMAIL_ADDRESS:a1b2], SSN [US_SSN:c3d4]"

// Restore original
let restored = vault.detokenize(&anon.text);
assert_eq!(restored, text);
```

### TypeScript

```bash
npm install pii-vault
```

```typescript
import { Analyzer, Anonymizer, RegexRecognizer, Vault } from 'pii-vault';
import * as fs from 'fs';

// Load recognizers from spec/
const specDir = './spec/recognizers';
const recognizers = fs.readdirSync(specDir)
  .filter(f => f.endsWith('.json'))
  .map(f => new RegexRecognizer(JSON.parse(fs.readFileSync(`${specDir}/${f}`, 'utf-8'))));

const analyzer = new Analyzer(recognizers);

// Analyze
const text = 'Email alice@company.com, SSN 123-45-6789';
const result = analyzer.analyze(text);

// Anonymize with vault
const vault = new Vault();
const ops = { EMAIL_ADDRESS: { type: 'vault' }, US_SSN: { type: 'vault' } };
const anon = Anonymizer.anonymize(text, result.entities, ops, { type: 'replace' }, vault);

// Restore
const restored = vault.detokenize(anon.text);
```

### Swift

```swift
import PIIVault

let analyzer = try Analyzer(rulesDirectory: URL(fileURLWithPath: "spec/recognizers"))
let text = "Email alice@company.com, SSN 123-45-6789"
let result = analyzer.analyze(text, scoreThreshold: 0.5)

result.entities          // [EMAIL_ADDRESS {6, 17} 0.9, US_SSN {29, 11} 0.9] — UTF-16 offsets / NSRange
result.redactionRanges   // [NSRange] to blank out, overlaps merged

let vault = Vault()
let anon = Anonymizer.anonymize(text, entities: result.entities,
                                operators: [.emailAddress: .vault, .usSSN: .vault], vault: vault)
vault.detokenize(anon.text) == text  // true
```

See [swift/README.md](swift/README.md) for app integration notes.

## Architecture

```
pii-vault/
├── spec/                     # Shared specification (language-agnostic)
│   ├── entities.json         # 74 entity type definitions
│   ├── recognizers/          # 74 regex recognizer definitions (JSON)
│   ├── tools/                # generator for the detect-secrets rules
│   └── test-cases/           # Cross-language test cases
├── rust/                     # Rust implementation → crates.io: pii-vault ✅
├── typescript/               # TypeScript implementation → npm: pii-vault ✅
├── swift/                    # Swift package (macOS library) ✅
├── wasm/                     # WASM from Rust → GitHub Pages demo ✅
├── python/                   # Python placeholder (PyO3 planned)
├── go/                       # Go placeholder (planned)
└── java/                     # Java placeholder (planned)
```

The `spec/recognizers/*.json` files are the **single source of truth**. All language implementations load these patterns at runtime or compile time.

## Supported Entity Types

### Generic (all languages)
EMAIL_ADDRESS, PHONE_NUMBER, CREDIT_CARD, CRYPTO, IP_ADDRESS, MAC_ADDRESS, IBAN_CODE, URL, UUID

### Country-Specific
| Country | Entities |
|---------|----------|
| US | SSN, ITIN, Passport, Driver License, Bank Routing |
| UK | NHS, NINO |
| China | ID Card (18-digit), Phone, Passport, Bank Card |
| India | Aadhaar, PAN, Passport |
| Australia | TFN, Medicare, ABN |
| Germany | Steuer-ID |
| Italy | Fiscal Code |
| Spain | NIE, NIF |
| Korea | RRN |
| Singapore | NRIC |
| Finland | Personal ID |
| Sweden | Personal Number |
| Poland | PESEL |
| Japan | My Number, Passport |
| France | NIR |
| Canada | SIN |
| Brazil | CPF, CNPJ |
| Netherlands | BSN |

## Anonymization Strategies

| Strategy | Description | Reversible |
|----------|-------------|------------|
| Replace | Replace with `<ENTITY_TYPE>` or custom string | No |
| Mask | Partially mask characters (e.g., `****1111`) | No |
| Hash | FNV hash of original value | No |
| Redact | Remove entirely | No |
| **Vault** | Deterministic token `[ENTITY:xxxx]` with persistent mapping | **Yes** |

## Contributing

Add a new recognizer:
1. Create `spec/recognizers/your_entity.json` following the existing format
2. Add test cases to `spec/test-cases/`
3. Run tests in both Rust and TypeScript to verify

## License

MIT
