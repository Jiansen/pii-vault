# PII Vault

**Presidio-compatible PII detection, anonymization, and reversible tokenization.**

[![Crates.io](https://img.shields.io/crates/v/pii-vault)](https://crates.io/crates/pii-vault)
[![npm](https://img.shields.io/npm/v/pii-vault)](https://www.npmjs.com/package/pii-vault)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE-MIT)

Multi-language implementations sharing a common specification. Detect 40+ PII entity types, anonymize with multiple strategies (replace, mask, hash, redact), and reversibly tokenize with a persistent vault.

## Install

```bash
# Rust
cargo add pii-vault

# TypeScript / JavaScript
npm install pii-vault
```

## Features

- **29 built-in recognizers** covering 15 countries (US, UK, CN, IN, AU, DE, IT, ES, KR, SG, FI, SE, PL, JP, FR, CA, BR)
- **Presidio-aligned regex patterns** for core entity types (email, credit card, IP, crypto)
- **Shared spec**: Recognizer patterns defined as JSON, consumed by all language implementations
- **Vault**: Deterministic, reversible tokenization with collision handling and context disambiguation
- **Multiple anonymization strategies**: Replace, Mask, Hash, Redact, Vault
- **Luhn validation** for credit cards, **checksum validation** for Chinese ID cards
- **Context-aware scoring**: Boost detection confidence when context words appear nearby
- **Zero runtime dependencies** beyond regex and JSON parsing

## Quick Start

### Rust

```toml
[dependencies]
pii-vault = "0.1"
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

## Architecture

```
pii-vault/
├── spec/                     # Shared specification (language-agnostic)
│   ├── entities.json         # 45 entity type definitions
│   ├── recognizers/          # 29 regex recognizer definitions (JSON)
│   └── test-cases/           # Cross-language test cases
├── rust/                     # Rust implementation → crates.io: pii-vault
├── typescript/               # TypeScript implementation → npm: pii-vault
├── go/                       # Go implementation (planned)
├── java/                     # Java implementation (planned)
├── haskell/                  # Haskell implementation (planned)
└── wasm/                     # WASM from Rust (planned)
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
| Brazil | CPF |

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
