// Package piivault provides Presidio-compatible PII detection, anonymization,
// and reversible tokenization.
//
// The Go SDK is not yet implemented. Currently available implementations:
//
//   - Rust: cargo add pii-vault (full implementation, 60 tests)
//   - TypeScript: npm install pii-vault (full implementation, 62 tests)
//   - WASM: runs in the browser — https://jiansen.github.io/pii-vault/
//
// Track progress: https://github.com/Jiansen/pii-vault/issues
package piivault

import "errors"

// ErrNotImplemented is returned by all placeholder functions.
var ErrNotImplemented = errors.New(
	"pii-vault Go SDK is not yet implemented; " +
		"use the Rust (cargo add pii-vault) or TypeScript (npm install pii-vault) SDK; " +
		"see https://github.com/Jiansen/pii-vault",
)
