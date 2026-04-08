"""pii-vault: Presidio-compatible PII detection, anonymization, and reversible tokenization.

The Python SDK is not yet implemented. Currently available implementations:

- **Rust**: ``cargo add pii-vault`` (full implementation, 60 tests)
- **TypeScript**: ``npm install pii-vault`` (full implementation, 62 tests)
- **WASM**: runs in the browser — https://jiansen.github.io/pii-vault/

If you need Python PII detection today, consider:
- Using the WASM build via a JS runtime
- Calling the Rust library via PyO3 (planned)
- Microsoft Presidio (Python-native, but heavier)

Track progress: https://github.com/Jiansen/pii-vault/issues
"""

__version__ = "0.2.0"


def _not_yet() -> None:
    raise NotImplementedError(
        "pii-vault Python SDK is not yet implemented. "
        "Use the Rust (cargo add pii-vault) or TypeScript (npm install pii-vault) SDK. "
        "See https://github.com/Jiansen/pii-vault"
    )


class Analyzer:
    """Placeholder — raises NotImplementedError with guidance."""

    def __init__(self, *args, **kwargs):
        _not_yet()


class Anonymizer:
    """Placeholder — raises NotImplementedError with guidance."""

    def __init__(self, *args, **kwargs):
        _not_yet()


class Vault:
    """Placeholder — raises NotImplementedError with guidance."""

    def __init__(self, *args, **kwargs):
        _not_yet()
