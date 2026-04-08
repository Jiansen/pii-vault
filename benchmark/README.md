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

## Entity Matching

- Type match required (with compatible types: CN_PHONE ↔ PHONE_NUMBER)
- Character overlap ≥ 50% for position matching
- Each ground truth entity matched at most once
