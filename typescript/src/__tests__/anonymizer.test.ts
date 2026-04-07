import { Anonymizer, Operator } from '../anonymizer';
import { EntityType, RecognizerResult } from '../entity';
import { Vault } from '../vault';

function makeEntity(entityType: string, start: number, end: number): RecognizerResult {
  return {
    entityType: new EntityType(entityType),
    start,
    end,
    score: 0.9,
  };
}

describe('Anonymizer', () => {
  test('replace default', () => {
    const text = 'Email me at test@example.com';
    const entities = [makeEntity('EMAIL_ADDRESS', 12, 28)];
    const result = Anonymizer.anonymize(text, entities);
    expect(result.text).toBe('Email me at <EMAIL_ADDRESS>');
    expect(result.items).toHaveLength(1);
  });

  test('replace custom', () => {
    const text = 'SSN: 123-45-6789';
    const entities = [makeEntity('US_SSN', 5, 16)];
    const ops: Record<string, Operator> = { US_SSN: { type: 'replace', newValue: '[REDACTED]' } };
    const result = Anonymizer.anonymize(text, entities, ops);
    expect(result.text).toBe('SSN: [REDACTED]');
  });

  test('mask', () => {
    const text = 'Card: 4111111111111111';
    const entities = [makeEntity('CREDIT_CARD', 6, 22)];
    const ops: Record<string, Operator> = {
      CREDIT_CARD: { type: 'mask', maskingChar: '*', charsToMask: 12, fromEnd: false },
    };
    const result = Anonymizer.anonymize(text, entities, ops);
    expect(result.text).toBe('Card: ************1111');
  });

  test('hash', () => {
    const text = 'Email: test@example.com';
    const entities = [makeEntity('EMAIL_ADDRESS', 7, 23)];
    const ops: Record<string, Operator> = { EMAIL_ADDRESS: { type: 'hash' } };
    const result = Anonymizer.anonymize(text, entities, ops);
    expect(result.text).toMatch(/^Email: [0-9a-f]{8}$/);
  });

  test('redact', () => {
    const text = 'My phone is 555-123-4567';
    const entities = [makeEntity('PHONE_NUMBER', 12, 24)];
    const ops: Record<string, Operator> = { PHONE_NUMBER: { type: 'redact' } };
    const result = Anonymizer.anonymize(text, entities, ops);
    expect(result.text).toBe('My phone is ');
  });

  test('vault with roundtrip', () => {
    const text = 'Email: test@example.com';
    const entities = [makeEntity('EMAIL_ADDRESS', 7, 23)];
    const ops: Record<string, Operator> = { EMAIL_ADDRESS: { type: 'vault' } };
    const vault = new Vault();
    const result = Anonymizer.anonymize(text, entities, ops, { type: 'replace' }, vault);
    expect(result.text).toMatch(/\[EMAIL_ADDRESS:/);
    expect(vault.entryCount).toBe(1);

    const restored = vault.detokenize(result.text);
    expect(restored).toBe(text);
  });

  test('multiple entities', () => {
    const text = 'alice@test.com called 555-123-4567';
    const entities = [
      makeEntity('EMAIL_ADDRESS', 0, 14),
      makeEntity('PHONE_NUMBER', 22, 34),
    ];
    const result = Anonymizer.anonymize(text, entities);
    expect(result.text).toBe('<EMAIL_ADDRESS> called <PHONE_NUMBER>');
  });
});
