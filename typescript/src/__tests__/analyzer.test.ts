import { Analyzer } from '../analyzer';
import { RegexRecognizer } from '../recognizer';
import { EntityType } from '../entity';

const emailRec = new RegexRecognizer({
  name: 'email_recognizer',
  entity_type: 'EMAIL_ADDRESS',
  version: '1.0.0',
  patterns: [{ name: 'email', regex: '[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}', score: 0.5 }],
  context_words: ['email'],
  context_score_boost: 0.4,
});

const phoneRec = new RegexRecognizer({
  name: 'phone_recognizer',
  entity_type: 'PHONE_NUMBER',
  version: '1.0.0',
  patterns: [{ name: 'phone', regex: '\\(?\\d{3}\\)?[\\-\\s.]?\\d{3}[\\-\\s.]?\\d{4}', score: 0.4 }],
  context_words: ['phone', 'call'],
  context_score_boost: 0.4,
});

describe('Analyzer', () => {
  test('detects multiple entity types', () => {
    const analyzer = new Analyzer([emailRec, phoneRec]);
    const result = analyzer.analyze('Email alice@example.com or call 555-123-4567');
    expect(result.entities).toHaveLength(2);
    expect(result.entities[0].entityType.name).toBe('EMAIL_ADDRESS');
    expect(result.entities[1].entityType.name).toBe('PHONE_NUMBER');
  });

  test('filters by entity type', () => {
    const analyzer = new Analyzer([emailRec, phoneRec]);
    const result = analyzer.analyze(
      'Email alice@example.com or call 555-123-4567',
      [new EntityType('EMAIL_ADDRESS')]
    );
    expect(result.entities).toHaveLength(1);
    expect(result.entities[0].entityType.name).toBe('EMAIL_ADDRESS');
  });

  test('score threshold', () => {
    const analyzer = new Analyzer([emailRec]);
    const result = analyzer.analyze('test@example.com', [], 0.9);
    expect(result.entities).toHaveLength(0);
  });

  test('recognizer count', () => {
    const analyzer = new Analyzer([emailRec, phoneRec]);
    expect(analyzer.recognizerCount).toBe(2);
  });
});
