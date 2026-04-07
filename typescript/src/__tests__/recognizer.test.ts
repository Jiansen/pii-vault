import { RegexRecognizer, luhnCheck, cnIdCheck } from '../recognizer';
import { EntityType } from '../entity';

describe('RegexRecognizer', () => {
  const emailDef = {
    name: 'email_recognizer',
    entity_type: 'EMAIL_ADDRESS',
    version: '1.0.0',
    patterns: [{ name: 'email', regex: '[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}', score: 0.5 }],
    context_words: ['email'],
    context_score_boost: 0.4,
  };

  test('detects email address', () => {
    const rec = new RegexRecognizer(emailDef);
    const results = rec.analyze('Contact me at test@example.com please', []);
    expect(results).toHaveLength(1);
    expect(results[0].entityType.name).toBe('EMAIL_ADDRESS');
    expect('Contact me at test@example.com please'.slice(results[0].start, results[0].end)).toBe('test@example.com');
  });

  test('context boost increases score', () => {
    const rec = new RegexRecognizer(emailDef);
    const withCtx = rec.analyze('My email is test@example.com', []);
    const withoutCtx = rec.analyze('test@example.com', []);
    expect(withCtx[0].score).toBeGreaterThan(withoutCtx[0].score);
  });

  test('filters by entity type', () => {
    const rec = new RegexRecognizer(emailDef);
    const results = rec.analyze('test@example.com', [new EntityType('PHONE_NUMBER')]);
    expect(results).toHaveLength(0);
  });

  test('deny list filters matches', () => {
    const ipDef = {
      name: 'ip_recognizer',
      entity_type: 'IP_ADDRESS',
      version: '1.0.0',
      patterns: [{ name: 'ipv4', regex: '\\b(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\b', score: 0.5 }],
      deny_list: ['0.0.0.0', '127.0.0.1'],
      context_words: [],
    };
    const rec = new RegexRecognizer(ipDef);
    const results = rec.analyze('Server at 127.0.0.1 and 192.168.1.1', []);
    expect(results).toHaveLength(1);
    expect('Server at 127.0.0.1 and 192.168.1.1'.slice(results[0].start, results[0].end)).toBe('192.168.1.1');
  });

  test('detects US SSN', () => {
    const ssnDef = {
      name: 'us_ssn_recognizer',
      entity_type: 'US_SSN',
      version: '1.0.0',
      patterns: [{ name: 'ssn', regex: '\\b\\d{3}-\\d{2}-\\d{4}\\b', score: 0.5 }],
      context_words: ['social security', 'ssn'],
      context_score_boost: 0.4,
    };
    const rec = new RegexRecognizer(ssnDef);
    const results = rec.analyze('SSN: 123-45-6789', []);
    expect(results).toHaveLength(1);
    expect(results[0].entityType.name).toBe('US_SSN');
  });

  test('detects Chinese ID card', () => {
    const cnDef = {
      name: 'cn_id_card_recognizer',
      entity_type: 'CN_ID_CARD',
      version: '1.0.0',
      patterns: [{ name: 'cn_id', regex: '\\b\\d{17}[\\dXx]\\b', score: 0.3 }],
      context_words: ['身份证'],
      context_score_boost: 0.5,
      validators: ['cn_id_checksum'],
    };
    const rec = new RegexRecognizer(cnDef);
    const results = rec.analyze('身份证号: 11010519491231002X', []);
    expect(results).toHaveLength(1);
    expect(results[0].score).toBe(0.8);
  });

  test('detects Chinese phone number', () => {
    const phoneDef = {
      name: 'cn_phone_recognizer',
      entity_type: 'CN_PHONE',
      version: '1.0.0',
      patterns: [{ name: 'cn_mobile', regex: '\\b1[3-9]\\d{9}\\b', score: 0.4 }],
      context_words: ['手机'],
      context_score_boost: 0.3,
    };
    const rec = new RegexRecognizer(phoneDef);
    const results = rec.analyze('手机号: 13912345678', []);
    expect(results).toHaveLength(1);
    expect(results[0].entityType.name).toBe('CN_PHONE');
  });

  test('detects credit card with Luhn validation', () => {
    const ccDef = {
      name: 'credit_card_recognizer',
      entity_type: 'CREDIT_CARD',
      version: '1.0.0',
      patterns: [{ name: 'cc', regex: '\\b(?:\\d{4}[\\-\\s]?){3}\\d{4}\\b', score: 0.3 }],
      validators: ['luhn'],
    };
    const rec = new RegexRecognizer(ccDef);
    const valid = rec.analyze('Card: 4111111111111111', []);
    expect(valid).toHaveLength(1);
    const invalid = rec.analyze('Card: 1234567890123456', []);
    expect(invalid).toHaveLength(0);
  });

  test('detects multiple emails in text', () => {
    const rec = new RegexRecognizer(emailDef);
    const results = rec.analyze('Contact alice@test.com and bob@test.com', []);
    expect(results).toHaveLength(2);
  });
});

describe('Validators', () => {
  test('luhn valid', () => {
    expect(luhnCheck('4532015112830366')).toBe(true);
    expect(luhnCheck('4111111111111111')).toBe(true);
  });

  test('luhn invalid', () => {
    expect(luhnCheck('1234567890123456')).toBe(false);
  });

  test('Chinese ID valid', () => {
    expect(cnIdCheck('11010519491231002X')).toBe(true);
  });

  test('Chinese ID invalid', () => {
    expect(cnIdCheck('110105194912310020')).toBe(false);
  });
});
