import * as fs from 'fs';
import * as path from 'path';
import { Analyzer } from '../analyzer';
import { Anonymizer } from '../anonymizer';
import { RegexRecognizer, RecognizerDef } from '../recognizer';
import { Vault } from '../vault';
import { EntityType } from '../entity';

function loadSpecRecognizers(): RegexRecognizer[] {
  const specDir = path.join(__dirname, '..', '..', '..', 'spec', 'recognizers');
  const files = fs.readdirSync(specDir).filter(f => f.endsWith('.json'));
  return files.map(f => {
    const json = fs.readFileSync(path.join(specDir, f), 'utf-8');
    return new RegexRecognizer(JSON.parse(json) as RecognizerDef);
  });
}

describe('Integration: Spec-loaded recognizers', () => {
  const recognizers = loadSpecRecognizers();
  const analyzer = new Analyzer(recognizers);

  test('loads 25+ recognizers from spec/', () => {
    expect(recognizers.length).toBeGreaterThanOrEqual(25);
  });

  test('detects email', () => {
    const result = analyzer.analyze('Send to alice@company.org');
    const emails = result.entities.filter(e => e.entityType.name === 'EMAIL_ADDRESS');
    expect(emails.length).toBe(1);
  });

  test('detects multiple emails', () => {
    const result = analyzer.analyze('alice@test.com and bob@test.com');
    const emails = result.entities.filter(e => e.entityType.name === 'EMAIL_ADDRESS');
    expect(emails.length).toBe(2);
  });

  test('detects US SSN', () => {
    const result = analyzer.analyze('SSN: 123-45-6789');
    const ssns = result.entities.filter(e => e.entityType.name === 'US_SSN');
    expect(ssns.length).toBeGreaterThanOrEqual(1);
  });

  test('detects Chinese ID card', () => {
    const result = analyzer.analyze('身份证号: 11010519491231002X');
    const ids = result.entities.filter(e => e.entityType.name === 'CN_ID_CARD');
    expect(ids.length).toBe(1);
  });

  test('detects credit card (valid Luhn)', () => {
    const result = analyzer.analyze('Card: 4111111111111111');
    const cards = result.entities.filter(e => e.entityType.name === 'CREDIT_CARD');
    expect(cards.length).toBeGreaterThanOrEqual(1);
  });

  test('rejects credit card (invalid Luhn)', () => {
    const result = analyzer.analyze('Card: 1234567890123456');
    const cards = result.entities.filter(e => e.entityType.name === 'CREDIT_CARD');
    expect(cards.length).toBe(0);
  });

  test('detects IP address', () => {
    const result = analyzer.analyze('Server at 192.168.1.100');
    const ips = result.entities.filter(e => e.entityType.name === 'IP_ADDRESS');
    expect(ips.length).toBe(1);
  });

  test('denies localhost IP', () => {
    const result = analyzer.analyze('localhost is 127.0.0.1');
    const ips = result.entities.filter(e => e.entityType.name === 'IP_ADDRESS');
    expect(ips.length).toBe(0);
  });

  test('detects URL', () => {
    const result = analyzer.analyze('Visit https://example.com/page');
    const urls = result.entities.filter(e => e.entityType.name === 'URL');
    expect(urls.length).toBe(1);
  });

  test('detects UUID', () => {
    const result = analyzer.analyze('ID: 550e8400-e29b-41d4-a716-446655440000');
    const uuids = result.entities.filter(e => e.entityType.name === 'UUID');
    expect(uuids.length).toBe(1);
  });

  test('detects MAC address', () => {
    const result = analyzer.analyze('MAC: 00:1A:2B:3C:4D:5E');
    const macs = result.entities.filter(e => e.entityType.name === 'MAC_ADDRESS');
    expect(macs.length).toBe(1);
  });

  test('detects UK NINO', () => {
    const result = analyzer.analyze('NI number: AB 12 34 56 C');
    const ninos = result.entities.filter(e => e.entityType.name === 'UK_NINO');
    expect(ninos.length).toBe(1);
  });

  test('detects Indian PAN', () => {
    const result = analyzer.analyze('PAN: ABCDE1234F');
    const pans = result.entities.filter(e => e.entityType.name === 'IN_PAN');
    expect(pans.length).toBe(1);
  });

  test('detects Italian fiscal code', () => {
    const result = analyzer.analyze('CF: RSSMRA85M01H501Z');
    const cfs = result.entities.filter(e => e.entityType.name === 'IT_FISCAL_CODE');
    expect(cfs.length).toBe(1);
  });

  test('detects Brazilian CPF', () => {
    const result = analyzer.analyze('CPF: 123.456.789-09');
    const cpfs = result.entities.filter(e => e.entityType.name === 'BR_CPF');
    expect(cpfs.length).toBe(1);
  });

  test('detects Spanish NIE', () => {
    const result = analyzer.analyze('NIE: X1234567A');
    const nies = result.entities.filter(e => e.entityType.name === 'ES_NIE');
    expect(nies.length).toBe(1);
  });

  test('detects Singapore NRIC', () => {
    const result = analyzer.analyze('NRIC: S1234567A');
    const nrics = result.entities.filter(e => e.entityType.name === 'SG_NRIC');
    expect(nrics.length).toBe(1);
  });

  test('detects Korean RRN', () => {
    const result = analyzer.analyze('주민등록번호: 850101-1234567');
    const rrns = result.entities.filter(e => e.entityType.name === 'KR_RRN');
    expect(rrns.length).toBe(1);
  });

  test('detects IBAN', () => {
    const result = analyzer.analyze('IBAN: DE89370400440532013000');
    const ibans = result.entities.filter(e => e.entityType.name === 'IBAN_CODE');
    expect(ibans.length).toBeGreaterThanOrEqual(1);
  });

  test('rejects invalid IBAN checksum', () => {
    const result = analyzer.analyze('IBAN: DE00370400440532013000');
    const ibans = result.entities.filter(e => e.entityType.name === 'IBAN_CODE');
    expect(ibans.length).toBe(0);
  });

  test('detects German Tax ID', () => {
    const result = analyzer.analyze('Steuer-ID: 86095742719');
    const ids = result.entities.filter(e => e.entityType.name === 'DE_TAX_ID');
    expect(ids.length).toBeGreaterThanOrEqual(1);
  });

  test('detects German passport', () => {
    const result = analyzer.analyze('Reisepass: C01X00T47');
    const passports = result.entities.filter(e => e.entityType.name === 'DE_PASSPORT');
    expect(passports.length).toBeGreaterThanOrEqual(1);
  });

  test('detects German VAT ID', () => {
    const result = analyzer.analyze('USt-IdNr: DE123456789');
    const vats = result.entities.filter(e => e.entityType.name === 'DE_VAT_ID');
    expect(vats.length).toBeGreaterThanOrEqual(1);
  });

  test('detects Australian ABN', () => {
    const result = analyzer.analyze('ABN: 51 824 753 556');
    const abns = result.entities.filter(e => e.entityType.name === 'AU_ABN');
    expect(abns.length).toBeGreaterThanOrEqual(1);
  });

  test('detects Australian TFN', () => {
    const result = analyzer.analyze('TFN: 123 456 782');
    const tfns = result.entities.filter(e => e.entityType.name === 'AU_TFN');
    expect(tfns.length).toBeGreaterThanOrEqual(1);
  });

  test('empty text returns no entities', () => {
    const result = analyzer.analyze('');
    expect(result.entities.length).toBe(0);
  });

  test('no PII text returns no entities (with threshold)', () => {
    const result = analyzer.analyze('The weather is nice today', [], 0.3);
    expect(result.entities.length).toBe(0);
  });

  test('mixed language text detects email', () => {
    const result = analyzer.analyze('张三的邮箱是 zhangsan@example.com');
    const emails = result.entities.filter(e => e.entityType.name === 'EMAIL_ADDRESS');
    expect(emails.length).toBe(1);
  });
});

describe('Integration: Full pipeline with vault', () => {
  test('analyze → vault anonymize → detokenize roundtrip', () => {
    const recognizers = loadSpecRecognizers();
    const analyzer = new Analyzer(recognizers);
    const text = 'Email alice@company.com, SSN 123-45-6789';
    const analysis = analyzer.analyze(text);

    const vault = new Vault();
    const ops: Record<string, any> = {};
    for (const entity of analysis.entities) {
      ops[entity.entityType.name] = { type: 'vault' as const };
    }

    const anon = Anonymizer.anonymize(text, analysis.entities, ops, { type: 'replace' }, vault);

    expect(anon.text).not.toContain('alice@company.com');
    expect(anon.text).not.toContain('123-45-6789');
    expect(vault.entryCount).toBeGreaterThanOrEqual(1);

    const restored = vault.detokenize(anon.text);
    expect(restored).toContain('alice@company.com');
  });
});
