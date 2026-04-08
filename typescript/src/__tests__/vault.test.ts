import { Vault } from '../vault';

describe('Vault', () => {
  test('deterministic tokenization', () => {
    const vault = new Vault();
    const t1 = vault.tokenize('email_address', 'test@example.com');
    const t2 = vault.tokenize('email_address', 'test@example.com');
    expect(t1).toBe(t2);
    expect(vault.entryCount).toBe(1);
  });

  test('different originals get different tokens', () => {
    const vault = new Vault();
    const t1 = vault.tokenize('email_address', 'alice@example.com');
    const t2 = vault.tokenize('email_address', 'bob@example.com');
    expect(t1).not.toBe(t2);
    expect(vault.entryCount).toBe(2);
  });

  test('context disambiguation', () => {
    const vault = new Vault();
    const t1 = vault.tokenizeCtx('person', 'Zhang San', 'customer');
    const t2 = vault.tokenizeCtx('person', 'Zhang San', 'colleague');
    expect(t1).not.toBe(t2);
  });

  test('detokenize restores text', () => {
    const vault = new Vault();
    const token = vault.tokenize('email_address', 'test@example.com');
    const text = `Contact ${token}`;
    const restored = vault.detokenize(text);
    expect(restored).toBe('Contact test@example.com');
  });

  test('JSON roundtrip', () => {
    const vault = new Vault();
    vault.tokenize('email_address', 'test@example.com');
    vault.tokenize('phone_number', '555-1234');

    const json = vault.toJson();
    const loaded = Vault.fromJson(json);
    expect(loaded.entryCount).toBe(2);
  });

  test('token format is 8 hex (v2)', () => {
    const vault = new Vault();
    const token = vault.tokenize('email_address', 'test@example.com');
    expect(token).toMatch(/^\[EMAIL_ADDRESS:[0-9a-f]{8}\]$/);
  });

  test('lookup token', () => {
    const vault = new Vault();
    const token = vault.tokenize('email_address', 'test@example.com');
    const entry = vault.lookupToken(token);
    expect(entry).toBeDefined();
    expect(entry!.original).toBe('test@example.com');
  });

  test('use count increments', () => {
    const vault = new Vault();
    vault.tokenize('email_address', 'test@example.com');
    vault.tokenize('email_address', 'test@example.com');
    vault.tokenize('email_address', 'test@example.com');
    const token = vault.tokenize('email_address', 'test@example.com');
    const entry = vault.lookupToken(token);
    expect(entry!.useCount).toBe(4);
  });

  test('different vaults produce different tokens (salt isolation)', () => {
    const v1 = new Vault();
    const v2 = new Vault();
    const t1 = v1.tokenize('person', 'Zhang Wei');
    const t2 = v2.tokenize('person', 'Zhang Wei');
    expect(t1).not.toBe(t2);
  });

  test('JSON roundtrip preserves salt and produces same tokens', () => {
    const vault = new Vault();
    const token1 = vault.tokenize('person', 'Alice');
    const json = vault.toJson();
    const loaded = Vault.fromJson(json);
    const token2 = loaded.tokenize('person', 'Alice');
    expect(token2).toBe(token1);
    expect(loaded.entryCount).toBe(1);
  });

  test('toJson writes version 2 with salt', () => {
    const vault = new Vault();
    vault.tokenize('email_address', 'a@b.com');
    const data = JSON.parse(vault.toJson());
    expect(data.version).toBe(2);
    expect(typeof data.salt).toBe('string');
    expect(data.salt.length).toBe(32);
  });

  test('v1 vault JSON can be loaded (backward compat)', () => {
    const v1Json = JSON.stringify({
      version: 1,
      entries: [{
        token: '[PERSON:e702]',
        original: 'Zhang Wei',
        category: 'person',
        context: '',
        createdAt: '2026-04-01T00:00:00Z',
        lastUsed: '2026-04-01T00:00:00Z',
        useCount: 1,
      }],
    });
    const vault = Vault.fromJson(v1Json);
    expect(vault.entryCount).toBe(1);
    const entry = vault.lookupToken('[PERSON:e702]');
    expect(entry).toBeDefined();
    expect(entry!.original).toBe('Zhang Wei');
    const restored = vault.detokenize('Hello [PERSON:e702]');
    expect(restored).toBe('Hello Zhang Wei');
  });

  test('new tokenizations in loaded v1 vault use 8-hex format', () => {
    const v1Json = JSON.stringify({
      version: 1,
      entries: [{
        token: '[PERSON:e702]',
        original: 'Zhang Wei',
        category: 'person',
        context: '',
        createdAt: '2026-04-01T00:00:00Z',
        lastUsed: '2026-04-01T00:00:00Z',
        useCount: 1,
      }],
    });
    const vault = Vault.fromJson(v1Json);
    const newToken = vault.tokenize('person', 'Li Na');
    expect(newToken).toMatch(/^\[PERSON:[0-9a-f]{8}\]$/);
    expect(vault.entryCount).toBe(2);
  });
});
