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

  test('token format', () => {
    const vault = new Vault();
    const token = vault.tokenize('email_address', 'test@example.com');
    expect(token).toMatch(/^\[EMAIL_ADDRESS:[0-9a-f]{4}\]$/);
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
});
