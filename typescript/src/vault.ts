export interface VaultEntry {
  token: string;
  original: string;
  category: string;
  context: string;
  createdAt: string;
  lastUsed: string;
  useCount: number;
}

export interface VaultData {
  version: number;
  salt?: string;
  entries: VaultEntry[];
}

export class Vault {
  private entries: VaultEntry[] = [];
  private index = new Map<string, number>();
  private salt: string;

  constructor() {
    this.salt = Vault.generateSalt();
  }

  private static generateSalt(): string {
    if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.getRandomValues) {
      const bytes = new Uint8Array(16);
      globalThis.crypto.getRandomValues(bytes);
      return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
    }
    // Fallback for environments without Web Crypto
    let s = '';
    for (let i = 0; i < 32; i++) {
      s += Math.floor(Math.random() * 16).toString(16);
    }
    return s;
  }

  static fromJson(json: string): Vault {
    const data: VaultData = JSON.parse(json);
    const vault = new Vault();
    vault.entries = data.entries;
    if (data.version >= 2 && data.salt) {
      vault.salt = data.salt;
    }
    // v1 vaults: keep generated salt; old entries retain their original tokens
    vault.rebuildIndex();
    return vault;
  }

  toJson(): string {
    const data: VaultData = { version: 2, salt: this.salt, entries: this.entries };
    return JSON.stringify(data, null, 2);
  }

  tokenize(category: string, original: string): string {
    return this.tokenizeCtx(category, original, '');
  }

  tokenizeCtx(category: string, original: string, context: string): string {
    const key = `${category}:${original}:${context}`;
    const now = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');

    const existingIdx = this.index.get(key);
    if (existingIdx !== undefined) {
      const entry = this.entries[existingIdx];
      entry.lastUsed = now;
      entry.useCount += 1;
      return entry.token;
    }

    const hashInput = context
      ? `${this.salt}:${category}:${original}:${context}`
      : `${this.salt}:${category}:${original}`;
    let token = Vault.stableToken(category, hashInput);

    let attempt = 0;
    while (this.entries.some(e => e.token === token && (e.original !== original || e.context !== context))) {
      attempt++;
      token = Vault.stableToken(category, `${this.salt}:${category}:${original}:${context}:${attempt}`);
    }

    const entry: VaultEntry = {
      token,
      original,
      category,
      context,
      createdAt: now,
      lastUsed: now,
      useCount: 1,
    };
    const idx = this.entries.length;
    this.entries.push(entry);
    this.index.set(key, idx);

    return token;
  }

  detokenize(text: string): string {
    let result = text;
    const sorted = [...this.entries].sort((a, b) => b.token.length - a.token.length);
    for (const entry of sorted) {
      result = result.split(entry.token).join(entry.original);
    }
    return result;
  }

  lookupToken(token: string): VaultEntry | undefined {
    return this.entries.find(e => e.token === token);
  }

  get entryCount(): number {
    return this.entries.length;
  }

  private rebuildIndex(): void {
    this.index.clear();
    for (let i = 0; i < this.entries.length; i++) {
      const e = this.entries[i];
      this.index.set(`${e.category}:${e.original}:${e.context}`, i);
    }
  }

  private static stableToken(category: string, input: string): string {
    // FNV-1a 32-bit hash for better distribution
    let hash = 0x811c9dc5;
    for (let i = 0; i < input.length; i++) {
      hash ^= input.charCodeAt(i);
      hash = Math.imul(hash, 0x01000193) >>> 0;
    }
    const hex = hash.toString(16).padStart(8, '0');
    return `[${category.toUpperCase()}:${hex}]`;
  }
}
