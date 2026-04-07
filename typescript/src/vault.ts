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
  entries: VaultEntry[];
}

export class Vault {
  private entries: VaultEntry[] = [];
  private index = new Map<string, number>();

  static fromJson(json: string): Vault {
    const data: VaultData = JSON.parse(json);
    const vault = new Vault();
    vault.entries = data.entries;
    vault.rebuildIndex();
    return vault;
  }

  toJson(): string {
    const data: VaultData = { version: 1, entries: this.entries };
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

    const hashInput = context ? `${category}:${original}:${context}` : `${category}:${original}`;
    let token = Vault.stableToken(category, hashInput);

    let attempt = 0;
    while (this.entries.some(e => e.token === token && (e.original !== original || e.context !== context))) {
      attempt++;
      token = Vault.stableToken(category, `${category}:${original}:${context}:${attempt}`);
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
    let hash = 0;
    for (let i = 0; i < input.length; i++) {
      hash = (Math.imul(hash, 31) + input.charCodeAt(i)) >>> 0;
    }
    const short = (hash & 0xffff).toString(16).padStart(4, '0');
    return `[${category.toUpperCase()}:${short}]`;
  }
}
