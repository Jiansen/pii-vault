import { RecognizerResult } from './entity';
import { Vault } from './vault';

export type Operator =
  | { type: 'replace'; newValue?: string }
  | { type: 'mask'; maskingChar: string; charsToMask: number; fromEnd: boolean }
  | { type: 'hash' }
  | { type: 'redact' }
  | { type: 'vault' };

export interface AnonymizedItem {
  entityType: string;
  start: number;
  end: number;
  original: string;
  replacement: string;
}

export interface AnonymizedResult {
  text: string;
  items: AnonymizedItem[];
}

export class Anonymizer {
  static anonymize(
    text: string,
    entities: RecognizerResult[],
    operators: Record<string, Operator> = {},
    defaultOperator: Operator = { type: 'replace' },
    vault?: Vault
  ): AnonymizedResult {
    const sorted = [...entities].sort((a, b) => b.start - a.start);
    let result = text;
    const items: AnonymizedItem[] = [];

    for (const entity of sorted) {
      const original = text.slice(entity.start, entity.end);
      const op = operators[entity.entityType.name] || defaultOperator;

      let replacement: string;
      switch (op.type) {
        case 'replace':
          replacement = op.newValue || `<${entity.entityType.name}>`;
          break;
        case 'mask':
          replacement = maskText(original, op.maskingChar, op.charsToMask, op.fromEnd);
          break;
        case 'hash':
          replacement = hashText(original);
          break;
        case 'redact':
          replacement = '';
          break;
        case 'vault':
          replacement = vault
            ? vault.tokenize(entity.entityType.name, original)
            : `<${entity.entityType.name}>`;
          break;
      }

      items.push({
        entityType: entity.entityType.name,
        start: entity.start,
        end: entity.end,
        original,
        replacement,
      });

      result = result.slice(0, entity.start) + replacement + result.slice(entity.end);
    }

    items.reverse();
    return { text: result, items };
  }
}

function maskText(text: string, maskChar: string, charsToMask: number, fromEnd: boolean): string {
  const chars = [...text];
  const toMask = Math.min(charsToMask, chars.length);
  if (fromEnd) {
    for (let i = chars.length - 1; i >= chars.length - toMask; i--) {
      chars[i] = maskChar;
    }
  } else {
    for (let i = 0; i < toMask; i++) {
      chars[i] = maskChar;
    }
  }
  return chars.join('');
}

function hashText(text: string): string {
  let hash = 2166136261;
  for (let i = 0; i < text.length; i++) {
    hash = Math.imul(hash ^ text.charCodeAt(i), 16777619) >>> 0;
  }
  return hash.toString(16).padStart(8, '0');
}
