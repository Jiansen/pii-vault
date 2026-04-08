import { EntityType, RecognizerResult } from './entity';

export interface Recognizer {
  name: string;
  supportedEntities: EntityType[];
  analyze(text: string, entities: EntityType[]): RecognizerResult[];
}

export interface PatternDef {
  name: string;
  regex: string;
  score: number;
}

export interface RecognizerDef {
  name: string;
  entity_type: string;
  version: string;
  patterns: PatternDef[];
  context_words?: string[];
  context_score_boost?: number;
  deny_list?: string[];
  validators?: string[];
  supported_languages?: string[] | null;
}

export class RegexRecognizer implements Recognizer {
  readonly name: string;
  readonly supportedEntities: EntityType[];
  private readonly entity: EntityType;
  private readonly compiled: Array<{ name: string; regex: RegExp; score: number }>;
  private readonly contextWords: string[];
  private readonly contextBoost: number;
  private readonly denyList: Set<string>;
  private readonly validators: string[];

  constructor(private readonly def: RecognizerDef) {
    this.name = def.name;
    this.entity = new EntityType(def.entity_type);
    this.supportedEntities = [this.entity];
    this.contextWords = (def.context_words || []).map(w => w.toLowerCase());
    this.contextBoost = def.context_score_boost || 0;
    this.denyList = new Set(def.deny_list || []);
    this.validators = def.validators || [];
    this.compiled = def.patterns.map(p => ({
      name: p.name,
      regex: new RegExp(p.regex, 'g'),
      score: p.score,
    }));
  }

  static fromJson(json: string): RegexRecognizer {
    const def: RecognizerDef = JSON.parse(json);
    return new RegexRecognizer(def);
  }

  analyze(text: string, entities: EntityType[]): RecognizerResult[] {
    if (entities.length > 0 && !entities.some(e => e.equals(this.entity))) {
      return [];
    }

    const results: RecognizerResult[] = [];
    for (const { name, regex, score } of this.compiled) {
      regex.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = regex.exec(text)) !== null) {
        const matched = match[0];

        if (this.denyList.has(matched)) continue;
        if (!this.validate(matched)) continue;

        let finalScore = score;
        if (this.hasContext(text, match.index, match.index + matched.length)) {
          finalScore = Math.min(finalScore + this.contextBoost, 1.0);
        }

        results.push({
          entityType: this.entity,
          start: match.index,
          end: match.index + matched.length,
          score: finalScore,
          recognizerName: name,
        });
      }
    }
    return results;
  }

  private hasContext(text: string, start: number, end: number): boolean {
    if (this.contextWords.length === 0) return false;
    const windowStart = Math.max(0, start - 100);
    const windowEnd = Math.min(text.length, end + 100);
    const window = text.slice(windowStart, windowEnd).toLowerCase();
    return this.contextWords.some(w => window.includes(w));
  }

  private validate(matched: string): boolean {
    for (const v of this.validators) {
      switch (v) {
        case 'luhn': if (!luhnCheck(matched)) return false; break;
        case 'cn_id_checksum': if (!cnIdCheck(matched)) return false; break;
        case 'iban': if (!ibanCheck(matched)) return false; break;
        case 'de_tax_id': if (!deTaxIdCheck(matched)) return false; break;
        case 'au_abn': if (!auAbnCheck(matched)) return false; break;
        case 'au_tfn': if (!auTfnCheck(matched)) return false; break;
        case 'au_acn': if (!auAcnCheck(matched)) return false; break;
        case 'au_medicare': if (!auMedicareCheck(matched)) return false; break;
        case 'uk_driving_licence': if (!ukDrivingLicenceCheck(matched)) return false; break;
      }
    }
    return true;
  }
}

export function luhnCheck(number: string): boolean {
  const digits = number.replace(/\D/g, '');
  if (digits.length < 2) return false;
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let val = parseInt(digits[i], 10);
    if (double) {
      val *= 2;
      if (val > 9) val -= 9;
    }
    sum += val;
    double = !double;
  }
  return sum % 10 === 0;
}

export function cnIdCheck(id: string): boolean {
  if (id.length !== 18) return false;
  const weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
  const checkChars = '10X98765432';
  let sum = 0;
  for (let i = 0; i < 17; i++) {
    const d = parseInt(id[i], 10);
    if (isNaN(d)) return false;
    sum += d * weights[i];
  }
  return id[17].toUpperCase() === checkChars[sum % 11];
}

export function ibanCheck(iban: string): boolean {
  const cleaned = iban.replace(/[\s-]/g, '');
  if (cleaned.length < 5 || cleaned.length > 34) return false;
  const rearranged = cleaned.slice(4) + cleaned.slice(0, 4);
  const numeric = rearranged.split('').map(c => {
    const code = c.charCodeAt(0);
    if (code >= 48 && code <= 57) return c;
    return String(code - 55);
  }).join('');
  let remainder = 0;
  for (let i = 0; i < numeric.length; i += 7) {
    const chunk = String(remainder) + numeric.slice(i, i + 7);
    remainder = parseInt(chunk, 10) % 97;
  }
  return remainder === 1;
}

export function deTaxIdCheck(id: string): boolean {
  const digits = id.replace(/\D/g, '');
  if (digits.length !== 11) return false;
  const d = digits.split('').map(Number);
  if (d[0] === 0) return false;
  const first10 = new Set(d.slice(0, 10));
  if (first10.size === 1) return false;
  let product = 10;
  for (let i = 0; i < 10; i++) {
    let total = (d[i] + product) % 10;
    if (total === 0) total = 10;
    product = (total * 2) % 11;
  }
  let check = 11 - product;
  if (check === 10) check = 0;
  return check === d[10];
}

export function auAbnCheck(abn: string): boolean {
  const digits = abn.replace(/\D/g, '').split('').map(Number);
  if (digits.length !== 11) return false;
  const weights = [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19];
  const d = [...digits];
  d[0] -= 1;
  const sum = d.reduce((acc, v, i) => acc + v * weights[i], 0);
  return sum % 89 === 0;
}

export function auTfnCheck(tfn: string): boolean {
  const digits = tfn.replace(/\D/g, '').split('').map(Number);
  if (digits.length !== 9) return false;
  const weights = [1, 4, 3, 7, 5, 8, 6, 9, 10];
  const sum = digits.reduce((acc, v, i) => acc + v * weights[i], 0);
  return sum % 11 === 0;
}

export function auAcnCheck(acn: string): boolean {
  const digits = acn.replace(/\D/g, '').split('').map(Number);
  if (digits.length !== 9) return false;
  const weights = [8, 7, 6, 5, 4, 3, 2, 1];
  const sum = digits.slice(0, 8).reduce((acc, v, i) => acc + v * weights[i], 0);
  const check = (10 - (sum % 10)) % 10;
  return check === digits[8];
}

export function auMedicareCheck(medicare: string): boolean {
  const digits = medicare.replace(/\D/g, '').split('').map(Number);
  if (digits.length < 10 || digits.length > 11) return false;
  if (digits[0] < 2 || digits[0] > 6) return false;
  const weights = [1, 3, 7, 9, 1, 3, 7, 9];
  const sum = digits.slice(0, 8).reduce((acc, v, i) => acc + v * weights[i], 0);
  return sum % 10 === digits[8];
}

export function ukDrivingLicenceCheck(licence: string): boolean {
  const text = licence.toUpperCase();
  if (text.length !== 16) return false;
  const surname = text.slice(0, 5);
  // All 9s = no valid surname
  if (surname === '99999') return false;
  // Surname must be letters followed by optional 9-padding (no 9 before a letter)
  let seenNine = false;
  for (const c of surname) {
    if (c === '9') {
      seenNine = true;
    } else if (seenNine) {
      return false; // Letter after 9 = invalid padding
    }
  }
  // Must start with at least one letter
  if (surname[0] >= '0' && surname[0] <= '9') return false;
  return true;
}
