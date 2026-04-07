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
        case 'luhn':
          if (!luhnCheck(matched)) return false;
          break;
        case 'cn_id_checksum':
          if (!cnIdCheck(matched)) return false;
          break;
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
