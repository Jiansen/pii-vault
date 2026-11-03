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

/**
 * Scripts written without spaces between words: Thai, Lao, Myanmar, Khmer, Hangul (whose
 * particles join the word before), Japanese kana and CJK ideographs. A context word in
 * one matches anywhere, as there is no word edge to look for.
 */
function isUnspacedScript(c: number): boolean {
  return (c >= 0x0E00 && c <= 0x0EFF) || (c >= 0x1000 && c <= 0x109F) || (c >= 0x1100 && c <= 0x11FF)
    || (c >= 0x1780 && c <= 0x17FF) || (c >= 0x3040 && c <= 0x30FF) || (c >= 0x3130 && c <= 0x318F)
    || (c >= 0x31F0 && c <= 0x31FF) || (c >= 0x3400 && c <= 0x4DBF) || (c >= 0x4E00 && c <= 0x9FFF)
    || (c >= 0xAC00 && c <= 0xD7AF) || (c >= 0xF900 && c <= 0xFAFF) || (c >= 0xFF66 && c <= 0xFF9F)
    || (c >= 0x20000 && c <= 0x3FFFF);
}

const LETTER_OR_DIGIT = /[\p{Alphabetic}\p{N}]/u;

/** Letters and digits make up a word; spaces, punctuation, `_` and `-` end one. */
function isWordChar(c: number | undefined): boolean {
  return c !== undefined && LETTER_OR_DIGIT.test(String.fromCodePoint(c)) && !isUnspacedScript(c);
}

/** The code point that ends just before UTF-16 index `i`. */
function codePointBefore(s: string, i: number): number | undefined {
  if (i <= 0) return undefined;
  const low = s.charCodeAt(i - 1);
  if (low >= 0xDC00 && low <= 0xDFFF && i >= 2) {
    const high = s.charCodeAt(i - 2);
    if (high >= 0xD800 && high <= 0xDBFF) return s.codePointAt(i - 2);
  }
  return low;
}

/**
 * Whether `word` occurs in `window` as a whole word: not inside a longer one, so "tel"
 * is not found in "hotel" nor "id" in "valid". An English plural counts as the word ("calls",
 * "accounts"), and an edge of the window as a word edge.
 */
export function containsWord(window: string, word: string): boolean {
  if (word.length === 0) return true;
  const checkStart = isWordChar(word.codePointAt(0));
  const checkEnd = isWordChar(codePointBefore(word, word.length));
  const plural = /[a-z]$/i.test(word);
  for (let start = window.indexOf(word); start !== -1; start = window.indexOf(word, start + 1)) {
    let end = start + word.length;
    if (plural && window[end] === 's') end += 1;
    const startsWord = !checkStart || !isWordChar(codePointBefore(window, start));
    const endsWord = !checkEnd || !isWordChar(window.codePointAt(end));
    if (startsWord && endsWord) return true;
  }
  return false;
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
    return this.contextWords.some(w => containsWord(window, w));
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
        case 'br_cnpj': if (!brCnpjCheck(matched)) return false; break;
        case 'nl_bsn': if (!nlBsnCheck(matched)) return false; break;
        case 'cpf_checksum': if (!cpfCheck(matched)) return false; break;
        case 'pesel_checksum': if (!peselCheck(matched)) return false; break;
        case 'verhoeff': if (!verhoeffCheck(matched)) return false; break;
        case 'nhs_checksum': if (!nhsCheck(matched)) return false; break;
        case 'aba_checksum': if (!abaCheck(matched)) return false; break;
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

/**
 * CNPJ: 12 base characters (0-9, or A-Z since the July 2026 alphanumeric format) and two
 * numeric mod-11 check digits. Each character is worth its ASCII code minus 48, so digits
 * keep their value and 'A' is 17; weights run 2..9 from the right, repeating.
 */
export function brCnpjCheck(cnpj: string): boolean {
  const chars = cnpj.replace(/[^0-9A-Za-z]/g, '').toUpperCase();
  if (chars.length !== 14 || !/^\d{2}$/.test(chars.slice(12))) return false;
  // 00.000.000/0000-00, 11.111.111/1111-11 and so on pass the arithmetic but are not issued.
  if (/^(.)\1*$/.test(chars)) return false;
  const values = chars.split('').map(c => c.charCodeAt(0) - 48);
  const checkDigit = (n: number): number => {
    let sum = 0;
    for (let i = 0; i < n; i++) sum += values[n - 1 - i] * (2 + (i % 8));
    return sum % 11 < 2 ? 0 : 11 - (sum % 11);
  };
  return checkDigit(12) === values[12] && checkDigit(13) === values[13];
}

/** BSN 11-proof: 9*d1 + 8*d2 + ... + 2*d8 - d9 must be a positive multiple of 11. */
export function nlBsnCheck(bsn: string): boolean {
  const d = bsn.replace(/\D/g, '').split('').map(Number);
  if (d.length !== 9) return false;
  let sum = -d[8];
  for (let i = 0; i < 8; i++) sum += d[i] * (9 - i);
  return sum > 0 && sum % 11 === 0;
}

const asciiDigits = (s: string): number[] => s.replace(/[^0-9]/g, '').split('').map(Number);

/**
 * CPF: two mod-11 check digits over weights 10..2 and 11..2. Repeated-digit numbers
 * (111.111.111-11 and so on) pass the arithmetic but are not issued.
 */
export function cpfCheck(cpf: string): boolean {
  const d = asciiDigits(cpf);
  if (d.length !== 11 || d.every(x => x === d[0])) return false;
  return [9, 10].every(n => {
    let sum = 0;
    for (let i = 0; i < n; i++) sum += d[i] * (n + 1 - i);
    return ((sum * 10) % 11) % 10 === d[n];
  });
}

/** PESEL: weights 1, 3, 7, 9 repeating over the first 10 digits; the 11th makes the sum a multiple of 10. */
export function peselCheck(pesel: string): boolean {
  const d = asciiDigits(pesel);
  if (d.length !== 11) return false;
  const weights = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3];
  const sum = weights.reduce((acc, w, i) => acc + w * d[i], 0);
  return (10 - (sum % 10)) % 10 === d[10];
}

const VERHOEFF_D = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];
const VERHOEFF_P = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

/** Verhoeff (dihedral group D5), as used by Aadhaar: the number including its check digit must reduce to 0. */
export function verhoeffCheck(number: string): boolean {
  const d = asciiDigits(number);
  if (d.length === 0) return false;
  let c = 0;
  d.reverse().forEach((x, i) => { c = VERHOEFF_D[c][VERHOEFF_P[i % 8][x]]; });
  return c === 0;
}

/**
 * NHS: weights 10..2 over the first 9 digits; the check digit is 11 minus the sum mod 11,
 * with 11 meaning 0. A result of 10 means the number is never issued.
 */
export function nhsCheck(nhs: string): boolean {
  const d = asciiDigits(nhs);
  if (d.length !== 10) return false;
  let sum = 0;
  for (let i = 0; i < 9; i++) sum += d[i] * (10 - i);
  const check = (11 - (sum % 11)) % 11;
  return check !== 10 && check === d[9];
}

/** ABA routing number: weights 3, 7, 1 repeating; the sum is a multiple of 10. 000000000 passes the arithmetic and is rejected. */
export function abaCheck(routing: string): boolean {
  const d = asciiDigits(routing);
  if (d.length !== 9 || d.every(x => x === 0)) return false;
  const weights = [3, 7, 1, 3, 7, 1, 3, 7, 1];
  return weights.reduce((acc, w, i) => acc + w * d[i], 0) % 10 === 0;
}
