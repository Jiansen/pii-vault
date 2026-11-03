use crate::entity::{EntityType, RecognizerResult};
use regex::Regex;
use serde::{Deserialize, Serialize};

pub trait Recognizer: Send + Sync {
    fn name(&self) -> &str;
    fn supported_entities(&self) -> &[EntityType];
    fn analyze(&self, text: &str, entities: &[EntityType]) -> Vec<RecognizerResult>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternDef {
    pub name: String,
    pub regex: String,
    pub score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecognizerDef {
    pub name: String,
    pub entity_type: String,
    pub version: String,
    pub patterns: Vec<PatternDef>,
    #[serde(default)]
    pub context_words: Vec<String>,
    #[serde(default)]
    pub context_score_boost: f64,
    #[serde(default)]
    pub deny_list: Vec<String>,
    #[serde(default)]
    pub validators: Vec<String>,
    pub supported_languages: Option<Vec<String>>,
}

pub struct RegexRecognizer {
    def: RecognizerDef,
    compiled: Vec<(String, Regex, f64)>,
    entity: EntityType,
}

/// Scripts written without spaces between words: Thai, Lao, Myanmar, Khmer, Hangul (whose
/// particles join the word before), Japanese kana and CJK ideographs. A context word in
/// one matches anywhere, as there is no word edge to look for.
fn is_unspaced_script(c: char) -> bool {
    matches!(c as u32,
        0x0E00..=0x0EFF | 0x1000..=0x109F | 0x1100..=0x11FF | 0x1780..=0x17FF
        | 0x3040..=0x30FF | 0x3130..=0x318F | 0x31F0..=0x31FF | 0x3400..=0x4DBF
        | 0x4E00..=0x9FFF | 0xAC00..=0xD7AF | 0xF900..=0xFAFF | 0xFF66..=0xFF9F
        | 0x20000..=0x3FFFF)
}

/// Letters and digits make up a word; spaces, punctuation, `_` and `-` end one.
fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() && !is_unspaced_script(c)
}

/// Whether `word` occurs in `window` as a whole word: not inside a longer one, so "tel"
/// is not found in "hotel" nor "id" in "valid". An English plural counts as the word ("calls",
/// "accounts"), and an edge of the window as a word edge.
pub(crate) fn contains_word(window: &str, word: &str) -> bool {
    if word.is_empty() {
        return true;
    }
    let check_start = word.chars().next().map_or(false, is_word_char);
    let check_end = word.chars().next_back().map_or(false, is_word_char);
    let plural = word.chars().next_back().map_or(false, |c| c.is_ascii_alphabetic());
    let step = word.chars().next().map_or(1, char::len_utf8);
    let mut from = 0;
    while let Some(found) = window[from..].find(word) {
        let start = from + found;
        let end = start + word.len();
        let starts_word = !check_start || !window[..start].chars().next_back().map_or(false, is_word_char);
        let end = if plural && window[end..].starts_with('s') { end + 1 } else { end };
        let ends_word = !check_end || !window[end..].chars().next().map_or(false, is_word_char);
        if starts_word && ends_word {
            return true;
        }
        from = start + step;
    }
    false
}

impl RegexRecognizer {
    pub fn from_def(def: RecognizerDef) -> Result<Self, regex::Error> {
        let mut compiled = Vec::new();
        for p in &def.patterns {
            let re = Regex::new(&p.regex)?;
            compiled.push((p.name.clone(), re, p.score));
        }
        let entity = EntityType::new(&def.entity_type);
        Ok(Self { def, compiled, entity })
    }

    pub fn from_json(json: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let def: RecognizerDef = serde_json::from_str(json)?;
        Ok(Self::from_def(def)?)
    }

    fn has_context(&self, text: &str, start: usize, end: usize) -> bool {
        if self.def.context_words.is_empty() {
            return false;
        }
        let window_start = start.saturating_sub(100);
        let window_end = (end + 100).min(text.len());
        let window = &text[window_start..window_end].to_lowercase();
        self.def.context_words.iter().any(|w| contains_word(window, &w.to_lowercase()))
    }

    fn is_denied(&self, matched: &str) -> bool {
        self.def.deny_list.iter().any(|d| matched == d)
    }

    fn validate(&self, matched: &str) -> bool {
        for v in &self.def.validators {
            match v.as_str() {
                "luhn" => { if !luhn_check(matched) { return false; } }
                "cn_id_checksum" => { if !cn_id_check(matched) { return false; } }
                "iban" => { if !iban_check(matched) { return false; } }
                "de_tax_id" => { if !de_tax_id_check(matched) { return false; } }
                "au_abn" => { if !au_abn_check(matched) { return false; } }
                "au_tfn" => { if !au_tfn_check(matched) { return false; } }
                "au_acn" => { if !au_acn_check(matched) { return false; } }
                "au_medicare" => { if !au_medicare_check(matched) { return false; } }
                "uk_driving_licence" => { if !uk_driving_licence_check(matched) { return false; } }
                "br_cnpj" => { if !br_cnpj_check(matched) { return false; } }
                "nl_bsn" => { if !nl_bsn_check(matched) { return false; } }
                "cpf_checksum" => { if !cpf_check(matched) { return false; } }
                "pesel_checksum" => { if !pesel_check(matched) { return false; } }
                "verhoeff" => { if !verhoeff_check(matched) { return false; } }
                "nhs_checksum" => { if !nhs_check(matched) { return false; } }
                "aba_checksum" => { if !aba_check(matched) { return false; } }
                _ => {}
            }
        }
        true
    }
}

impl Recognizer for RegexRecognizer {
    fn name(&self) -> &str {
        &self.def.name
    }

    fn supported_entities(&self) -> &[EntityType] {
        std::slice::from_ref(&self.entity)
    }

    fn analyze(&self, text: &str, entities: &[EntityType]) -> Vec<RecognizerResult> {
        if !entities.is_empty() && !entities.contains(&self.entity) {
            return Vec::new();
        }

        let mut results = Vec::new();
        for (pat_name, re, base_score) in &self.compiled {
            for m in re.find_iter(text) {
                let matched = m.as_str();

                if self.is_denied(matched) {
                    continue;
                }

                if !self.validate(matched) {
                    continue;
                }

                let mut score = *base_score;
                if self.has_context(text, m.start(), m.end()) {
                    score = (score + self.def.context_score_boost).min(1.0);
                }

                results.push(RecognizerResult {
                    entity_type: self.entity.clone(),
                    start: m.start(),
                    end: m.end(),
                    score,
                    recognizer_name: Some(pat_name.clone()),
                });
            }
        }
        results
    }
}

fn luhn_check(number: &str) -> bool {
    let digits: Vec<u32> = number
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() < 2 {
        return false;
    }
    let mut sum = 0u32;
    let mut double = false;
    for &d in digits.iter().rev() {
        let mut val = d;
        if double {
            val *= 2;
            if val > 9 {
                val -= 9;
            }
        }
        sum += val;
        double = !double;
    }
    sum % 10 == 0
}

fn cn_id_check(id: &str) -> bool {
    if id.len() != 18 {
        return false;
    }
    let weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
    let check_chars = ['1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2'];
    let chars: Vec<char> = id.chars().collect();
    let mut sum = 0usize;
    for i in 0..17 {
        let d = match chars[i].to_digit(10) {
            Some(d) => d as usize,
            None => return false,
        };
        sum += d * weights[i];
    }
    let expected = check_chars[sum % 11];
    chars[17].to_ascii_uppercase() == expected
}

fn iban_check(iban: &str) -> bool {
    let cleaned: String = iban.chars().filter(|c| !c.is_whitespace() && *c != '-').collect();
    if cleaned.len() < 5 || cleaned.len() > 34 {
        return false;
    }
    let rearranged = format!("{}{}", &cleaned[4..], &cleaned[..4]);
    let numeric: String = rearranged.chars().map(|c| {
        if c.is_ascii_digit() { c.to_string() }
        else { ((c as u32 - 'A' as u32) + 10).to_string() }
    }).collect();
    let mut remainder = 0u64;
    for chunk in numeric.as_bytes().chunks(7) {
        let s = format!("{}{}", remainder, std::str::from_utf8(chunk).unwrap_or(""));
        remainder = s.parse::<u64>().unwrap_or(0) % 97;
    }
    remainder == 1
}

fn de_tax_id_check(id: &str) -> bool {
    let digits: Vec<u32> = id.chars().filter(|c| c.is_ascii_digit()).filter_map(|c| c.to_digit(10)).collect();
    if digits.len() != 11 || digits[0] == 0 {
        return false;
    }
    let first10: std::collections::HashSet<u32> = digits[..10].iter().copied().collect();
    if first10.len() == 1 {
        return false;
    }
    let mut product = 10u32;
    for i in 0..10 {
        let total = (digits[i] + product) % 10;
        let total = if total == 0 { 10 } else { total };
        product = (total * 2) % 11;
    }
    let check = if 11 - product == 10 { 0 } else { 11 - product };
    check == digits[10]
}

fn au_abn_check(abn: &str) -> bool {
    let digits: Vec<i64> = abn.chars().filter(|c| c.is_ascii_digit()).filter_map(|c| c.to_digit(10).map(|d| d as i64)).collect();
    if digits.len() != 11 {
        return false;
    }
    let weights: [i64; 11] = [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19];
    let mut d = digits.clone();
    d[0] -= 1;
    let sum: i64 = d.iter().zip(weights.iter()).map(|(a, b)| a * b).sum();
    sum % 89 == 0
}

fn au_tfn_check(tfn: &str) -> bool {
    let digits: Vec<u32> = tfn.chars().filter(|c| c.is_ascii_digit()).filter_map(|c| c.to_digit(10)).collect();
    if digits.len() != 9 {
        return false;
    }
    let weights: [u32; 9] = [1, 4, 3, 7, 5, 8, 6, 9, 10];
    let sum: u32 = digits.iter().zip(weights.iter()).map(|(a, b)| a * b).sum();
    sum % 11 == 0
}

fn au_acn_check(acn: &str) -> bool {
    let digits: Vec<u32> = acn.chars().filter(|c| c.is_ascii_digit()).filter_map(|c| c.to_digit(10)).collect();
    if digits.len() != 9 {
        return false;
    }
    let weights: [u32; 8] = [8, 7, 6, 5, 4, 3, 2, 1];
    let sum: u32 = digits[..8].iter().zip(weights.iter()).map(|(a, b)| a * b).sum();
    let check = (10 - (sum % 10)) % 10;
    check == digits[8]
}

fn au_medicare_check(medicare: &str) -> bool {
    let digits: Vec<u32> = medicare.chars().filter(|c| c.is_ascii_digit()).filter_map(|c| c.to_digit(10)).collect();
    if digits.len() < 10 || digits.len() > 11 {
        return false;
    }
    if digits[0] < 2 || digits[0] > 6 {
        return false;
    }
    let weights: [u32; 8] = [1, 3, 7, 9, 1, 3, 7, 9];
    let sum: u32 = digits[..8].iter().zip(weights.iter()).map(|(a, b)| a * b).sum();
    sum % 10 == digits[8]
}

fn uk_driving_licence_check(licence: &str) -> bool {
    let text = licence.to_uppercase();
    if text.len() != 16 {
        return false;
    }
    let surname: &str = &text[..5];
    // All 9s = no valid surname
    if surname == "99999" {
        return false;
    }
    // Surname must be letters followed by optional 9-padding (no 9 before a letter)
    let chars: Vec<char> = surname.chars().collect();
    let mut seen_nine = false;
    for &c in &chars {
        if c == '9' {
            seen_nine = true;
        } else if seen_nine {
            // Letter after 9 = invalid padding
            return false;
        }
    }
    // Must start with at least one letter
    !chars[0].is_ascii_digit()
}

/// CNPJ: 12 base characters (0-9, or A-Z since the July 2026 alphanumeric format) and two
/// numeric mod-11 check digits. Each character is worth its ASCII code minus 48, so digits
/// keep their value and 'A' is 17; weights run 2..=9 from the right, repeating.
fn br_cnpj_check(cnpj: &str) -> bool {
    let chars: Vec<u8> = cnpj.bytes().filter(|b| b.is_ascii_alphanumeric()).map(|b| b.to_ascii_uppercase()).collect();
    if chars.len() != 14 || !chars[12..].iter().all(|b| b.is_ascii_digit()) {
        return false;
    }
    // 00.000.000/0000-00, 11.111.111/1111-11 and so on pass the arithmetic but are not issued.
    if chars.iter().all(|&b| b == chars[0]) {
        return false;
    }
    let values: Vec<u32> = chars.iter().map(|&b| (b - b'0') as u32).collect();
    let check_digit = |n: usize| {
        let sum: u32 = values[..n].iter().rev().enumerate().map(|(i, v)| v * (2 + (i as u32 % 8))).sum();
        if sum % 11 < 2 { 0 } else { 11 - sum % 11 }
    };
    check_digit(12) == values[12] && check_digit(13) == values[13]
}

/// BSN 11-proof: 9*d1 + 8*d2 + ... + 2*d8 - d9 must be a positive multiple of 11.
fn nl_bsn_check(bsn: &str) -> bool {
    let digits: Vec<i32> = bsn.chars().filter(|c| c.is_ascii_digit()).filter_map(|c| c.to_digit(10).map(|d| d as i32)).collect();
    if digits.len() != 9 {
        return false;
    }
    let sum: i32 = digits[..8].iter().enumerate().map(|(i, d)| d * (9 - i as i32)).sum::<i32>() - digits[8];
    sum > 0 && sum % 11 == 0
}

fn ascii_digits(s: &str) -> Vec<u32> {
    s.chars().filter_map(|c| if c.is_ascii_digit() { c.to_digit(10) } else { None }).collect()
}

/// CPF: two mod-11 check digits over weights 10..=2 and 11..=2. Repeated-digit numbers
/// (111.111.111-11 and so on) pass the arithmetic but are not issued.
fn cpf_check(cpf: &str) -> bool {
    let d = ascii_digits(cpf);
    if d.len() != 11 || d.iter().all(|&x| x == d[0]) {
        return false;
    }
    [9, 10].iter().all(|&n| {
        let sum: u32 = d[..n].iter().enumerate().map(|(i, x)| x * (n as u32 + 1 - i as u32)).sum();
        (sum * 10 % 11) % 10 == d[n]
    })
}

/// PESEL: weights 1, 3, 7, 9 repeating over the first 10 digits; the 11th makes the sum a
/// multiple of 10.
fn pesel_check(pesel: &str) -> bool {
    let d = ascii_digits(pesel);
    if d.len() != 11 {
        return false;
    }
    let weights = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3];
    let sum: u32 = d[..10].iter().zip(weights.iter()).map(|(a, b)| a * b).sum();
    (10 - sum % 10) % 10 == d[10]
}

const VERHOEFF_D: [[u8; 10]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];
const VERHOEFF_P: [[u8; 10]; 8] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

/// Verhoeff (dihedral group D5), as used by Aadhaar: the number including its check digit
/// must reduce to 0.
fn verhoeff_check(number: &str) -> bool {
    let d = ascii_digits(number);
    if d.is_empty() {
        return false;
    }
    let mut c = 0usize;
    for (i, &x) in d.iter().rev().enumerate() {
        c = VERHOEFF_D[c][VERHOEFF_P[i % 8][x as usize] as usize] as usize;
    }
    c == 0
}

/// NHS: weights 10..=2 over the first 9 digits; the check digit is 11 minus the sum mod 11,
/// with 11 meaning 0. A result of 10 means the number is never issued.
fn nhs_check(nhs: &str) -> bool {
    let d = ascii_digits(nhs);
    if d.len() != 10 {
        return false;
    }
    let sum: u32 = d[..9].iter().enumerate().map(|(i, x)| x * (10 - i as u32)).sum();
    let check = (11 - sum % 11) % 11;
    check != 10 && check == d[9]
}

/// ABA routing number: weights 3, 7, 1 repeating; the sum is a multiple of 10. 000000000
/// passes the arithmetic and is rejected.
fn aba_check(routing: &str) -> bool {
    let d = ascii_digits(routing);
    if d.len() != 9 || d.iter().all(|&x| x == 0) {
        return false;
    }
    let weights = [3, 7, 1, 3, 7, 1, 3, 7, 1];
    d.iter().zip(weights.iter()).map(|(a, b)| a * b).sum::<u32>() % 10 == 0
}

pub fn load_recognizers_from_dir(dir: &std::path::Path) -> Vec<Box<dyn Recognizer>> {
    let mut recognizers: Vec<Box<dyn Recognizer>> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map_or(false, |e| e == "json") {
                if let Ok(json) = std::fs::read_to_string(&path) {
                    match RegexRecognizer::from_json(&json) {
                        Ok(r) => recognizers.push(Box::new(r)),
                        Err(e) => eprintln!("Failed to load {:?}: {}", path, e),
                    }
                }
            }
        }
    }
    recognizers
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shared with the TypeScript and Swift tests: the same cases, the same answers.
    #[test]
    fn test_context_words_match_whole_words() {
        let cases = [
            ("tel: 555 1234", "tel", true),
            ("hotel 555 1234", "tel", false),
            ("the hotel tel line", "tel", true),
            ("valid until", "id", false),
            ("id: 42", "id", true),
            ("aws_secret_access_key=", "secret", true),
            ("e-mail me", "mail", true),
            ("accounts", "account", true),
            ("calls", "call", true),
            ("callsign", "call", false),
            ("ids", "id", true),
            ("联系电话：", "电话", true),
            ("phone号码", "phone", true),
            ("주민등록번호는", "주민등록번호", true),
            ("bass#1", "ss#", false),
            ("ss#123", "ss#", true),
            ("\u{1D400}tel", "tel", false),
            ("tel\u{1D400}", "tel", false),
            ("anything", "", true),
        ];
        for (window, word, expected) in cases {
            assert_eq!(contains_word(window, word), expected, "{word:?} in {window:?}");
        }
    }

    #[test]
    fn test_context_inside_a_longer_word_does_not_boost() {
        let rec = RegexRecognizer::from_json(r#"{
            "name": "phone", "entity_type": "PHONE_NUMBER", "version": "1.0.0",
            "patterns": [{"name": "us", "regex": "\\d{3}-\\d{4}", "score": 0.4}],
            "context_words": ["tel"], "context_score_boost": 0.4
        }"#).unwrap();
        let score = |text: &str| rec.analyze(text, &[])[0].score;
        assert!((score("Tel: 555-1234") - 0.8).abs() < 1e-9);
        assert!((score("Hotel room 555-1234") - 0.4).abs() < 1e-9);
    }

    #[test]
    fn test_luhn_valid() {
        assert!(luhn_check("4532015112830366"));
        assert!(luhn_check("4111111111111111"));
    }

    #[test]
    fn test_luhn_invalid() {
        assert!(!luhn_check("1234567890123456"));
    }

    #[test]
    fn test_cn_id_valid() {
        assert!(cn_id_check("11010519491231002X"));
    }

    #[test]
    fn test_cn_id_invalid() {
        assert!(!cn_id_check("110105194912310020"));
    }

    /// Shared with the TypeScript and Swift tests.
    #[test]
    fn test_br_cnpj() {
        assert!(br_cnpj_check("11.222.333/0001-81"));
        assert!(br_cnpj_check("11222333000181"));
        assert!(br_cnpj_check("04.252.011/0001-10"));
        // Alphanumeric example published by the Receita Federal
        assert!(br_cnpj_check("12.ABC.345/01DE-35"));
        assert!(!br_cnpj_check("12.ABC.345/01DE-36"));
        assert!(!br_cnpj_check("11.222.333/0001-82"));
        assert!(!br_cnpj_check("11.222.333/0001-91"));
        assert!(!br_cnpj_check("00.000.000/0000-00"));
        assert!(!br_cnpj_check("1122233300018"));
        assert!(!br_cnpj_check("12.ABC.345/01DE-3A"));
    }

    /// Shared with the TypeScript and Swift tests.
    #[test]
    fn test_cpf() {
        assert!(cpf_check("123.456.789-09"));
        assert!(cpf_check("52998224725"));
        assert!(!cpf_check("123.456.789-08"));
        assert!(!cpf_check("123.456.789-19"));
        assert!(!cpf_check("111.111.111-11"));
        assert!(!cpf_check("1234567890"));
    }

    /// Shared with the TypeScript and Swift tests.
    #[test]
    fn test_pesel() {
        assert!(pesel_check("44051401458"));
        assert!(pesel_check("02070803628"));
        assert!(!pesel_check("44051401459"));
        assert!(!pesel_check("4405140145"));
    }

    /// Shared with the TypeScript and Swift tests.
    #[test]
    fn test_verhoeff() {
        assert!(verhoeff_check("2363"));
        assert!(!verhoeff_check("2364"));
        assert!(verhoeff_check("4991 1866 5246"));
        assert!(verhoeff_check("2234 5678 9018"));
        assert!(!verhoeff_check("2234 5678 9012"));
        assert!(!verhoeff_check(""));
    }

    /// Shared with the TypeScript and Swift tests.
    #[test]
    fn test_nhs() {
        assert!(nhs_check("943 476 5919"));
        assert!(nhs_check("4010232137"));
        assert!(!nhs_check("943 476 5918"));
        assert!(!nhs_check("401 023 2138"));
        assert!(!nhs_check("123456789"));
    }

    /// Shared with the TypeScript and Swift tests.
    #[test]
    fn test_aba() {
        assert!(aba_check("021000021"));
        assert!(aba_check("011000015"));
        assert!(!aba_check("021000022"));
        assert!(!aba_check("000000000"));
        assert!(!aba_check("02100002"));
    }

    /// Shared with the TypeScript and Swift tests.
    #[test]
    fn test_nl_bsn() {
        assert!(nl_bsn_check("111222333"));
        assert!(nl_bsn_check("123456782"));
        assert!(nl_bsn_check("1234.56.782"));
        assert!(!nl_bsn_check("123456789"));
        assert!(!nl_bsn_check("000000000"));
        assert!(!nl_bsn_check("12345678"));
    }

    #[test]
    fn test_regex_recognizer_email() {
        let json = r#"{
            "name": "email_recognizer",
            "entity_type": "EMAIL_ADDRESS",
            "version": "1.0.0",
            "patterns": [{"name": "email", "regex": "[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}", "score": 0.5}],
            "context_words": ["email"],
            "context_score_boost": 0.4
        }"#;
        let rec = RegexRecognizer::from_json(json).unwrap();
        let results = rec.analyze("Contact me at test@example.com please", &[]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].entity_type.as_str(), "EMAIL_ADDRESS");
        assert_eq!(&"Contact me at test@example.com please"[results[0].start..results[0].end], "test@example.com");
    }

    #[test]
    fn test_context_boost() {
        let json = r#"{
            "name": "email_recognizer",
            "entity_type": "EMAIL_ADDRESS",
            "version": "1.0.0",
            "patterns": [{"name": "email", "regex": "[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}", "score": 0.5}],
            "context_words": ["email"],
            "context_score_boost": 0.4
        }"#;
        let rec = RegexRecognizer::from_json(json).unwrap();

        let with_ctx = rec.analyze("My email is test@example.com", &[]);
        let without_ctx = rec.analyze("test@example.com", &[]);

        assert!(with_ctx[0].score > without_ctx[0].score);
    }

    #[test]
    fn test_deny_list() {
        let json = r#"{
            "name": "ip_recognizer",
            "entity_type": "IP_ADDRESS",
            "version": "1.0.0",
            "patterns": [{"name": "ipv4", "regex": "\\b(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\b", "score": 0.5}],
            "deny_list": ["0.0.0.0", "127.0.0.1"],
            "context_words": []
        }"#;
        let rec = RegexRecognizer::from_json(json).unwrap();
        let results = rec.analyze("Server at 127.0.0.1 and 192.168.1.1", &[]);
        assert_eq!(results.len(), 1);
        assert_eq!(&"Server at 127.0.0.1 and 192.168.1.1"[results[0].start..results[0].end], "192.168.1.1");
    }
}
