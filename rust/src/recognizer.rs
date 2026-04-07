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
        self.def.context_words.iter().any(|w| window.contains(&w.to_lowercase()))
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
