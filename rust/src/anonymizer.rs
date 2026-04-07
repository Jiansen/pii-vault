use crate::entity::RecognizerResult;
use crate::vault::Vault;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Operator {
    Replace { new_value: String },
    Mask { masking_char: char, chars_to_mask: usize, from_end: bool },
    Hash { hash_type: HashType },
    Redact,
    Vault,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HashType {
    Fnv,
}

impl Default for Operator {
    fn default() -> Self {
        Operator::Replace {
            new_value: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymizedItem {
    pub entity_type: String,
    pub start: usize,
    pub end: usize,
    pub original: String,
    pub replacement: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymizedResult {
    pub text: String,
    pub items: Vec<AnonymizedItem>,
}

pub struct Anonymizer;

impl Anonymizer {
    pub fn anonymize(
        text: &str,
        entities: &[RecognizerResult],
        operators: &std::collections::HashMap<String, Operator>,
        default_operator: &Operator,
        mut vault: Option<&mut Vault>,
    ) -> AnonymizedResult {
        let mut sorted = entities.to_vec();
        sorted.sort_by(|a, b| b.start.cmp(&a.start));

        let mut result = text.to_string();
        let mut items = Vec::new();

        for entity in &sorted {
            let original = &text[entity.start..entity.end];
            let op = operators
                .get(entity.entity_type.as_str())
                .unwrap_or(default_operator);

            let replacement = match op {
                Operator::Replace { new_value } => {
                    if new_value.is_empty() {
                        format!("<{}>", entity.entity_type)
                    } else {
                        new_value.clone()
                    }
                }
                Operator::Mask { masking_char, chars_to_mask, from_end } => {
                    mask_text(original, *masking_char, *chars_to_mask, *from_end)
                }
                Operator::Hash { hash_type } => {
                    hash_text(original, hash_type)
                }
                Operator::Redact => String::new(),
                Operator::Vault => {
                    if let Some(ref mut v) = { vault.as_deref_mut() } {
                        v.tokenize(entity.entity_type.as_str(), original)
                    } else {
                        format!("<{}>", entity.entity_type)
                    }
                }
            };

            items.push(AnonymizedItem {
                entity_type: entity.entity_type.to_string(),
                start: entity.start,
                end: entity.end,
                original: original.to_string(),
                replacement: replacement.clone(),
            });

            result.replace_range(entity.start..entity.end, &replacement);
        }

        items.reverse();

        AnonymizedResult { text: result, items }
    }
}

fn mask_text(text: &str, mask_char: char, chars_to_mask: usize, from_end: bool) -> String {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let to_mask = chars_to_mask.min(n);
    let mut result = chars.clone();

    if from_end {
        for c in result.iter_mut().rev().take(to_mask) {
            *c = mask_char;
        }
    } else {
        for c in result.iter_mut().take(to_mask) {
            *c = mask_char;
        }
    }
    result.into_iter().collect()
}

fn hash_text(text: &str, _hash_type: &HashType) -> String {
    let hash = text.bytes().fold(2166136261u32, |h, b| {
        (h ^ b as u32).wrapping_mul(16777619)
    });
    format!("{:08x}", hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::EntityType;
    use std::collections::HashMap;

    fn make_entity(entity_type: &str, start: usize, end: usize) -> RecognizerResult {
        RecognizerResult {
            entity_type: EntityType::new(entity_type),
            start,
            end,
            score: 0.9,
            recognizer_name: None,
        }
    }

    #[test]
    fn test_anonymize_replace_default() {
        let text = "Email me at test@example.com";
        let entities = vec![make_entity("EMAIL_ADDRESS", 12, 28)];
        let result = Anonymizer::anonymize(text, &entities, &HashMap::new(), &Operator::default(), None);
        assert_eq!(result.text, "Email me at <EMAIL_ADDRESS>");
        assert_eq!(result.items.len(), 1);
    }

    #[test]
    fn test_anonymize_replace_custom() {
        let text = "SSN: 123-45-6789";
        let entities = vec![make_entity("US_SSN", 5, 16)];
        let mut ops = HashMap::new();
        ops.insert("US_SSN".to_string(), Operator::Replace { new_value: "[REDACTED]".to_string() });
        let result = Anonymizer::anonymize(text, &entities, &ops, &Operator::default(), None);
        assert_eq!(result.text, "SSN: [REDACTED]");
    }

    #[test]
    fn test_anonymize_mask() {
        let text = "Card: 4111111111111111";
        let entities = vec![make_entity("CREDIT_CARD", 6, 22)];
        let mut ops = HashMap::new();
        ops.insert("CREDIT_CARD".to_string(), Operator::Mask {
            masking_char: '*',
            chars_to_mask: 12,
            from_end: false,
        });
        let result = Anonymizer::anonymize(text, &entities, &ops, &Operator::default(), None);
        assert_eq!(result.text, "Card: ************1111");
    }

    #[test]
    fn test_anonymize_hash() {
        let text = "Email: test@example.com";
        let entities = vec![make_entity("EMAIL_ADDRESS", 7, 23)];
        let mut ops = HashMap::new();
        ops.insert("EMAIL_ADDRESS".to_string(), Operator::Hash { hash_type: HashType::Fnv });
        let result = Anonymizer::anonymize(text, &entities, &ops, &Operator::default(), None);
        assert!(result.text.starts_with("Email: "));
        assert_ne!(result.text, text);
    }

    #[test]
    fn test_anonymize_redact() {
        let text = "My phone is 555-123-4567";
        let entities = vec![make_entity("PHONE_NUMBER", 12, 24)];
        let mut ops = HashMap::new();
        ops.insert("PHONE_NUMBER".to_string(), Operator::Redact);
        let result = Anonymizer::anonymize(text, &entities, &ops, &Operator::default(), None);
        assert_eq!(result.text, "My phone is ");
    }

    #[test]
    fn test_anonymize_vault() {
        let text = "Email: test@example.com";
        let entities = vec![make_entity("EMAIL_ADDRESS", 7, 23)];
        let mut ops = HashMap::new();
        ops.insert("EMAIL_ADDRESS".to_string(), Operator::Vault);
        let mut vault = crate::vault::Vault::new();
        let result = Anonymizer::anonymize(text, &entities, &ops, &Operator::default(), Some(&mut vault));
        assert!(result.text.contains("[EMAIL_ADDRESS:"));
        assert_eq!(vault.entry_count(), 1);

        let restored = vault.detokenize(&result.text);
        assert_eq!(restored, text);
    }

    #[test]
    fn test_anonymize_multiple_entities() {
        let text = "alice@test.com called 555-123-4567";
        let entities = vec![
            make_entity("EMAIL_ADDRESS", 0, 14),
            make_entity("PHONE_NUMBER", 22, 34),
        ];
        let result = Anonymizer::anonymize(text, &entities, &HashMap::new(), &Operator::default(), None);
        assert_eq!(result.text, "<EMAIL_ADDRESS> called <PHONE_NUMBER>");
    }
}
