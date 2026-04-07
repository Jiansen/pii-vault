use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EntityType(pub String);

impl EntityType {
    pub fn new(name: &str) -> Self {
        Self(name.to_uppercase())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EntityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for EntityType {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecognizerResult {
    pub entity_type: EntityType,
    pub start: usize,
    pub end: usize,
    pub score: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recognizer_name: Option<String>,
}

impl RecognizerResult {
    pub fn text<'a>(&self, input: &'a str) -> &'a str {
        &input[self.start..self.end]
    }

    pub fn overlaps(&self, other: &RecognizerResult) -> bool {
        self.start < other.end && other.start < self.end
    }
}

pub const EMAIL_ADDRESS: &str = "EMAIL_ADDRESS";
pub const PHONE_NUMBER: &str = "PHONE_NUMBER";
pub const CREDIT_CARD: &str = "CREDIT_CARD";
pub const CRYPTO: &str = "CRYPTO";
pub const IP_ADDRESS: &str = "IP_ADDRESS";
pub const MAC_ADDRESS: &str = "MAC_ADDRESS";
pub const IBAN_CODE: &str = "IBAN_CODE";
pub const URL: &str = "URL";
pub const UUID: &str = "UUID";
pub const US_SSN: &str = "US_SSN";
pub const US_ITIN: &str = "US_ITIN";
pub const CN_ID_CARD: &str = "CN_ID_CARD";
pub const CN_PHONE: &str = "CN_PHONE";
pub const UK_NHS: &str = "UK_NHS";
pub const UK_NINO: &str = "UK_NINO";
