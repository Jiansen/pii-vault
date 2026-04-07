use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    pub token: String,
    pub original: String,
    pub category: String,
    #[serde(default)]
    pub context: String,
    pub created_at: String,
    pub last_used: String,
    pub use_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vault {
    pub version: u32,
    pub entries: Vec<VaultEntry>,
    #[serde(skip)]
    index: HashMap<String, usize>,
}

impl Default for Vault {
    fn default() -> Self {
        Self {
            version: 1,
            entries: Vec::new(),
            index: HashMap::new(),
        }
    }
}

impl Vault {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        let mut vault: Self = serde_json::from_str(json)?;
        vault.rebuild_index();
        Ok(vault)
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    fn rebuild_index(&mut self) {
        self.index.clear();
        for (i, entry) in self.entries.iter().enumerate() {
            let key = Self::make_key(&entry.category, &entry.original, &entry.context);
            self.index.insert(key, i);
        }
    }

    fn make_key(category: &str, original: &str, context: &str) -> String {
        format!("{}:{}:{}", category, original, context)
    }

    pub fn tokenize(&mut self, category: &str, original: &str) -> String {
        self.tokenize_ctx(category, original, "")
    }

    pub fn tokenize_ctx(&mut self, category: &str, original: &str, context: &str) -> String {
        let key = Self::make_key(category, original, context);
        let now = Self::utc_now();

        if let Some(&idx) = self.index.get(&key) {
            let entry = &mut self.entries[idx];
            entry.last_used = now;
            entry.use_count += 1;
            return entry.token.clone();
        }

        let hash_input = if context.is_empty() {
            format!("{}:{}", category, original)
        } else {
            format!("{}:{}:{}", category, original, context)
        };
        let mut token = Self::stable_token(category, &hash_input);

        let mut attempt = 0u32;
        while self.entries.iter().any(|e| e.token == token && (e.original != original || e.context != context)) {
            attempt += 1;
            let input = format!("{}:{}:{}:{}", category, original, context, attempt);
            token = Self::stable_token(category, &input);
        }

        let entry = VaultEntry {
            token: token.clone(),
            original: original.to_string(),
            category: category.to_string(),
            context: context.to_string(),
            created_at: now.clone(),
            last_used: now,
            use_count: 1,
        };
        let idx = self.entries.len();
        self.entries.push(entry);
        self.index.insert(key, idx);

        token
    }

    pub fn detokenize(&self, text: &str) -> String {
        let mut result = text.to_string();
        let mut sorted: Vec<&VaultEntry> = self.entries.iter().collect();
        sorted.sort_by(|a, b| b.token.len().cmp(&a.token.len()));
        for entry in sorted {
            result = result.replace(&entry.token, &entry.original);
        }
        result
    }

    pub fn lookup_token(&self, token: &str) -> Option<&VaultEntry> {
        self.entries.iter().find(|e| e.token == token)
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    fn stable_token(category: &str, input: &str) -> String {
        let hash = input.bytes().fold(0u32, |h, b| h.wrapping_mul(31).wrapping_add(b as u32));
        let short = format!("{:04x}", hash & 0xFFFF);
        format!("[{}:{}]", category.to_uppercase(), short)
    }

    fn utc_now() -> String {
        "1970-01-01T00:00:00Z".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tokenize_deterministic() {
        let mut vault = Vault::new();
        let t1 = vault.tokenize("email_address", "test@example.com");
        let t2 = vault.tokenize("email_address", "test@example.com");
        assert_eq!(t1, t2);
        assert_eq!(vault.entry_count(), 1);
        assert_eq!(vault.entries[0].use_count, 2);
    }

    #[test]
    fn test_tokenize_different_originals() {
        let mut vault = Vault::new();
        let t1 = vault.tokenize("email_address", "alice@example.com");
        let t2 = vault.tokenize("email_address", "bob@example.com");
        assert_ne!(t1, t2);
        assert_eq!(vault.entry_count(), 2);
    }

    #[test]
    fn test_tokenize_with_context() {
        let mut vault = Vault::new();
        let t1 = vault.tokenize_ctx("person", "Zhang San", "customer");
        let t2 = vault.tokenize_ctx("person", "Zhang San", "colleague");
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_detokenize() {
        let mut vault = Vault::new();
        let token = vault.tokenize("email_address", "test@example.com");
        let text = format!("Contact {}", token);
        let restored = vault.detokenize(&text);
        assert_eq!(restored, "Contact test@example.com");
    }

    #[test]
    fn test_roundtrip_json() {
        let mut vault = Vault::new();
        vault.tokenize("email_address", "test@example.com");
        vault.tokenize("phone_number", "555-1234");

        let json = vault.to_json().unwrap();
        let loaded = Vault::from_json(&json).unwrap();

        assert_eq!(loaded.entry_count(), 2);
        assert_eq!(loaded.entries[0].original, "test@example.com");
    }

    #[test]
    fn test_token_format() {
        let mut vault = Vault::new();
        let token = vault.tokenize("email_address", "test@example.com");
        assert!(token.starts_with("[EMAIL_ADDRESS:"));
        assert!(token.ends_with(']'));
    }

    #[test]
    fn test_lookup_token() {
        let mut vault = Vault::new();
        let token = vault.tokenize("email_address", "test@example.com");
        let entry = vault.lookup_token(&token).unwrap();
        assert_eq!(entry.original, "test@example.com");
    }
}
