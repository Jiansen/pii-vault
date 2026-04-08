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
    #[serde(default)]
    pub salt: String,
    pub entries: Vec<VaultEntry>,
    #[serde(skip)]
    index: HashMap<String, usize>,
}

impl Default for Vault {
    fn default() -> Self {
        Self {
            version: 2,
            salt: Self::generate_salt(),
            entries: Vec::new(),
            index: HashMap::new(),
        }
    }
}

impl Vault {
    pub fn new() -> Self {
        Self::default()
    }

    fn generate_salt() -> String {
        let mut bytes = [0u8; 16];
        getrandom::getrandom(&mut bytes).unwrap_or_else(|_| {
            // Fallback: use system time as entropy source
            let t = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            for (i, b) in bytes.iter_mut().enumerate() {
                *b = ((t >> (i * 8)) & 0xFF) as u8;
            }
        });
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        let mut vault: Self = serde_json::from_str(json)?;
        if vault.version < 2 || vault.salt.is_empty() {
            // v1 vault: generate a new salt; old entries retain their original tokens
            vault.salt = Self::generate_salt();
            vault.version = 2;
        }
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
            format!("{}:{}:{}", self.salt, category, original)
        } else {
            format!("{}:{}:{}:{}", self.salt, category, original, context)
        };
        let mut token = Self::stable_token(category, &hash_input);

        let mut attempt = 0u32;
        while self.entries.iter().any(|e| e.token == token && (e.original != original || e.context != context)) {
            attempt += 1;
            let input = format!("{}:{}:{}:{}:{}", self.salt, category, original, context, attempt);
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
        // FNV-1a 32-bit hash for better distribution
        let hash = input.bytes().fold(0x811c9dc5u32, |h, b| {
            (h ^ b as u32).wrapping_mul(0x01000193)
        });
        format!("[{}:{:08x}]", category.to_uppercase(), hash)
    }

    fn utc_now() -> String {
        let d = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let secs = d.as_secs();
        let days = secs / 86400;
        let time_secs = secs % 86400;
        let h = time_secs / 3600;
        let m = (time_secs % 3600) / 60;
        let s = time_secs % 60;

        // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm)
        let z = days as i64 + 719468;
        let era = z.div_euclid(146097);
        let doe = z.rem_euclid(146097) as u64;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        let y = yoe as i64 + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let mon = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = if mon <= 2 { y + 1 } else { y };

        format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mon, d, h, m, s)
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
    fn test_token_format_8hex() {
        let mut vault = Vault::new();
        let token = vault.tokenize("email_address", "test@example.com");
        assert!(token.starts_with("[EMAIL_ADDRESS:"));
        assert!(token.ends_with(']'));
        let hex_part = &token["[EMAIL_ADDRESS:".len()..token.len() - 1];
        assert_eq!(hex_part.len(), 8, "token should have 8 hex chars");
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_lookup_token() {
        let mut vault = Vault::new();
        let token = vault.tokenize("email_address", "test@example.com");
        let entry = vault.lookup_token(&token).unwrap();
        assert_eq!(entry.original, "test@example.com");
    }

    #[test]
    fn test_different_vaults_different_tokens() {
        let mut v1 = Vault::new();
        let mut v2 = Vault::new();
        let t1 = v1.tokenize("person", "Zhang Wei");
        let t2 = v2.tokenize("person", "Zhang Wei");
        assert_ne!(t1, t2, "different vaults should produce different tokens (salt isolation)");
    }

    #[test]
    fn test_json_roundtrip_preserves_salt() {
        let mut vault = Vault::new();
        let token = vault.tokenize("person", "Alice");
        let json = vault.to_json().unwrap();
        let mut loaded = Vault::from_json(&json).unwrap();
        let token2 = loaded.tokenize("person", "Alice");
        assert_eq!(token, token2, "loaded vault should produce same token for same input");
        assert_eq!(loaded.entry_count(), 1);
    }

    #[test]
    fn test_v1_vault_backward_compat() {
        let v1_json = r#"{
            "version": 1,
            "entries": [{
                "token": "[PERSON:e702]",
                "original": "Zhang Wei",
                "category": "person",
                "context": "",
                "created_at": "2026-04-01T00:00:00Z",
                "last_used": "2026-04-01T00:00:00Z",
                "use_count": 1
            }]
        }"#;
        let vault = Vault::from_json(v1_json).unwrap();
        assert_eq!(vault.entry_count(), 1);
        let entry = vault.lookup_token("[PERSON:e702]").unwrap();
        assert_eq!(entry.original, "Zhang Wei");
        let restored = vault.detokenize("Hello [PERSON:e702]");
        assert_eq!(restored, "Hello Zhang Wei");
    }

    #[test]
    fn test_to_json_version_2() {
        let vault = Vault::new();
        let json = vault.to_json().unwrap();
        let data: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(data["version"], 2);
        assert!(data["salt"].is_string());
        assert_eq!(data["salt"].as_str().unwrap().len(), 32);
    }
}
