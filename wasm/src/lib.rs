use wasm_bindgen::prelude::*;
use pii_vault::recognizer::{RegexRecognizer, RecognizerDef, Recognizer};
use pii_vault::analyzer::Analyzer;
use pii_vault::anonymizer::{Anonymizer as CoreAnonymizer, Operator};
use pii_vault::vault::Vault;
use std::collections::HashMap;

#[wasm_bindgen]
pub struct WasmAnalyzer {
    analyzer: Analyzer,
}

#[wasm_bindgen]
impl WasmAnalyzer {
    #[wasm_bindgen(constructor)]
    pub fn new(recognizer_jsons: &str) -> Result<WasmAnalyzer, JsError> {
        let defs: Vec<RecognizerDef> = serde_json::from_str(recognizer_jsons)
            .map_err(|e| JsError::new(&format!("Invalid recognizer JSON: {}", e)))?;

        let mut recognizers: Vec<Box<dyn Recognizer>> = Vec::new();
        for def in defs {
            let rec = RegexRecognizer::from_def(def)
                .map_err(|e| JsError::new(&format!("Invalid regex: {}", e)))?;
            recognizers.push(Box::new(rec));
        }

        Ok(WasmAnalyzer {
            analyzer: Analyzer::new(recognizers),
        })
    }

    pub fn analyze(&self, text: &str, score_threshold: f64) -> Result<JsValue, JsError> {
        let result = self.analyzer.analyze(text, &[], score_threshold);
        let entities: Vec<EntityResult> = result.entities.iter().map(|e| EntityResult {
            entity_type: e.entity_type.as_str().to_string(),
            start: e.start,
            end: e.end,
            score: e.score,
            text: text[e.start..e.end].to_string(),
        }).collect();
        serde_wasm_bindgen::to_value(&entities)
            .map_err(|e| JsError::new(&format!("Serialization error: {}", e)))
    }

    pub fn anonymize(&self, text: &str, score_threshold: f64) -> Result<String, JsError> {
        let result = self.analyzer.analyze(text, &[], score_threshold);
        let ops = HashMap::new();
        let default_op = Operator::Replace { new_value: String::new() };
        let anon = CoreAnonymizer::anonymize(text, &result.entities, &ops, &default_op, None);
        Ok(anon.text)
    }
}

#[wasm_bindgen]
pub struct WasmVault {
    vault: Vault,
}

#[wasm_bindgen]
impl WasmVault {
    #[wasm_bindgen(constructor)]
    pub fn new() -> WasmVault {
        WasmVault { vault: Vault::new() }
    }

    pub fn tokenize(&mut self, entity_type: &str, original: &str) -> String {
        self.vault.tokenize_ctx(entity_type, original, "")
    }

    pub fn detokenize(&self, text: &str) -> String {
        self.vault.detokenize(text)
    }

    pub fn entry_count(&self) -> usize {
        self.vault.entry_count()
    }
}

#[derive(serde::Serialize)]
struct EntityResult {
    entity_type: String,
    start: usize,
    end: usize,
    score: f64,
    text: String,
}
