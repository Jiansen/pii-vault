pub mod analyzer;
pub mod anonymizer;
pub mod entity;
pub mod recognizer;
pub mod vault;

#[cfg(test)]
mod integration_tests;

pub use analyzer::{Analyzer, AnalyzerResult};
pub use anonymizer::{AnonymizedResult, Anonymizer, Operator};
pub use entity::{EntityType, RecognizerResult};
pub use recognizer::{load_recognizers_from_dir, Recognizer, RecognizerDef, RegexRecognizer};
pub use vault::Vault;
