use crate::entity::{EntityType, RecognizerResult};
use crate::recognizer::Recognizer;

pub struct Analyzer {
    recognizers: Vec<Box<dyn Recognizer>>,
}

#[derive(Debug, Clone)]
pub struct AnalyzerResult {
    pub entities: Vec<RecognizerResult>,
}

impl Analyzer {
    pub fn new(recognizers: Vec<Box<dyn Recognizer>>) -> Self {
        Self { recognizers }
    }

    pub fn analyze(&self, text: &str, entities: &[EntityType], score_threshold: f64) -> AnalyzerResult {
        let mut all_results = Vec::new();

        for recognizer in &self.recognizers {
            let results = recognizer.analyze(text, entities);
            all_results.extend(results);
        }

        all_results.retain(|r| r.score >= score_threshold);
        all_results.sort_by(|a, b| a.start.cmp(&b.start).then(b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal)));

        let deduped = Self::resolve_overlaps(all_results);

        AnalyzerResult { entities: deduped }
    }

    fn resolve_overlaps(results: Vec<RecognizerResult>) -> Vec<RecognizerResult> {
        let mut output: Vec<RecognizerResult> = Vec::new();
        for result in results {
            let dominated = output.iter().any(|existing| {
                existing.start <= result.start
                    && existing.end >= result.end
                    && existing.score >= result.score
            });
            if dominated {
                continue;
            }

            output.retain(|existing| {
                !(result.start <= existing.start
                    && result.end >= existing.end
                    && result.score >= existing.score)
            });

            output.push(result);
        }
        output.sort_by_key(|r| r.start);
        output
    }

    pub fn recognizer_count(&self) -> usize {
        self.recognizers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recognizer::RegexRecognizer;

    fn make_email_recognizer() -> Box<dyn Recognizer> {
        let json = r#"{
            "name": "email_recognizer",
            "entity_type": "EMAIL_ADDRESS",
            "version": "1.0.0",
            "patterns": [{"name": "email", "regex": "[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}", "score": 0.5}],
            "context_words": ["email"],
            "context_score_boost": 0.4
        }"#;
        Box::new(RegexRecognizer::from_json(json).unwrap())
    }

    fn make_phone_recognizer() -> Box<dyn Recognizer> {
        let json = r#"{
            "name": "phone_recognizer",
            "entity_type": "PHONE_NUMBER",
            "version": "1.0.0",
            "patterns": [{"name": "phone", "regex": "\\(?\\d{3}\\)?[\\-\\s.]?\\d{3}[\\-\\s.]?\\d{4}", "score": 0.4}],
            "context_words": ["phone", "call"],
            "context_score_boost": 0.4
        }"#;
        Box::new(RegexRecognizer::from_json(json).unwrap())
    }

    #[test]
    fn test_analyzer_multi_entity() {
        let analyzer = Analyzer::new(vec![make_email_recognizer(), make_phone_recognizer()]);
        let result = analyzer.analyze(
            "Email me at alice@example.com or call 555-123-4567",
            &[],
            0.0,
        );
        assert_eq!(result.entities.len(), 2);
        assert_eq!(result.entities[0].entity_type.as_str(), "EMAIL_ADDRESS");
        assert_eq!(result.entities[1].entity_type.as_str(), "PHONE_NUMBER");
    }

    #[test]
    fn test_analyzer_filter_by_entity() {
        let analyzer = Analyzer::new(vec![make_email_recognizer(), make_phone_recognizer()]);
        let result = analyzer.analyze(
            "Email me at alice@example.com or call 555-123-4567",
            &[EntityType::new("EMAIL_ADDRESS")],
            0.0,
        );
        assert_eq!(result.entities.len(), 1);
        assert_eq!(result.entities[0].entity_type.as_str(), "EMAIL_ADDRESS");
    }

    #[test]
    fn test_score_threshold() {
        let analyzer = Analyzer::new(vec![make_email_recognizer()]);
        let result = analyzer.analyze("test@example.com", &[], 0.9);
        assert_eq!(result.entities.len(), 0);
    }
}
