import Foundation
@testable import PIIVault

let repoRoot = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent().deletingLastPathComponent()
    .deletingLastPathComponent().deletingLastPathComponent()
let specRecognizersDir = repoRoot.appendingPathComponent("spec/recognizers")

/// One analyzer over every rule in `spec/recognizers`, shared by the integration tests.
let specAnalyzer: Analyzer = {
    do {
        return try Analyzer(rulesDirectory: specRecognizersDir)
    } catch {
        fatalError("Failed to load spec recognizers: \(error)")
    }
}()

func makeRecognizer(_ json: String) -> RegexRecognizer {
    do {
        return try RegexRecognizer(jsonString: json)
    } catch {
        fatalError("Bad test recognizer: \(error)")
    }
}

let emailJSON = #"""
{
    "name": "email_recognizer",
    "entity_type": "EMAIL_ADDRESS",
    "version": "1.0.0",
    "patterns": [{"name": "email", "regex": "[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}", "score": 0.5}],
    "context_words": ["email"],
    "context_score_boost": 0.4
}
"""#

let phoneJSON = #"""
{
    "name": "phone_recognizer",
    "entity_type": "PHONE_NUMBER",
    "version": "1.0.0",
    "patterns": [{"name": "phone", "regex": "\\(?\\d{3}\\)?[\\-\\s.]?\\d{3}[\\-\\s.]?\\d{4}", "score": 0.4}],
    "context_words": ["phone", "call"],
    "context_score_boost": 0.4
}
"""#

func entities(_ result: AnalyzerResult, ofType type: String) -> [RecognizerResult] {
    result.entities.filter { $0.entityType.name == type }
}
