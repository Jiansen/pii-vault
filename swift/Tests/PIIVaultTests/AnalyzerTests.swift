import Foundation
import Testing
@testable import PIIVault

@Suite struct AnalyzerTests {
    let analyzer = Analyzer(recognizers: [makeRecognizer(emailJSON), makeRecognizer(phoneJSON)])

    @Test func detectsMultipleEntityTypes() {
        let result = analyzer.analyze("Email me at alice@example.com or call 555-123-4567")
        #expect(result.entities.count == 2)
        #expect(result.entities[0].entityType.name == "EMAIL_ADDRESS")
        #expect(result.entities[1].entityType.name == "PHONE_NUMBER")
    }

    @Test func filtersByEntityType() {
        let result = analyzer.analyze("Email me at alice@example.com or call 555-123-4567", entities: ["EMAIL_ADDRESS"])
        #expect(result.entities.count == 1)
        #expect(result.entities[0].entityType.name == "EMAIL_ADDRESS")
    }

    @Test func scoreThreshold() {
        let result = Analyzer(recognizers: [makeRecognizer(emailJSON)]).analyze("test@example.com", scoreThreshold: 0.9)
        #expect(result.entities.isEmpty)
    }

    @Test func recognizerCount() {
        #expect(analyzer.recognizerCount == 2)
    }

    @Test func containedLowerScoreMatchIsDropped() {
        let wide = makeRecognizer(#"""
        {"name": "wide", "entity_type": "WIDE", "version": "1", "patterns": [{"name": "w", "regex": "\\d{3}-\\d{4}", "score": 0.6}]}
        """#)
        let narrow = makeRecognizer(#"""
        {"name": "narrow", "entity_type": "NARROW", "version": "1", "patterns": [{"name": "n", "regex": "\\d{4}", "score": 0.3}]}
        """#)
        let result = Analyzer(recognizers: [narrow, wide]).analyze("123-4567")
        #expect(result.entities.map(\.entityType.name) == ["WIDE"])
    }

    @Test func exactTieKeepsFirstRecognizer() {
        let a = makeRecognizer(#"{"name": "a", "entity_type": "A", "version": "1", "patterns": [{"name": "p", "regex": "\\d+", "score": 0.5}]}"#)
        let b = makeRecognizer(#"{"name": "b", "entity_type": "B", "version": "1", "patterns": [{"name": "p", "regex": "\\d+", "score": 0.5}]}"#)
        #expect(Analyzer(recognizers: [a, b]).analyze("42").entities.map(\.entityType.name) == ["A"])
        #expect(Analyzer(recognizers: [b, a]).analyze("42").entities.map(\.entityType.name) == ["B"])
    }

    @Test func redactionRangesMergeOverlaps() {
        let result = AnalyzerResult(entities: [
            RecognizerResult(entityType: "A", start: 0, end: 5, score: 0.5),
            RecognizerResult(entityType: "B", start: 3, end: 8, score: 0.5),
            RecognizerResult(entityType: "C", start: 10, end: 12, score: 0.5),
        ])
        #expect(result.redactionRanges == [NSRange(location: 0, length: 8), NSRange(location: 10, length: 2)])
    }

    @Test func redactionRangesMergeTouchingAndSkipEmpty() {
        let result = AnalyzerResult(entities: [
            RecognizerResult(entityType: "A", start: 0, end: 3, score: 0.5),
            RecognizerResult(entityType: "B", start: 3, end: 5, score: 0.5),
            RecognizerResult(entityType: "C", start: 7, end: 7, score: 0.5),
        ])
        #expect(result.redactionRanges == [NSRange(location: 0, length: 5)])
    }

    @Test func customRecognizerConformance() {
        struct KeywordRecognizer: Recognizer {
            let name = "keyword"
            let supportedEntities: [EntityType] = ["SECRET"]
            func analyze(_ text: String, entities: [EntityType]) -> [RecognizerResult] {
                let r = (text as NSString).range(of: "hunter2")
                return r.location == NSNotFound ? [] : [RecognizerResult(entityType: "SECRET", start: r.location, end: NSMaxRange(r), score: 1)]
            }
        }
        let result = Analyzer(recognizers: [KeywordRecognizer(), makeRecognizer(emailJSON)]).analyze("pw hunter2 for a@b.com")
        #expect(result.entities.map(\.entityType.name) == ["SECRET", "EMAIL_ADDRESS"])
    }

    @Test(arguments: [0.0, 0.5])
    func concurrentMatchesSequential(threshold: Double) throws {
        struct Sample: Decodable { let text: String }
        let samples = try JSONDecoder().decode([Sample].self, from: Data(contentsOf: repoRoot.appendingPathComponent("benchmark/dataset.json")))
        let all = samples.map(\.text).joined(separator: "\n")
        let documents = [
            all,                                                          // ~5k units, includes CJK
            Array(repeating: all, count: 5).joined(separator: "\n"),
            String(repeating: "SSN 123-45-6789\u{200B} 张三 a@b.co\u{00AD} ", count: 40),
        ]
        for doc in documents {
            #expect((doc as NSString).length >= Analyzer.minimumConcurrentLength)
            let sequential = specAnalyzer.analyze(doc, scoreThreshold: threshold).entities
            #expect(!sequential.isEmpty)
            #expect(specAnalyzer.analyzeConcurrently(doc, scoreThreshold: threshold).entities == sequential)
            let filter: [EntityType] = [.emailAddress, .usSSN]
            #expect(specAnalyzer.analyzeConcurrently(doc, entities: filter, scoreThreshold: threshold).entities
                    == specAnalyzer.analyze(doc, entities: filter, scoreThreshold: threshold).entities)
        }
        for sample in samples {
            #expect(specAnalyzer.analyzeConcurrently(sample.text, scoreThreshold: threshold).entities
                    == specAnalyzer.analyze(sample.text, scoreThreshold: threshold).entities)
        }
    }

    @Test func concurrentKeepsRecognizerOrderOnTies() {
        let a = makeRecognizer(#"{"name": "a", "entity_type": "A", "version": "1", "patterns": [{"name": "p", "regex": "\\d+", "score": 0.5}]}"#)
        let b = makeRecognizer(#"{"name": "b", "entity_type": "B", "version": "1", "patterns": [{"name": "p", "regex": "\\d+", "score": 0.5}]}"#)
        let text = String(repeating: "x 42 ", count: 100)
        for order in [[a, b], [b, a]] {
            let analyzer = Analyzer(recognizers: order)
            let concurrent = analyzer.analyzeConcurrently(text).entities
            #expect(concurrent.count == 100)
            #expect(Set(concurrent.map(\.entityType)) == [order[0].entity])
            #expect(concurrent == analyzer.analyze(text).entities)
        }
    }

    @Test func concurrentRunsCustomRecognizers() {
        struct Marker: Recognizer {
            let name = "marker"
            let supportedEntities: [EntityType] = ["MARKER"]
            func analyze(_ text: String, entities: [EntityType]) -> [RecognizerResult] {
                [RecognizerResult(entityType: "MARKER", start: 0, end: 1, score: 1)]
            }
        }
        let analyzer = Analyzer(recognizers: [Marker(), makeRecognizer(emailJSON)])
        let text = String(repeating: "mail a@b.co ", count: 30)
        #expect(analyzer.analyzeConcurrently(text).entities == analyzer.analyze(text).entities)
        #expect(analyzer.analyzeConcurrently(text).entities.first?.entityType == "MARKER")
    }

    @Test func concurrentCallsFromManyTasks() async {
        let analyzer = specAnalyzer
        let text = String(repeating: "Email alice@company.com, SSN 123-45-6789. ", count: 20)
        let expected = analyzer.analyze(text).entities
        let results = await withTaskGroup(of: [RecognizerResult].self) { group in
            for _ in 0..<8 {
                group.addTask { analyzer.analyzeConcurrently(text).entities }
            }
            return await group.reduce(into: []) { $0.append($1) }
        }
        #expect(results.count == 8)
        #expect(results.allSatisfy { $0 == expected })
    }

    @Test func concurrentUseIsSafe() async {
        let analyzer = specAnalyzer
        let text = "Email alice@company.com, SSN 123-45-6789"
        let expected = analyzer.analyze(text).entities
        #expect(expected.contains { $0.entityType == .emailAddress } && expected.contains { $0.entityType == .usSSN })
        let results = await withTaskGroup(of: [RecognizerResult].self) { group in
            for _ in 0..<16 {
                group.addTask { analyzer.analyze(text).entities }
            }
            return await group.reduce(into: []) { $0.append($1) }
        }
        #expect(results.count == 16)
        #expect(results.allSatisfy { $0 == expected })
    }
}
