import Foundation
import Testing
@testable import PIIVault

private func entity(_ type: EntityType, _ start: Int, _ end: Int) -> RecognizerResult {
    RecognizerResult(entityType: type, start: start, end: end, score: 0.9)
}

@Suite struct AnonymizerTests {
    @Test func replaceDefault() {
        let result = Anonymizer.anonymize("Email me at test@example.com", entities: [entity(.emailAddress, 12, 28)])
        #expect(result.text == "Email me at <EMAIL_ADDRESS>")
        #expect(result.items.count == 1)
    }

    @Test func replaceCustom() {
        let result = Anonymizer.anonymize(
            "SSN: 123-45-6789",
            entities: [entity(.usSSN, 5, 16)],
            operators: [.usSSN: .replace(newValue: "[REDACTED]")]
        )
        #expect(result.text == "SSN: [REDACTED]")
    }

    @Test func mask() {
        let result = Anonymizer.anonymize(
            "Card: 4111111111111111",
            entities: [entity(.creditCard, 6, 22)],
            operators: [.creditCard: .mask(maskingChar: "*", charsToMask: 12, fromEnd: false)]
        )
        #expect(result.text == "Card: ************1111")
    }

    @Test func maskFromEnd() {
        let result = Anonymizer.anonymize(
            "Card: 4111111111111111",
            entities: [entity(.creditCard, 6, 22)],
            operators: [.creditCard: .mask(maskingChar: "#", charsToMask: 100, fromEnd: true)]
        )
        #expect(result.text == "Card: ################")
    }

    @Test func hash() {
        let text = "Email: test@example.com"
        let result = Anonymizer.anonymize(text, entities: [entity(.emailAddress, 7, 23)], operators: [.emailAddress: .hash()])
        #expect(result.text.hasPrefix("Email: "))
        #expect(result.text != text)
        // Golden value from the Rust implementation's Operator::Hash.
        #expect(result.items[0].replacement == "b1c28148")
        #expect(fnv1a32("") == 0x811c_9dc5)
        #expect(fnv1a32("张三") == 0x3901_87fb)  // UTF-8 bytes, as in Rust
    }

    @Test func redact() {
        let result = Anonymizer.anonymize("My phone is 555-123-4567", entities: [entity(.phoneNumber, 12, 24)], operators: [.phoneNumber: .redact])
        #expect(result.text == "My phone is ")
    }

    @Test func vaultRoundtrip() {
        let text = "Email: test@example.com"
        let vault = Vault()
        let result = Anonymizer.anonymize(text, entities: [entity(.emailAddress, 7, 23)], operators: [.emailAddress: .vault], vault: vault)
        #expect(result.text.contains("[EMAIL_ADDRESS:"))
        #expect(vault.entryCount == 1)
        #expect(vault.detokenize(result.text) == text)
    }

    @Test func vaultWithoutVaultFallsBackToPlaceholder() {
        let result = Anonymizer.anonymize("Email: test@example.com", entities: [entity(.emailAddress, 7, 23)], operators: [.emailAddress: .vault])
        #expect(result.text == "Email: <EMAIL_ADDRESS>")
    }

    @Test func multipleEntities() {
        let result = Anonymizer.anonymize(
            "alice@test.com called 555-123-4567",
            entities: [entity(.emailAddress, 0, 14), entity(.phoneNumber, 22, 34)]
        )
        #expect(result.text == "<EMAIL_ADDRESS> called <PHONE_NUMBER>")
        #expect(result.items.map(\.start) == [0, 22])
    }

    @Test func unicodeOffsets() {
        let text = "张三 📧 a@b.co"
        let result = Anonymizer.anonymize(text, entities: [entity(.emailAddress, 6, 12)])
        #expect(result.text == "张三 📧 <EMAIL_ADDRESS>")
        #expect(result.items[0].original == "a@b.co")
    }

    @Test func partialOverlapReplacesTheUnion() {
        let result = Anonymizer.anonymize("0123456789", entities: [entity("B", 4, 9), entity("A", 1, 6)])
        #expect(result.text == "0<A>9")
        #expect(result.items.map(\.entityType) == ["A"])
        #expect(result.items.map(\.original) == ["12345678"])
    }

    @Test func partialOverlapUsesHighestScoringOperator() {
        let low = RecognizerResult(entityType: "A", start: 1, end: 6, score: 0.3)
        let high = RecognizerResult(entityType: "B", start: 4, end: 9, score: 0.8)
        let result = Anonymizer.anonymize("0123456789", entities: [low, high], operators: ["B": .redact])
        #expect(result.text == "09")
    }

    @Test func overlappingAnalyzerOutputLeaksNothing() {
        // Dataset sample 80: two PHONE_NUMBER matches overlap inside the IBAN.
        let text = "Send payment to IBAN: ES9121000418450200051332 ref: INV-2024."
        let analysis = specAnalyzer.analyze(text)
        #expect(analysis.entities.contains { a in analysis.entities.contains { b in a != b && a.overlaps(b) } })
        let result = Anonymizer.anonymize(text, entities: analysis.entities)
        for range in analysis.redactionRanges {
            #expect(!result.text.contains((text as NSString).substring(with: range)))
        }
        #expect(!result.text.contains("0051332"))
    }

    @Test func outOfBoundsEntityIsSkipped() {
        let result = Anonymizer.anonymize("short", entities: [entity("X", 2, 50)])
        #expect(result.text == "short")
        #expect(result.items.isEmpty)
    }
}
