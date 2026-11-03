import Foundation
import Testing
@testable import PIIVault

/// Ported from `rust/src/integration_tests.rs` and `typescript/src/__tests__/integration.test.ts`:
/// every case runs against the shared `spec/recognizers` rules.
@Suite struct IntegrationTests {
    struct Case: CustomTestStringConvertible, Sendable {
        let text: String
        let types: [String]
        var testDescription: String { "\(types.joined(separator: "|")): \(text)" }

        init(_ text: String, _ types: String...) {
            self.text = text
            self.types = types
        }
    }

    @Test func specRecognizersLoad() {
        #expect(specAnalyzer.recognizerCount >= 25)
    }

    @Test(arguments: [
        Case("Send to alice@company.org", "EMAIL_ADDRESS"),
        Case("SSN: 123-45-6789", "US_SSN"),
        Case("身份证号: 11010519491231002X", "CN_ID_CARD"),
        Case("手机号: +86 13912345678", "CN_PHONE", "PHONE_NUMBER"),
        Case("Card: 4111111111111111", "CREDIT_CARD"),
        Case("Server at 192.168.1.100", "IP_ADDRESS"),
        Case("Visit https://example.com/page", "URL"),
        Case("ID: 550e8400-e29b-41d4-a716-446655440000", "UUID"),
        Case("MAC: 00:1A:2B:3C:4D:5E", "MAC_ADDRESS"),
        Case("NI number: AB 12 34 56 C", "UK_NINO"),
        Case("PAN: ABCDE1234F", "IN_PAN"),
        Case("CF: RSSMRA85M01H501Z", "IT_FISCAL_CODE"),
        Case("CPF: 123.456.789-09", "BR_CPF"),
        Case("CPF: 529.982.247-25", "BR_CPF"),
        Case("PESEL: 02070803628", "PL_PESEL"),
        Case("Aadhaar: 4991 1866 5246", "IN_AADHAAR"),
        Case("NHS number: 401 023 2137", "UK_NHS"),
        Case("Routing: 011000015", "US_BANK_ROUTING"),
        Case("NIE: X1234567A", "ES_NIE"),
        Case("NRIC: S1234567A", "SG_NRIC"),
        Case("주민등록번호: 850101-1234567", "KR_RRN"),
        Case("IBAN: DE89370400440532013000", "IBAN_CODE"),
        Case("Steuer-ID: 86095742719", "DE_TAX_ID"),
        Case("Reisepass: C01X00T47", "DE_PASSPORT"),
        Case("USt-IdNr: DE123456789", "DE_VAT_ID"),
        Case("ABN: 51 824 753 556", "AU_ABN"),
        Case("TFN: 123 456 782", "AU_TFN"),
        // Male licence: MORGA = Morgan surname, 6=decade, 07=July, 05=5th, 4=year digit
        Case("Driving licence: MORGA607054SM9IJ", "UK_DRIVING_LICENCE"),
        // Female licence: month + 50 = 57 for July
        Case("MORGA657054SM9IJ", "UK_DRIVING_LICENCE"),
        // Short surname "FO" padded with 9s
        Case("FO999512018AA1AB", "UK_DRIVING_LICENCE"),
    ])
    func detects(_ c: Case) {
        let result = specAnalyzer.analyze(c.text)
        #expect(result.entities.contains { c.types.contains($0.entityType.name) }, "found: \(result.entities.map(\.entityType.name))")
    }

    @Test(arguments: [
        Case("Card: 1234567890123456", "CREDIT_CARD"),          // invalid Luhn
        Case("localhost is 127.0.0.1", "IP_ADDRESS"),           // deny list
        Case("IBAN: DE00370400440532013000", "IBAN_CODE"),      // invalid checksum
        Case("99999657054SM9IJ", "UK_DRIVING_LICENCE"),         // all-9s surname
        Case("MO9G9657054SM9IJ", "UK_DRIVING_LICENCE"),         // 9 before a letter in surname
        Case("CPF: 123.456.789-08", "BR_CPF"),                   // wrong check digit
        Case("PESEL: 44051401459", "PL_PESEL"),                  // wrong check digit
        Case("Aadhaar: 2234 5678 9012", "IN_AADHAAR"),           // wrong check digit
        Case("NHS number: 943 476 5918", "UK_NHS"),              // wrong check digit
        Case("Routing: 021000022", "US_BANK_ROUTING"),           // wrong check digit
    ])
    func rejects(_ c: Case) {
        let result = specAnalyzer.analyze(c.text)
        #expect(!result.entities.contains { c.types.contains($0.entityType.name) }, "found: \(result.entities.map(\.entityType.name))")
    }

    /// Format characters (zero-width space, soft hyphen, LRM, BOM, word joiner) next to PII:
    /// ICU's own `\b` sees no boundary there; the rewritten patterns must match like Rust.
    @Test(arguments: [
        ("SSN 123-45-6789\u{200B}", "US_SSN", "123-45-6789"),
        ("email a@b.co\u{200E}", "EMAIL_ADDRESS", "a@b.co"),
        ("x\u{00AD}123-45-6789", "US_SSN", "123-45-6789"),
        ("Card 4111111111111111\u{00AD}", "CREDIT_CARD", "4111111111111111"),
        ("ID 550e8400-e29b-41d4-a716-446655440000\u{200B}", "UUID", "550e8400-e29b-41d4-a716-446655440000"),
        ("IBAN DE89370400440532013000\u{FEFF}", "IBAN_CODE", "DE89370400440532013000"),
        ("身份证 11010519491231002X\u{2060}", "CN_ID_CARD", "11010519491231002X"),
    ])
    func detectsNextToFormatCharacters(text: String, type: String, expected: String) {
        let found = entities(specAnalyzer.analyze(text), ofType: type)
        #expect(found.map { $0.text(in: text) } == [expected])
    }

    @Test func exactlyOneEmail() {
        #expect(entities(specAnalyzer.analyze("Send to alice@company.org"), ofType: "EMAIL_ADDRESS").count == 1)
        #expect(specAnalyzer.analyze("Send to alice@company.org").entities.count == 1)
    }

    @Test func usBankNumberNeedsContext() {
        func banks(_ text: String) -> [String] {
            entities(specAnalyzer.analyze(text, scoreThreshold: 0.5), ofType: "US_BANK_NUMBER").compactMap { $0.text(in: text) }
        }
        #expect(banks("Regular Checking 98765432101") == ["98765432101"])
        #expect(banks("Order 98765432101 has shipped") == [])
    }

    private func found(_ text: String, _ type: String) -> [String] {
        entities(specAnalyzer.analyze(text, scoreThreshold: 0.5), ofType: type).compactMap { $0.text(in: text) }
    }

    @Test func koreanRRNForeignResidentAndDates() {
        // 5-8 in the 7th digit: foreign residents (외국인등록번호), same format
        #expect(found("외국인등록번호: 900101-5123456", "KR_RRN") == ["900101-5123456"])
        // Month 13 and day 32 are not dates of birth
        #expect(found("ref 851301-1234567", "KR_RRN") == [])
        #expect(found("ref 850132-1234567", "KR_RRN") == [])
    }

    @Test func brazilianCNPJ() {
        #expect(found("Empresa 11.222.333/0001-81 Ltda", "BR_CNPJ") == ["11.222.333/0001-81"])
        #expect(found("CNPJ 12.ABC.345/01DE-35", "BR_CNPJ") == ["12.ABC.345/01DE-35"])
        #expect(found("CNPJ: 11222333000181", "BR_CNPJ") == ["11222333000181"])
        // Bad check digit; bare 14 digits without context
        #expect(found("CNPJ 11.222.333/0001-82", "BR_CNPJ") == [])
        #expect(found("Pedido 11222333000181", "BR_CNPJ") == [])
    }

    @Test func dutchBSNNeedsContext() {
        #expect(found("BSN: 123456782", "NL_BSN") == ["123456782"])
        #expect(found("Burgerservicenummer 1234.56.782", "NL_BSN") == ["1234.56.782"])
        // Fails the 11-proof; passes it but has no context word
        #expect(found("BSN: 123456789", "NL_BSN") == [])
        #expect(found("Order 123456782 shipped", "NL_BSN") == [])
    }

    @Test func multipleEmails() {
        #expect(entities(specAnalyzer.analyze("alice@test.com and bob@test.com"), ofType: "EMAIL_ADDRESS").count == 2)
    }

    @Test(arguments: [
        ("身份证号: 11010519491231002X", "CN_ID_CARD"),
        ("Server at 192.168.1.100", "IP_ADDRESS"),
        ("Visit https://example.com/page", "URL"),
        ("ID: 550e8400-e29b-41d4-a716-446655440000", "UUID"),
        ("MAC: 00:1A:2B:3C:4D:5E", "MAC_ADDRESS"),
        ("NI number: AB 12 34 56 C", "UK_NINO"),
        ("PAN: ABCDE1234F", "IN_PAN"),
        ("CF: RSSMRA85M01H501Z", "IT_FISCAL_CODE"),
        ("CPF: 123.456.789-09", "BR_CPF"),
        ("NIE: X1234567A", "ES_NIE"),
        ("NRIC: S1234567A", "SG_NRIC"),
        ("주민등록번호: 850101-1234567", "KR_RRN"),
    ])
    func detectsExactlyOne(text: String, type: String) {
        #expect(entities(specAnalyzer.analyze(text), ofType: type).count == 1)
    }

    @Test func emptyText() {
        #expect(specAnalyzer.analyze("").entities.isEmpty)
    }

    @Test func noPIIText() {
        #expect(specAnalyzer.analyze("The weather is nice today", scoreThreshold: 0.3).entities.isEmpty)
    }

    @Test func mixedLanguageText() {
        let text = "张三的邮箱是 zhangsan@example.com，手机号 13800138000"
        let emails = entities(specAnalyzer.analyze(text), ofType: "EMAIL_ADDRESS")
        #expect(emails.count == 1)
        #expect(emails.first?.text(in: text) == "zhangsan@example.com")
        #expect(emails.first?.start == 7)  // UTF-16 offset
    }

    @Test func fullPipelineVault() {
        let text = "Email alice@company.com, SSN 123-45-6789, phone 13912345678"
        let analysis = specAnalyzer.analyze(text)
        let vault = Vault()
        let anon = Anonymizer.anonymize(
            text,
            entities: analysis.entities,
            operators: [.emailAddress: .vault, .usSSN: .vault, .cnPhone: .vault],
            vault: vault
        )
        #expect(!anon.text.contains("alice@company.com"))
        #expect(!anon.text.contains("123-45-6789"))
        #expect(vault.detokenize(anon.text).contains("alice@company.com"))
    }

    @Test func fullPipelineVaultAllEntities() {
        let text = "Email alice@company.com, SSN 123-45-6789"
        let analysis = specAnalyzer.analyze(text)
        let vault = Vault()
        let ops = Dictionary(analysis.entities.map { ($0.entityType, Operator.vault) }, uniquingKeysWith: { a, _ in a })
        let anon = Anonymizer.anonymize(text, entities: analysis.entities, operators: ops, vault: vault)
        #expect(!anon.text.contains("alice@company.com"))
        #expect(!anon.text.contains("123-45-6789"))
        #expect(vault.entryCount >= 1)
        #expect(vault.detokenize(anon.text) == text)
    }

    @Test func redactionRangesCoverEveryDetection() {
        let text = "Email alice@company.com, SSN 123-45-6789"
        let result = specAnalyzer.analyze(text, scoreThreshold: 0.5)
        let ns = text as NSString
        let redacted = result.redactionRanges.map { ns.substring(with: $0) }
        #expect(redacted.contains("alice@company.com"))
        #expect(redacted.contains("123-45-6789"))
    }
}

@Suite struct LoaderTests {
    @Test func directoryLoadIsSortedByFileName() throws {
        let recognizers = try RecognizerLoader.load(directory: specRecognizersDir)
        let files = try FileManager.default.contentsOfDirectory(atPath: specRecognizersDir.path)
            .filter { $0.hasSuffix(".json") }.sorted()
        let expected = try files.flatMap { try RecognizerLoader.load(file: specRecognizersDir.appendingPathComponent($0)) }
        #expect(recognizers.map(\.name) == expected.map(\.name))
    }

    @Test func singleFileWithArrayOfRules() throws {
        // Bundle every spec rule into one JSON array file, in directory load order.
        let files = try FileManager.default.contentsOfDirectory(atPath: specRecognizersDir.path)
            .filter { $0.hasSuffix(".json") }.sorted()
        let objects = try files.map { try JSONSerialization.jsonObject(with: Data(contentsOf: specRecognizersDir.appendingPathComponent($0))) }
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("piivault-rules-\(UUID().uuidString).json")
        try JSONSerialization.data(withJSONObject: objects).write(to: file)
        defer { try? FileManager.default.removeItem(at: file) }

        let recognizers = try RecognizerLoader.load(file: file)
        #expect(recognizers.map(\.name) == specAnalyzer.recognizers.map(\.name))
        let text = "SSN: 123-45-6789, mail a@b.co"
        #expect(Analyzer(recognizers: recognizers).analyze(text).entities == specAnalyzer.analyze(text).entities)
    }

    @Test func brokenFileFailsTheLoad() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("piivault-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        try Data(emailJSON.utf8).write(to: dir.appendingPathComponent("a.json"))
        try Data("{ not json".utf8).write(to: dir.appendingPathComponent("b.json"))
        try Data("ignored".utf8).write(to: dir.appendingPathComponent("README.md"))
        try Data("{ editor temp file".utf8).write(to: dir.appendingPathComponent(".a.json.swp.json"))

        #expect(throws: RecognizerLoadError.self) { try RecognizerLoader.load(directory: dir) }

        try FileManager.default.removeItem(at: dir.appendingPathComponent("b.json"))
        #expect(try RecognizerLoader.load(directory: dir).count == 1)
    }

    @Test func malformedArrayReportsTheArrayError() {
        #expect(throws: DecodingError.self) {
            try RecognizerLoader.definitions(from: Data(#"[{"name": "x"}]"#.utf8))
        }
        do {
            _ = try RecognizerLoader.definitions(from: Data(#"  [{"name": "x"}]"#.utf8))
        } catch let DecodingError.keyNotFound(key, _) {
            #expect(key.stringValue == "entity_type")
        } catch {
            Issue.record("unexpected error \(error)")
        }
    }

    @Test func missingDirectoryThrows() {
        #expect(throws: (any Error).self) {
            try RecognizerLoader.load(directory: URL(fileURLWithPath: "/nonexistent/piivault"))
        }
    }

    @Test func everySpecPatternCompiles() throws {
        for url in try FileManager.default.contentsOfDirectory(at: specRecognizersDir, includingPropertiesForKeys: nil)
        where url.pathExtension == "json" {
            #expect(throws: Never.self) { try RecognizerLoader.load(file: url) }
        }
    }
}
