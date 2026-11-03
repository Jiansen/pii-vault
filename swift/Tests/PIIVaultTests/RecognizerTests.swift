import Foundation
import Testing
@testable import PIIVault

@Suite struct RecognizerTests {
    @Test func detectsEmail() {
        let text = "Contact me at test@example.com please"
        let results = makeRecognizer(emailJSON).analyze(text, entities: [])
        #expect(results.count == 1)
        #expect(results[0].entityType.name == "EMAIL_ADDRESS")
        #expect(results[0].text(in: text) == "test@example.com")
    }

    @Test func contextBoostIncreasesScore() {
        let rec = makeRecognizer(emailJSON)
        let withContext = rec.analyze("My email is test@example.com", entities: [])
        let withoutContext = rec.analyze("test@example.com", entities: [])
        #expect(withContext[0].score > withoutContext[0].score)
    }

    @Test func filtersByEntityType() {
        let results = makeRecognizer(emailJSON).analyze("test@example.com", entities: [.phoneNumber])
        #expect(results.isEmpty)
    }

    @Test func denyListFiltersMatches() {
        let rec = makeRecognizer(#"""
        {
            "name": "ip_recognizer",
            "entity_type": "IP_ADDRESS",
            "version": "1.0.0",
            "patterns": [{"name": "ipv4", "regex": "\\b(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\b", "score": 0.5}],
            "deny_list": ["0.0.0.0", "127.0.0.1"],
            "context_words": []
        }
        """#)
        let text = "Server at 127.0.0.1 and 192.168.1.1"
        let results = rec.analyze(text, entities: [])
        #expect(results.count == 1)
        #expect(results[0].text(in: text) == "192.168.1.1")
    }

    @Test func detectsUSSSN() {
        let rec = makeRecognizer(#"""
        {
            "name": "us_ssn_recognizer", "entity_type": "US_SSN", "version": "1.0.0",
            "patterns": [{"name": "ssn", "regex": "\\b\\d{3}-\\d{2}-\\d{4}\\b", "score": 0.5}],
            "context_words": ["social security", "ssn"], "context_score_boost": 0.4
        }
        """#)
        let results = rec.analyze("SSN: 123-45-6789", entities: [])
        #expect(results.count == 1)
        #expect(results[0].entityType == .usSSN)
    }

    @Test func detectsChineseIDCardWithContextBoost() {
        let rec = makeRecognizer(#"""
        {
            "name": "cn_id_card_recognizer", "entity_type": "CN_ID_CARD", "version": "1.0.0",
            "patterns": [{"name": "cn_id", "regex": "\\b\\d{17}[\\dXx]\\b", "score": 0.3}],
            "context_words": ["身份证"], "context_score_boost": 0.5,
            "validators": ["cn_id_checksum"]
        }
        """#)
        let results = rec.analyze("身份证号: 11010519491231002X", entities: [])
        #expect(results.count == 1)
        #expect(results[0].score == 0.8)
    }

    @Test func detectsChinesePhoneNumber() {
        let rec = makeRecognizer(#"""
        {
            "name": "cn_phone_recognizer", "entity_type": "CN_PHONE", "version": "1.0.0",
            "patterns": [{"name": "cn_mobile", "regex": "\\b1[3-9]\\d{9}\\b", "score": 0.4}],
            "context_words": ["手机"], "context_score_boost": 0.3
        }
        """#)
        let results = rec.analyze("手机号: 13912345678", entities: [])
        #expect(results.count == 1)
        #expect(results[0].entityType == .cnPhone)
    }

    @Test func creditCardRequiresLuhn() {
        let rec = makeRecognizer(#"""
        {
            "name": "credit_card_recognizer", "entity_type": "CREDIT_CARD", "version": "1.0.0",
            "patterns": [{"name": "cc", "regex": "\\b(?:\\d{4}[\\-\\s]?){3}\\d{4}\\b", "score": 0.3}],
            "validators": ["luhn"]
        }
        """#)
        #expect(rec.analyze("Card: 4111111111111111", entities: []).count == 1)
        #expect(rec.analyze("Card: 1234567890123456", entities: []).isEmpty)
    }

    @Test func detectsMultipleEmails() {
        let results = makeRecognizer(emailJSON).analyze("Contact alice@test.com and bob@test.com", entities: [])
        #expect(results.count == 2)
    }

    @Test func offsetsAreUTF16() {
        // "👋" is 2 UTF-16 units, "邮箱" 2 units; the email starts at UTF-16 offset 7.
        let text = "👋 邮箱: a@b.co"
        let results = makeRecognizer(emailJSON).analyze(text, entities: [])
        #expect(results.count == 1)
        #expect(results[0].start == 7)
        #expect(results[0].end == 13)
        #expect(results[0].text(in: text) == "a@b.co")
        let range = results[0].range(in: text)
        #expect(range.map { String(text[$0]) } == "a@b.co")
    }

    @Test func contextWindowIsCaseInsensitive() {
        let rec = makeRecognizer(emailJSON)
        #expect(rec.analyze("EMAIL: x@y.com", entities: [])[0].score == 0.9)
    }

    @Test func emptyContextWordAlwaysBoosts() {
        let rec = makeRecognizer(#"""
        {"name": "r", "entity_type": "X", "version": "1", "patterns": [{"name": "p", "regex": "\\d{3}", "score": 0.5}],
         "context_words": [""], "context_score_boost": 0.2}
        """#)
        #expect(rec.analyze("123", entities: [])[0].score == 0.7)
    }

    @Test func outOfRangeResultTextIsNil() {
        let r = RecognizerResult(entityType: "X", start: 2, end: 50, score: 1)
        #expect(r.text(in: "short") == nil)
        #expect(r.range(in: "short") == nil)
    }

    @Test(arguments: [
        (#"\b\d{3}\b"#, #"(?<!\w)\d{3}(?!\w)"#),
        (#"\b[A-Z]{2}\d{7}\b"#, #"(?<!\w)[A-Z]{2}\d{7}(?!\w)"#),
        (#"\b[\dXx]\b"#, #"(?<!\w)[\dXx](?!\w)"#),
        (#"\b(?:4\d{3}|5\d{3})\b"#, #"(?<!\w)(?:4\d{3}|5\d{3})(?!\w)"#),  // every alternative starts/ends with a word char
        (#"\b(?:4|-)\b"#, #"⟨b⟩(?:4|-)⟨b⟩"#),  // one alternative does not
        (#"\b(?=\d)\d"#, #"⟨b⟩(?=\d)\d"#),  // lookahead: not analyzed
        (#"\b\d?x"#, #"(?<!\w)\d?x"#),           // optional word atom, then a word atom
        (#"\b\d?-"#, #"⟨b⟩\d?-"#),               // optional word atom, then a non-word one
        (#"[A-Z]{0,2}\b"#, #"[A-Z]{0,2}⟨b⟩"#),
        (#"\b[\s\d]"#, #"⟨b⟩[\s\d]"#),
        (#"\b[^a]"#, #"⟨b⟩[^a]"#),
        (#"\w+(?:[\-.]\w+)*\b"#, #"\w+(?:[\-.]\w+)*(?!\w)"#),
        (#"[\-.]\w*\b"#, #"[\-.]\w*⟨b⟩"#),
        (#"a\Bb"#, #"a(?:(?<=\w)(?=\w)|(?<!\w)(?!\w))b"#),
        (#"[\b\d]"#, #"[\b\d]"#),                           // inside a class: untouched
        (#"\\b"#, #"\\b"#),                                 // escaped backslash, then a literal b
        (#"\Q\b\E\b"#, #"\Q\b\E⟨b⟩"#),
    ])
    func wordBoundaryRewrite(input: String, expected: String) {
        // ⟨b⟩ stands for the general (unoptimized) boundary form.
        let general = #"(?:(?<=\w)(?!\w)|(?<!\w)(?=\w))"#
        #expect(rewriteWordBoundaries(input) == expected.replacingOccurrences(of: "⟨b⟩", with: general))
    }

    /// The shortcut forms must match exactly what the general lookaround form matches.
    @Test func optimizedRewriteMatchesGeneralForm() throws {
        let alphabet = Array("0123456789AZaz9X-. @_:/\u{200B}\u{00AD}\u{200D}\u{FEFF}é\u{301}张😀")
        var rng = SplitMix64(seed: 42)
        let corpus = (0..<400).map { _ in
            String((0..<Int.random(in: 1...40, using: &rng)).map { _ in alphabet.randomElement(using: &rng)! })
        } + ["SSN 123-45-6789\u{200B}", "4111111111111111\u{00AD}", "x\u{301}12345678901"]
        let definitions = try FileManager.default.contentsOfDirectory(at: specRecognizersDir, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "json" }
            .flatMap { try RecognizerLoader.definitions(from: Data(contentsOf: $0)) }
        for pattern in definitions.flatMap(\.patterns) {
            let fast = try NSRegularExpression(pattern: rewriteWordBoundaries(pattern.regex))
            let general = try NSRegularExpression(pattern: rewriteWordBoundaries(pattern.regex, optimize: false))
            for text in corpus {
                let range = NSRange(location: 0, length: (text as NSString).length)
                #expect(fast.matches(in: text, range: range).map(\.range) == general.matches(in: text, range: range).map(\.range),
                        "\(pattern.name) on \(text.debugDescription)")
            }
        }
    }

    @Test func unknownValidatorsAreIgnored() {
        let rec = makeRecognizer(#"""
        {"name": "r", "entity_type": "BR_CPF", "version": "1.0.0",
         "patterns": [{"name": "cpf", "regex": "\\b\\d{3}\\.\\d{3}\\.\\d{3}-\\d{2}\\b", "score": 0.5}],
         "validators": ["no_such_validator"]}
        """#)
        #expect(rec.analyze("CPF: 123.456.789-08", entities: []).count == 1)
    }

    @Test func invalidRegexThrows() {
        #expect(throws: RecognizerLoadError.self) {
            try RegexRecognizer(jsonString: #"""
            {"name": "bad", "entity_type": "X", "version": "1.0.0", "patterns": [{"name": "p", "regex": "(", "score": 0.5}]}
            """#)
        }
    }

    @Test func missingRequiredFieldThrows() {
        #expect(throws: DecodingError.self) {
            try RegexRecognizer(jsonString: #"{"name": "bad", "entity_type": "X", "patterns": []}"#)
        }
    }
}

@Suite struct ValidatorTests {
    @Test func luhnValid() {
        #expect(Checksum.luhn("4532015112830366"))
        #expect(Checksum.luhn("4111111111111111"))
    }

    @Test func luhnInvalid() {
        #expect(!Checksum.luhn("1234567890123456"))
    }

    @Test func cnIDValid() {
        #expect(Checksum.cnID("11010519491231002X"))
        #expect(Checksum.cnID("11010519491231002x"))
    }

    @Test func cnIDInvalid() {
        #expect(!Checksum.cnID("110105194912310020"))
    }

    /// Shared with the Rust and TypeScript tests.
    @Test func brazilianCNPJ() {
        #expect(Checksum.brCNPJ("11.222.333/0001-81"))
        #expect(Checksum.brCNPJ("11222333000181"))
        #expect(Checksum.brCNPJ("04.252.011/0001-10"))
        // Alphanumeric example published by the Receita Federal
        #expect(Checksum.brCNPJ("12.ABC.345/01DE-35"))
        #expect(!Checksum.brCNPJ("12.ABC.345/01DE-36"))
        #expect(!Checksum.brCNPJ("11.222.333/0001-82"))
        #expect(!Checksum.brCNPJ("11.222.333/0001-91"))
        #expect(!Checksum.brCNPJ("00.000.000/0000-00"))
        #expect(!Checksum.brCNPJ("1122233300018"))
        #expect(!Checksum.brCNPJ("12.ABC.345/01DE-3A"))
    }

    /// Shared with the Rust and TypeScript tests.
    @Test func brazilianCPF() {
        #expect(Checksum.cpf("123.456.789-09"))
        #expect(Checksum.cpf("52998224725"))
        #expect(!Checksum.cpf("123.456.789-08"))
        #expect(!Checksum.cpf("123.456.789-19"))
        #expect(!Checksum.cpf("111.111.111-11"))
        #expect(!Checksum.cpf("1234567890"))
    }

    /// Shared with the Rust and TypeScript tests.
    @Test func polishPESEL() {
        #expect(Checksum.pesel("44051401458"))
        #expect(Checksum.pesel("02070803628"))
        #expect(!Checksum.pesel("44051401459"))
        #expect(!Checksum.pesel("4405140145"))
    }

    /// Shared with the Rust and TypeScript tests.
    @Test func verhoeff() {
        #expect(Checksum.verhoeff("2363"))
        #expect(!Checksum.verhoeff("2364"))
        #expect(Checksum.verhoeff("4991 1866 5246"))
        #expect(Checksum.verhoeff("2234 5678 9018"))
        #expect(!Checksum.verhoeff("2234 5678 9012"))
        #expect(!Checksum.verhoeff(""))
    }

    /// Shared with the Rust and TypeScript tests.
    @Test func ukNHS() {
        #expect(Checksum.nhs("943 476 5919"))
        #expect(Checksum.nhs("4010232137"))
        #expect(!Checksum.nhs("943 476 5918"))
        #expect(!Checksum.nhs("401 023 2138"))
        #expect(!Checksum.nhs("123456789"))
    }

    /// Shared with the Rust and TypeScript tests.
    @Test func abaRouting() {
        #expect(Checksum.aba("021000021"))
        #expect(Checksum.aba("011000015"))
        #expect(!Checksum.aba("021000022"))
        #expect(!Checksum.aba("000000000"))
        #expect(!Checksum.aba("02100002"))
    }

    /// Shared with the Rust and TypeScript tests.
    @Test func dutchBSN() {
        #expect(Checksum.nlBSN("111222333"))
        #expect(Checksum.nlBSN("123456782"))
        #expect(Checksum.nlBSN("1234.56.782"))
        #expect(!Checksum.nlBSN("123456789"))
        #expect(!Checksum.nlBSN("000000000"))
        #expect(!Checksum.nlBSN("12345678"))
    }

    @Test func iban() {
        #expect(Checksum.iban("DE89370400440532013000"))
        #expect(Checksum.iban("DE89 3704 0044 0532 0130 00"))
        #expect(!Checksum.iban("DE00370400440532013000"))
    }

    @Test func germanTaxID() {
        #expect(Checksum.deTaxID("86095742719"))
        #expect(!Checksum.deTaxID("86095742718"))
        #expect(!Checksum.deTaxID("11111111111"))
    }

    @Test func australianNumbers() {
        #expect(Checksum.auABN("51 824 753 556"))
        #expect(!Checksum.auABN("51 824 753 557"))
        #expect(Checksum.auTFN("123 456 782"))
        #expect(!Checksum.auTFN("123 456 789"))
        #expect(Checksum.auACN("004 085 616"))
        #expect(!Checksum.auACN("004 085 617"))
        #expect(Checksum.auMedicare("2123 45670 1"))
        #expect(!Checksum.auMedicare("1123 45670 1"))
    }

    @Test func ukDrivingLicence() {
        #expect(Checksum.ukDrivingLicence("MORGA607054SM9IJ"))
        #expect(Checksum.ukDrivingLicence("FO999512018AA1AB"))
        #expect(!Checksum.ukDrivingLicence("99999657054SM9IJ"))
        #expect(!Checksum.ukDrivingLicence("MO9G9657054SM9IJ"))
    }
}

/// Deterministic RNG so the fuzz corpus is the same on every run.
struct SplitMix64: RandomNumberGenerator {
    var state: UInt64
    init(seed: UInt64) { state = seed }
    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}

/// Shared with the Rust and TypeScript tests: the same cases, the same answers.
@Suite struct ContextWordTests {
    @Test(arguments: [
        ("tel: 555 1234", "tel", true),
        ("hotel 555 1234", "tel", false),
        ("the hotel tel line", "tel", true),
        ("valid until", "id", false),
        ("id: 42", "id", true),
        ("aws_secret_access_key=", "secret", true),
        ("e-mail me", "mail", true),
        ("accounts", "account", true),
        ("calls", "call", true),
        ("callsign", "call", false),
        ("ids", "id", true),
        ("联系电话：", "电话", true),
        ("phone号码", "phone", true),
        ("주민등록번호는", "주민등록번호", true),
        ("bass#1", "ss#", false),
        ("ss#123", "ss#", true),
        ("\u{1D400}tel", "tel", false),
        ("tel\u{1D400}", "tel", false),
        ("anything", "", true),
    ])
    func matchesWholeWords(window: String, word: String, expected: Bool) {
        #expect(containsWord(window as NSString, word) == expected)
    }

    @Test func aContextWordInsideALongerWordDoesNotBoost() throws {
        let rec = try RegexRecognizer(jsonString: """
        {"name": "phone", "entity_type": "PHONE_NUMBER", "version": "1.0.0",
         "patterns": [{"name": "us", "regex": "\\\\d{3}-\\\\d{4}", "score": 0.4}],
         "context_words": ["tel"], "context_score_boost": 0.4}
        """)
        #expect(abs(rec.analyze("Tel: 555-1234", entities: [])[0].score - 0.8) < 1e-9)
        #expect(abs(rec.analyze("Hotel room 555-1234", entities: [])[0].score - 0.4) < 1e-9)
    }
}
