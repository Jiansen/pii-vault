import Foundation

/// Something that finds PII in text. Conform to this to plug custom detectors into ``Analyzer``.
public protocol Recognizer: Sendable {
    var name: String { get }
    var supportedEntities: [EntityType] { get }
    /// Returns every match in `text`. When `entities` is non-empty, recognizers whose entity is
    /// not in the list return nothing. Offsets are UTF-16 (see ``RecognizerResult``).
    func analyze(_ text: String, entities: [EntityType]) -> [RecognizerResult]
}

public struct PatternDefinition: Hashable, Sendable, Codable {
    public var name: String
    public var regex: String
    public var score: Double

    public init(name: String, regex: String, score: Double) {
        self.name = name
        self.regex = regex
        self.score = score
    }
}

/// The JSON rule format shared by every implementation (`spec/recognizers/*.json`).
public struct RecognizerDefinition: Hashable, Sendable, Codable {
    public var name: String
    public var entityType: String
    public var version: String
    public var patterns: [PatternDefinition]
    public var contextWords: [String]
    public var contextScoreBoost: Double
    public var denyList: [String]
    public var validators: [String]
    public var supportedLanguages: [String]?

    public init(
        name: String,
        entityType: String,
        version: String = "1.0.0",
        patterns: [PatternDefinition],
        contextWords: [String] = [],
        contextScoreBoost: Double = 0,
        denyList: [String] = [],
        validators: [String] = [],
        supportedLanguages: [String]? = nil
    ) {
        self.name = name
        self.entityType = entityType
        self.version = version
        self.patterns = patterns
        self.contextWords = contextWords
        self.contextScoreBoost = contextScoreBoost
        self.denyList = denyList
        self.validators = validators
        self.supportedLanguages = supportedLanguages
    }

    enum CodingKeys: String, CodingKey {
        case name
        case entityType = "entity_type"
        case version, patterns
        case contextWords = "context_words"
        case contextScoreBoost = "context_score_boost"
        case denyList = "deny_list"
        case validators
        case supportedLanguages = "supported_languages"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        name = try c.decode(String.self, forKey: .name)
        entityType = try c.decode(String.self, forKey: .entityType)
        version = try c.decode(String.self, forKey: .version)
        patterns = try c.decode([PatternDefinition].self, forKey: .patterns)
        contextWords = try c.decodeIfPresent([String].self, forKey: .contextWords) ?? []
        contextScoreBoost = try c.decodeIfPresent(Double.self, forKey: .contextScoreBoost) ?? 0
        denyList = try c.decodeIfPresent([String].self, forKey: .denyList) ?? []
        validators = try c.decodeIfPresent([String].self, forKey: .validators) ?? []
        supportedLanguages = try c.decodeIfPresent([String].self, forKey: .supportedLanguages)
    }
}

/// A recognizer driven by a ``RecognizerDefinition``: regex patterns, optional checksum
/// validators, a deny list, and context words that boost the score when found, as whole
/// words, within 100 UTF-16 units of a match.
public final class RegexRecognizer: Recognizer, @unchecked Sendable {
    // Immutable after init; NSRegularExpression is documented as thread-safe.
    public let definition: RecognizerDefinition
    public let entity: EntityType
    private let compiled: [(name: String, regex: NSRegularExpression, score: Double)]
    private let lowercasedContextWords: [String]
    private let denyList: Set<String>
    private let validators: [Validator]

    public init(definition: RecognizerDefinition) throws {
        self.definition = definition
        self.entity = EntityType(definition.entityType)
        self.compiled = try definition.patterns.map { p in
            do {
                return (p.name, try NSRegularExpression(pattern: rewriteWordBoundaries(p.regex)), p.score)
            } catch {
                throw RecognizerLoadError.invalidRegex(recognizer: definition.name, pattern: p.name, regex: p.regex)
            }
        }
        self.lowercasedContextWords = definition.contextWords.map { $0.lowercased() }
        self.denyList = Set(definition.denyList)
        // Unknown validator names are ignored, as in the Rust and TypeScript implementations.
        self.validators = definition.validators.compactMap(Validator.init(rawValue:))
    }

    public convenience init(json: Data) throws {
        try self.init(definition: JSONDecoder().decode(RecognizerDefinition.self, from: json))
    }

    public convenience init(jsonString: String) throws {
        try self.init(json: Data(jsonString.utf8))
    }

    public var name: String { definition.name }
    public var supportedEntities: [EntityType] { [entity] }

    public func analyze(_ text: String, entities: [EntityType]) -> [RecognizerResult] {
        analyze(utf16Backed(text), entities: entities)
    }

    /// Same as ``analyze(_:entities:)`` for a caller that already holds an `NSString`
    /// (``Analyzer`` builds one UTF-16 copy of the text and shares it across recognizers).
    public func analyze(_ text: NSString, entities: [EntityType]) -> [RecognizerResult] {
        if !entities.isEmpty && !entities.contains(entity) {
            return []
        }
        return compiled.indices.flatMap { matches(ofPattern: $0, in: text) }
    }

    var patternCount: Int { compiled.count }

    /// The results of one pattern; ``analyze(_:entities:)-(NSString,_)`` is these concatenated
    /// in pattern order. ``Analyzer/analyzeConcurrently(_:entities:scoreThreshold:)`` runs
    /// patterns as separate work items.
    func analyze(_ text: NSString, entities: [EntityType], pattern index: Int) -> [RecognizerResult] {
        if !entities.isEmpty && !entities.contains(entity) {
            return []
        }
        return matches(ofPattern: index, in: text)
    }

    private func matches(ofPattern index: Int, in text: NSString) -> [RecognizerResult] {
        let (patternName, regex, baseScore) = compiled[index]
        let fullRange = NSRange(location: 0, length: text.length)
        let needsMatchedText = !denyList.isEmpty || !validators.isEmpty
        var results: [RecognizerResult] = []
        // enumerateMatches avoids bridging an NSArray of results on every call.
        regex.enumerateMatches(in: text as String, range: fullRange) { match, _, _ in
            guard let range = match?.range else { return }
            if needsMatchedText {
                let matched = text.substring(with: range)
                if denyList.contains(matched) || !validators.allSatisfy({ $0.validate(matched) }) {
                    return
                }
            }

            var score = baseScore
            if hasContext(text, range: range) {
                score = min(score + definition.contextScoreBoost, 1.0)
            }

            results.append(RecognizerResult(
                entityType: entity,
                start: range.location,
                end: NSMaxRange(range),
                score: score,
                recognizerName: patternName
            ))
        }
        return results
    }

    private func hasContext(_ text: NSString, range: NSRange) -> Bool {
        if lowercasedContextWords.isEmpty {
            return false
        }
        let windowStart = max(0, range.location - 100)
        let windowEnd = min(text.length, NSMaxRange(range) + 100)
        let window = text.substring(with: NSRange(location: windowStart, length: windowEnd - windowStart))
            .lowercased() as NSString
        return lowercasedContextWords.contains { containsWord(window, $0) }
    }
}

/// Scripts written without spaces between words: Thai, Lao, Myanmar, Khmer, Hangul (whose
/// particles join the word before), Japanese kana and CJK ideographs. A context word in
/// one matches anywhere, as there is no word edge to look for.
private func isUnspacedScript(_ c: UInt32) -> Bool {
    switch c {
    case 0x0E00...0x0EFF, 0x1000...0x109F, 0x1100...0x11FF, 0x1780...0x17FF,
         0x3040...0x30FF, 0x3130...0x318F, 0x31F0...0x31FF, 0x3400...0x4DBF,
         0x4E00...0x9FFF, 0xAC00...0xD7AF, 0xF900...0xFAFF, 0xFF66...0xFF9F,
         0x20000...0x3FFFF: true
    default: false
    }
}

/// Letters and digits make up a word; spaces, punctuation, `_` and `-` end one. As Rust's
/// `char::is_alphanumeric`: alphabetic, or a number of any kind.
private func isWordChar(_ scalar: Unicode.Scalar?) -> Bool {
    guard let scalar else { return false }
    return (scalar.properties.isAlphabetic || scalar.properties.numericType != nil) && !isUnspacedScript(scalar.value)
}

/// The scalar that ends just before UTF-16 index `i`, and the one that starts at it.
private func scalar(before i: Int, in s: NSString) -> Unicode.Scalar? {
    guard i > 0 else { return nil }
    let low = s.character(at: i - 1)
    if UTF16.isTrailSurrogate(low), i >= 2, case let high = s.character(at: i - 2), UTF16.isLeadSurrogate(high) {
        return Unicode.Scalar(UTF16.decode(UTF16.EncodedScalar([high, low])).value)
    }
    return Unicode.Scalar(low)
}
private func scalar(at i: Int, in s: NSString) -> Unicode.Scalar? {
    guard i < s.length else { return nil }
    let high = s.character(at: i)
    if UTF16.isLeadSurrogate(high), i + 1 < s.length, case let low = s.character(at: i + 1), UTF16.isTrailSurrogate(low) {
        return Unicode.Scalar(UTF16.decode(UTF16.EncodedScalar([high, low])).value)
    }
    return Unicode.Scalar(high)
}

/// Whether `word` occurs in `window` as a whole word: not inside a longer one, so "tel"
/// is not found in "hotel" nor "id" in "valid". An English plural counts as the word ("calls",
/// "accounts"), and an edge of the window as a word edge.
/// An empty word always matches, as with Rust's `str::contains("")`.
func containsWord(_ window: NSString, _ word: String) -> Bool {
    guard !word.isEmpty else { return true }
    let target = word as NSString
    let checkStart = isWordChar(scalar(at: 0, in: target)), checkEnd = isWordChar(scalar(before: target.length, in: target))
    let plural = scalar(before: target.length, in: target).map { $0.isASCII && $0.properties.isAlphabetic } ?? false
    var from = 0
    while from < window.length {
        let found = window.range(of: word, options: .literal, range: NSRange(location: from, length: window.length - from))
        guard found.location != NSNotFound else { return false }
        let startsWord = !checkStart || !isWordChar(scalar(before: found.location, in: window))
        var end = NSMaxRange(found)
        if plural, end < window.length, window.character(at: end) == UInt16(UInt8(ascii: "s")) { end += 1 }
        let endsWord = !checkEnd || !isWordChar(scalar(at: end, in: window))
        if startsWord && endsWord { return true }
        from = found.location + 1
    }
    return false
}

/// Copies `text` into an `NSString` with contiguous UTF-16 storage. Bridging a native (UTF-8)
/// `String` with `as NSString` makes ICU transcode it on every regex call, which roughly doubles
/// analysis time on non-ASCII text.
func utf16Backed(_ text: String) -> NSString {
    let units = Array(text.utf16)
    return units.withUnsafeBufferPointer { buffer in
        guard let base = buffer.baseAddress else { return "" as NSString }
        return NSString(characters: base, length: buffer.count)
    }
}

/// Rewrites `\b` / `\B` into explicit `\w` lookarounds.
///
/// ICU never reports a word boundary next to format characters (U+200B, U+00AD, U+200E, U+FEFF…)
/// or combining marks, and skips over them when looking back; Rust's `regex` treats them as plain
/// non-word characters. Text copied from web pages and PDFs is full of these, so with a bare `\b`
/// a trailing zero-width space hides an SSN from ICU. Both engines define `\w` the same way, so
/// the lookaround form makes ICU agree with Rust.
///
/// The general form `(?:(?<=\w)(?!\w)|(?<!\w)(?=\w))` defeats ICU's start-of-match optimizations
/// (~1.6x slower on the spec rules). When whatever follows `\b` always starts by consuming a word
/// character (`\b\d`, `\b[A-Z]?\d{8}`, `\b(?:[0-9a-f]{2}:){5}`), the boundary reduces to
/// `(?<!\w)`; when whatever precedes it always ends with one (`\d{4}\b`), to `(?!\w)`.
/// `optimize: false` always emits the general form.
func rewriteWordBoundaries(_ pattern: String, optimize: Bool = true) -> String {
    let boundary = #"(?:(?<=\w)(?!\w)|(?<!\w)(?=\w))"#
    let nonBoundary = #"(?:(?<=\w)(?=\w)|(?<!\w)(?!\w))"#
    let tokens = PatternToken.tokenize(Array(pattern))
    let shape = PatternShape(tokens)
    var out = ""
    for (i, token) in tokens.enumerated() {
        switch token.kind {
        case .boundary:
            let nextIsWord = optimize && shape.startsWithWord(from: i + 1)
            let prevIsWord = optimize && shape.endsWithWord(before: i)
            if nextIsWord && !prevIsWord {
                out += #"(?<!\w)"#
            } else if prevIsWord && !nextIsWord {
                out += #"(?!\w)"#
            } else {
                out += boundary
            }
        case .nonBoundary:
            out += nonBoundary
        default:
            out += token.text
        }
    }
    return out
}

/// Answers "does every match of the pattern at this point start (or end) with a word character?"
/// over a token list. Conservative: anything it does not understand answers `false`.
struct PatternShape {
    let tokens: [PatternToken]
    /// Matching open/close indices for capturing and non-capturing groups only.
    private var closeOf: [Int: Int] = [:]
    private var openOf: [Int: Int] = [:]

    init(_ tokens: [PatternToken]) {
        self.tokens = tokens
        var stack: [Int] = []
        for (i, t) in tokens.enumerated() {
            switch t.kind {
            case .groupOpen, .otherOpen:
                stack.append(i)
            case .groupClose:
                guard let open = stack.popLast() else { continue }
                if tokens[open].kind == .groupOpen {
                    closeOf[open] = i
                    openOf[i] = open
                }
            default:
                break
            }
        }
    }

    func startsWithWord(from start: Int) -> Bool {
        var j = start
        while j < tokens.count {
            switch tokens[j].kind {
            case .wordAtom:
                return true
            case .optionalWordAtom:
                j += 1
            case .groupOpen:
                guard let close = closeOf[j], alternatives(open: j, close: close).allSatisfy({ startsWithWord(in: $0) }) else {
                    return false
                }
                if tokens[close].minimum >= 1 {
                    return true
                }
                j = close + 1
            default:
                return false
            }
        }
        return false
    }

    func endsWithWord(before end: Int) -> Bool {
        var j = end - 1
        while j >= 0 {
            switch tokens[j].kind {
            case .wordAtom:
                return true
            case .optionalWordAtom:
                j -= 1
            case .groupClose:
                guard let open = openOf[j], alternatives(open: open, close: j).allSatisfy({ endsWithWord(in: $0) }) else {
                    return false
                }
                if tokens[j].minimum >= 1 {
                    return true
                }
                j = open - 1
            default:
                return false
            }
        }
        return false
    }

    private func startsWithWord(in range: Range<Int>) -> Bool {
        PatternShape(Array(tokens[range])).startsWithWord(from: 0)
    }

    private func endsWithWord(in range: Range<Int>) -> Bool {
        let sub = Array(tokens[range])
        return PatternShape(sub).endsWithWord(before: sub.count)
    }

    /// Token ranges of the top-level alternatives between a group's parentheses.
    private func alternatives(open: Int, close: Int) -> [Range<Int>] {
        var result: [Range<Int>] = []
        var depth = 0
        var lo = open + 1
        for j in (open + 1)..<close {
            switch tokens[j].kind {
            case .groupOpen, .otherOpen: depth += 1
            case .groupClose: depth -= 1
            case .alternation where depth == 0:
                result.append(lo..<j)
                lo = j + 1
            default: break
            }
        }
        result.append(lo..<close)
        return result
    }
}

/// A coarse ICU-pattern tokenizer: just enough to classify the atoms around a `\b`. Anything it
/// does not recognize is `.other`, which makes the rewrite fall back to the general form.
struct PatternToken {
    enum Kind {
        case boundary, nonBoundary
        /// Consumes one word character per repetition, at least once.
        case wordAtom
        /// Consumes one word character per repetition, possibly zero times.
        case optionalWordAtom
        /// `(` or `(?:` / `(?<name>`; `otherOpen` is a lookaround or inline-flag group.
        case groupOpen, otherOpen
        /// `)` plus its quantifier.
        case groupClose
        case alternation
        case other
    }

    let text: String
    let kind: Kind
    var minimum = 1

    static func tokenize(_ p: [Character]) -> [PatternToken] {
        var tokens: [PatternToken] = []
        var i = 0
        func take(_ n: Int) -> String {
            let end = min(i + n, p.count)
            defer { i = end }
            return String(p[i..<end])
        }
        while i < p.count {
            let c = p[i]
            var text: String
            var isWord = false
            var isClose = false
            switch c {
            case "\\":
                guard i + 1 < p.count else {
                    tokens.append(PatternToken(text: take(1), kind: .other))
                    continue
                }
                let d = p[i + 1]
                if d == "b" || d == "B" {
                    tokens.append(PatternToken(text: take(2), kind: d == "b" ? .boundary : .nonBoundary))
                    continue
                }
                if d == "Q" {
                    var j = i + 2
                    while j < p.count && !(p[j] == "\\" && j + 1 < p.count && p[j + 1] == "E") { j += 1 }
                    tokens.append(PatternToken(text: take(min(j + 2, p.count) - i), kind: .other))
                    continue
                }
                var j = i + 2
                if "pPxN".contains(d) && j < p.count && p[j] == "{" {
                    while j < p.count && p[j] != "}" { j += 1 }
                    j += 1
                }
                text = take(j - i)
                isWord = d == "d" || d == "w"
            case "[":
                var j = i + 1
                var depth = 1
                while j < p.count && depth > 0 {
                    if p[j] == "\\" { j += 2; continue }
                    if p[j] == "[" { depth += 1 } else if p[j] == "]" { depth -= 1 }
                    j += 1
                }
                let body = Array(p[(i + 1)..<max(i + 1, min(j, p.count) - 1)])
                text = take(j - i)
                isWord = classIsWord(body)
            case "(":
                var j = i + 1
                var kind = Kind.groupOpen
                if j < p.count && p[j] == "?" {
                    j += 1
                    if j < p.count && p[j] == ":" {
                        j += 1
                    } else if j < p.count && "=!>".contains(p[j]) {
                        j += 1
                        kind = .otherOpen
                    } else if j < p.count && p[j] == "<" {
                        j += 1
                        if j < p.count && "=!".contains(p[j]) {
                            j += 1
                            kind = .otherOpen
                        } else {
                            while j < p.count && p[j] != ">" { j += 1 }
                            j += 1
                        }
                    } else {
                        // Inline flags: "(?i)" stands alone, "(?i:" opens a group.
                        while j < p.count && p[j] != ":" && p[j] != ")" { j += 1 }
                        kind = j < p.count && p[j] == ":" ? .otherOpen : .other
                        j += 1
                    }
                }
                tokens.append(PatternToken(text: take(j - i), kind: kind))
                continue
            case ")":
                text = take(1)
                isClose = true
            case ".":
                text = take(1)
            case "|":
                tokens.append(PatternToken(text: take(1), kind: .alternation))
                continue
            case "^", "$":
                tokens.append(PatternToken(text: take(1), kind: .other))
                continue
            default:
                text = take(1)
                isWord = c.isASCII && (c.isLetter || c.isNumber || c == "_")
            }

            var minimum = 1
            var quantified = false
            if i < p.count && "?*+".contains(p[i]) {
                if p[i] != "+" { minimum = 0 }
                text += take(1)
                quantified = true
            } else if i < p.count && p[i] == "{",
                      let close = p[i...].firstIndex(of: "}"),
                      let lower = Int(String(p[(i + 1)..<close].prefix { $0 != "," })) {
                minimum = lower
                text += take(close + 1 - i)
                quantified = true
            }
            if quantified && i < p.count && (p[i] == "?" || p[i] == "+") {
                text += take(1)  // lazy / possessive suffix
            }
            let kind: Kind = isClose ? .groupClose : isWord ? (minimum >= 1 ? .wordAtom : .optionalWordAtom) : .other
            tokens.append(PatternToken(text: text, kind: kind, minimum: minimum))
        }
        return tokens
    }

    /// True if every member of the bracket expression is an ASCII letter, digit, `_`, `\d` or `\w`.
    private static func classIsWord(_ body: [Character]) -> Bool {
        if body.isEmpty || body[0] == "^" {
            return false
        }
        func isWordChar(_ c: Character) -> Bool { c.isASCII && (c.isLetter || c.isNumber || c == "_") }
        func sameRun(_ a: Character, _ b: Character) -> Bool {
            for run in [("0", "9"), ("A", "Z"), ("a", "z")] as [(Character, Character)]
            where (run.0...run.1).contains(a) && (run.0...run.1).contains(b) {
                return a <= b
            }
            return false
        }
        var j = 0
        while j < body.count {
            let c = body[j]
            if c == "\\" {
                guard j + 1 < body.count, body[j + 1] == "d" || body[j + 1] == "w" else { return false }
                j += 2
            } else if j + 2 < body.count && body[j + 1] == "-" {
                guard sameRun(c, body[j + 2]) else { return false }
                j += 3
            } else {
                guard isWordChar(c) else { return false }
                j += 1
            }
        }
        return true
    }
}
