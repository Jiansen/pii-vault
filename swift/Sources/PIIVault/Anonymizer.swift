import Foundation

public enum HashType: Sendable, Hashable {
    case fnv
}

public enum Operator: Sendable, Hashable {
    /// Replace with `newValue`, or `<ENTITY_TYPE>` when `newValue` is empty.
    case replace(newValue: String = "")
    case mask(maskingChar: Character, charsToMask: Int, fromEnd: Bool)
    /// 32-bit FNV-1a of the UTF-8 bytes, as 8 lower-case hex digits.
    case hash(HashType = .fnv)
    case redact
    /// Reversible token from the ``Vault`` passed to ``Anonymizer/anonymize(_:entities:operators:defaultOperator:vault:)``;
    /// falls back to `<ENTITY_TYPE>` when no vault is given.
    case vault

    public static let `default` = Operator.replace()
}

public struct AnonymizedItem: Hashable, Sendable {
    public let entityType: String
    /// UTF-16 offsets into the original text.
    public let start: Int
    public let end: Int
    public let original: String
    public let replacement: String
}

public struct AnonymizedResult: Hashable, Sendable {
    public let text: String
    /// Applied replacements, in text order.
    public let items: [AnonymizedItem]
}

public enum Anonymizer {
    /// Replaces each entity in `text` according to `operators[entity.entityType]` (or
    /// `defaultOperator`).
    ///
    /// Entities that partially overlap (the analyzer keeps those) are replaced as one span
    /// covering all of them, using the operator of the highest-scoring entity in the group
    /// (earliest, then longest, on a tie). Rust splices each one with stale offsets instead, and
    /// replacing only one of them would leave the rest of the other in clear text.
    /// Entities whose offsets fall outside `text` are ignored.
    public static func anonymize(
        _ text: String,
        entities: [RecognizerResult],
        operators: [EntityType: Operator] = [:],
        defaultOperator: Operator = .default,
        vault: Vault? = nil
    ) -> AnonymizedResult {
        let source = text as NSString
        // (winner, span) per group of overlapping entities, in text order.
        var groups: [(winner: RecognizerResult, start: Int, end: Int)] = []
        for entity in entities.sorted(by: { $0.start != $1.start ? $0.start < $1.start : $0.end > $1.end }) {
            guard entity.start >= 0, entity.start <= entity.end, entity.end <= source.length else {
                continue
            }
            if let last = groups.last, entity.start < last.end {
                let winner = entity.score > last.winner.score ? entity : last.winner
                groups[groups.count - 1] = (winner, last.start, max(last.end, entity.end))
            } else {
                groups.append((entity, entity.start, entity.end))
            }
        }

        let result = NSMutableString(string: source)
        var items: [AnonymizedItem] = []
        for (entity, start, end) in groups.reversed() {
            let range = NSRange(location: start, length: end - start)
            let original = source.substring(with: range)
            let op = operators[entity.entityType] ?? defaultOperator

            let replacement: String
            switch op {
            case let .replace(newValue):
                replacement = newValue.isEmpty ? "<\(entity.entityType)>" : newValue
            case let .mask(maskingChar, charsToMask, fromEnd):
                replacement = mask(original, with: maskingChar, count: charsToMask, fromEnd: fromEnd)
            case .hash:
                replacement = String(format: "%08x", fnv1a32(original))
            case .redact:
                replacement = ""
            case .vault:
                replacement = vault?.tokenize(category: entity.entityType.name, original: original)
                    ?? "<\(entity.entityType)>"
            }

            items.append(AnonymizedItem(
                entityType: entity.entityType.name,
                start: start,
                end: end,
                original: original,
                replacement: replacement
            ))
            result.replaceCharacters(in: range, with: replacement)
        }

        return AnonymizedResult(text: result as String, items: items.reversed())
    }

    /// Masks grapheme clusters (Rust masks Unicode scalars; identical for the ASCII the spec
    /// patterns match).
    private static func mask(_ text: String, with maskChar: Character, count: Int, fromEnd: Bool) -> String {
        var chars = Array(text)
        let toMask = min(max(count, 0), chars.count)
        let indices = fromEnd ? (chars.count - toMask)..<chars.count : 0..<toMask
        for i in indices {
            chars[i] = maskChar
        }
        return String(chars)
    }
}

/// 32-bit FNV-1a over the UTF-8 bytes of `s` (same as the Rust implementation).
func fnv1a32(_ s: String) -> UInt32 {
    s.utf8.reduce(0x811c_9dc5 as UInt32) { ($0 ^ UInt32($1)) &* 0x0100_0193 }
}
