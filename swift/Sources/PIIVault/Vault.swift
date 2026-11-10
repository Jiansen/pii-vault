import Foundation

public struct VaultEntry: Hashable, Sendable, Codable {
    public let token: String
    public let original: String
    public let category: String
    public let context: String
    public let createdAt: String
    public internal(set) var lastUsed: String
    public internal(set) var useCount: Int

    enum CodingKeys: String, CodingKey {
        case token, original, category, context
        case createdAt = "created_at"
        case lastUsed = "last_used"
        case useCount = "use_count"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        token = try c.decode(String.self, forKey: .token)
        original = try c.decode(String.self, forKey: .original)
        category = try c.decode(String.self, forKey: .category)
        context = try c.decodeIfPresent(String.self, forKey: .context) ?? ""
        createdAt = try c.decode(String.self, forKey: .createdAt)
        lastUsed = try c.decode(String.self, forKey: .lastUsed)
        useCount = try c.decode(Int.self, forKey: .useCount)
    }

    init(token: String, original: String, category: String, context: String, now: String) {
        self.token = token
        self.original = original
        self.category = category
        self.context = context
        self.createdAt = now
        self.lastUsed = now
        self.useCount = 1
    }
}

/// Deterministic, reversible tokenization: the same (category, original, context) always maps to
/// the same `[CATEGORY:xxxxxxxx]` token within one vault, and tokens are salted per vault.
///
/// The JSON format (snake_case, `version: 2`, 32-hex `salt`) is the one the Rust implementation
/// reads and writes. Not thread-safe; confine a vault to one actor/queue.
public final class Vault: Codable {
    public private(set) var version: Int
    public private(set) var salt: String
    public private(set) var entries: [VaultEntry]
    private var index: [Key: Int] = [:]
    private var tokens: [[UInt8]: Int] = [:]

    /// Keys compare UTF-8 bytes, as in Rust. `String` equality uses canonical equivalence, which
    /// would map "Jos\u{E9}" and "Jose\u{301}" to one entry and detokenize one as the other.
    private struct Key: Hashable {
        let category: [UInt8]
        let original: [UInt8]
        let context: [UInt8]

        init(_ category: String, _ original: String, _ context: String) {
            self.category = Array(category.utf8)
            self.original = Array(original.utf8)
            self.context = Array(context.utf8)
        }
    }

    enum CodingKeys: String, CodingKey {
        case version, salt, entries
    }

    public init() {
        version = 2
        salt = Self.generateSalt()
        entries = []
    }

    public required init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        version = try c.decode(Int.self, forKey: .version)
        salt = try c.decodeIfPresent(String.self, forKey: .salt) ?? ""
        entries = try c.decode([VaultEntry].self, forKey: .entries)
        if version < 2 || salt.isEmpty {
            // v1 vault: generate a new salt; old entries retain their original tokens
            salt = Self.generateSalt()
            version = 2
        }
        rebuildIndex()
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(version, forKey: .version)
        try c.encode(salt, forKey: .salt)
        try c.encode(entries, forKey: .entries)
    }

    public static func fromJSON(_ json: String) throws -> Vault {
        try JSONDecoder().decode(Vault.self, from: Data(json.utf8))
    }

    public func toJSON() throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .withoutEscapingSlashes]
        return String(decoding: try encoder.encode(self), as: UTF8.self)
    }

    public var entryCount: Int { entries.count }

    @discardableResult
    public func tokenize(category: String, original: String) -> String {
        tokenize(category: category, original: original, context: "")
    }

    @discardableResult
    public func tokenize(category: String, original: String, context: String) -> String {
        let key = Key(category, original, context)
        let now = Self.utcNow()

        if let idx = index[key] {
            entries[idx].lastUsed = now
            entries[idx].useCount &+= 1
            return entries[idx].token
        }

        let hashInput = context.isEmpty
            ? "\(salt):\(category):\(original)"
            : "\(salt):\(category):\(original):\(context)"
        var token = Self.stableToken(category: category, input: hashInput)

        // Any existing holder of this token is a different (original, context) — the exact
        // match was handled above — so rehash until the token is free.
        var attempt = 0
        while tokens[Array(token.utf8)] != nil {
            attempt += 1
            token = Self.stableToken(category: category, input: "\(salt):\(category):\(original):\(context):\(attempt)")
        }

        entries.append(VaultEntry(token: token, original: original, category: category, context: context, now: now))
        index[key] = entries.count - 1
        tokens[Array(token.utf8)] = entries.count - 1
        return token
    }

    /// Replaces every token in `text` with its original value (longest tokens first).
    public func detokenize(_ text: String) -> String {
        var result = text
        for entry in entries.enumerated().sorted(by: { lhs, rhs in
            lhs.element.token.count != rhs.element.token.count
                ? lhs.element.token.count > rhs.element.token.count
                : lhs.offset < rhs.offset
        }).map(\.element) {
            result = result.replacingOccurrences(of: entry.token, with: entry.original, options: .literal)
        }
        return result
    }

    public func lookupToken(_ token: String) -> VaultEntry? {
        tokens[Array(token.utf8)].map { entries[$0] }
    }

    private func rebuildIndex() {
        index.removeAll()
        tokens.removeAll()
        for (i, entry) in entries.enumerated() {
            index[Key(entry.category, entry.original, entry.context)] = i
            tokens[Array(entry.token.utf8)] = tokens[Array(entry.token.utf8)] ?? i
        }
    }

    private static func generateSalt() -> String {
        var rng = SystemRandomNumberGenerator()
        return (0..<16).map { _ in String(format: "%02x", UInt8.random(in: .min ... .max, using: &rng)) }.joined()
    }

    private static func stableToken(category: String, input: String) -> String {
        "[\(category.uppercased()):\(String(format: "%08x", fnv1a32(input)))]"
    }

    private static func utcNow() -> String {
        Date().formatted(.iso8601)
    }
}
