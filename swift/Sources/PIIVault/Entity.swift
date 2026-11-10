import Foundation

/// An upper-cased PII entity name such as `EMAIL_ADDRESS` or `CN_ID_CARD`.
public struct EntityType: Hashable, Sendable, Codable, CustomStringConvertible, ExpressibleByStringLiteral {
    public let name: String

    public init(_ name: String) {
        self.name = name.uppercased()
    }

    public init(stringLiteral value: String) {
        self.init(value)
    }

    public init(from decoder: Decoder) throws {
        self.init(try decoder.singleValueContainer().decode(String.self))
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(name)
    }

    public var description: String { name }
}

extension EntityType {
    public static let emailAddress: EntityType = "EMAIL_ADDRESS"
    public static let phoneNumber: EntityType = "PHONE_NUMBER"
    public static let creditCard: EntityType = "CREDIT_CARD"
    public static let crypto: EntityType = "CRYPTO"
    public static let ipAddress: EntityType = "IP_ADDRESS"
    public static let macAddress: EntityType = "MAC_ADDRESS"
    public static let ibanCode: EntityType = "IBAN_CODE"
    public static let url: EntityType = "URL"
    public static let uuid: EntityType = "UUID"
    public static let usSSN: EntityType = "US_SSN"
    public static let usITIN: EntityType = "US_ITIN"
    public static let cnIDCard: EntityType = "CN_ID_CARD"
    public static let cnPhone: EntityType = "CN_PHONE"
    public static let ukNHS: EntityType = "UK_NHS"
    public static let ukNINO: EntityType = "UK_NINO"
}

/// A single detection.
///
/// `start` and `end` are UTF-16 offsets into the analyzed string, so they map directly onto
/// `NSRange` / `NSString` / `NSAttributedString` (and match the TypeScript implementation).
/// Use ``range(in:)`` to get a `Range<String.Index>`.
public struct RecognizerResult: Hashable, Sendable, Codable {
    public let entityType: EntityType
    public let start: Int
    public let end: Int
    public let score: Double
    public let recognizerName: String?

    public init(entityType: EntityType, start: Int, end: Int, score: Double, recognizerName: String? = nil) {
        self.entityType = entityType
        self.start = start
        self.end = end
        self.score = score
        self.recognizerName = recognizerName
    }

    enum CodingKeys: String, CodingKey {
        case entityType = "entity_type"
        case start, end, score
        case recognizerName = "recognizer_name"
    }

    public var nsRange: NSRange { NSRange(location: start, length: end - start) }

    /// The matched range as `String` indices, or `nil` if the offsets do not fall on
    /// character boundaries of `input`.
    public func range(in input: String) -> Range<String.Index>? {
        Range(nsRange, in: input)
    }

    /// The matched substring of `input`, or `nil` if the offsets fall outside it (e.g. the text
    /// was edited after analysis).
    public func text(in input: String) -> String? {
        let ns = input as NSString
        guard start >= 0, start <= end, end <= ns.length else { return nil }
        return ns.substring(with: nsRange)
    }

    public func overlaps(_ other: RecognizerResult) -> Bool {
        start < other.end && other.start < end
    }
}
