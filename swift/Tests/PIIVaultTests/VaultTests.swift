import Foundation
import Testing
@testable import PIIVault

private let v1JSON = #"""
{
    "version": 1,
    "entries": [{
        "token": "[PERSON:e702]",
        "original": "Zhang Wei",
        "category": "person",
        "context": "",
        "created_at": "2026-04-01T00:00:00Z",
        "last_used": "2026-04-01T00:00:00Z",
        "use_count": 1
    }]
}
"""#

@Suite struct VaultTests {
    @Test func tokenizeIsDeterministic() {
        let vault = Vault()
        let t1 = vault.tokenize(category: "email_address", original: "test@example.com")
        let t2 = vault.tokenize(category: "email_address", original: "test@example.com")
        #expect(t1 == t2)
        #expect(vault.entryCount == 1)
        #expect(vault.entries[0].useCount == 2)
    }

    @Test func differentOriginalsGetDifferentTokens() {
        let vault = Vault()
        let t1 = vault.tokenize(category: "email_address", original: "alice@example.com")
        let t2 = vault.tokenize(category: "email_address", original: "bob@example.com")
        #expect(t1 != t2)
        #expect(vault.entryCount == 2)
    }

    @Test func contextDisambiguates() {
        let vault = Vault()
        let t1 = vault.tokenize(category: "person", original: "Zhang San", context: "customer")
        let t2 = vault.tokenize(category: "person", original: "Zhang San", context: "colleague")
        #expect(t1 != t2)
    }

    @Test func detokenize() {
        let vault = Vault()
        let token = vault.tokenize(category: "email_address", original: "test@example.com")
        #expect(vault.detokenize("Contact \(token)") == "Contact test@example.com")
    }

    @Test func jsonRoundtrip() throws {
        let vault = Vault()
        vault.tokenize(category: "email_address", original: "test@example.com")
        vault.tokenize(category: "phone_number", original: "555-1234")
        let loaded = try Vault.fromJSON(try vault.toJSON())
        #expect(loaded.entryCount == 2)
        #expect(loaded.entries[0].original == "test@example.com")
    }

    @Test func tokenFormatIs8Hex() throws {
        let token = Vault().tokenize(category: "email_address", original: "test@example.com")
        let regex = try NSRegularExpression(pattern: #"^\[EMAIL_ADDRESS:[0-9a-f]{8}\]$"#)
        #expect(regex.firstMatch(in: token, range: NSRange(location: 0, length: (token as NSString).length)) != nil)
    }

    @Test func lookupToken() {
        let vault = Vault()
        let token = vault.tokenize(category: "email_address", original: "test@example.com")
        #expect(vault.lookupToken(token)?.original == "test@example.com")
        #expect(vault.lookupToken("[EMAIL_ADDRESS:00000000]") == nil)
    }

    @Test func useCountIncrements() {
        let vault = Vault()
        for _ in 0..<3 {
            vault.tokenize(category: "email_address", original: "test@example.com")
        }
        let token = vault.tokenize(category: "email_address", original: "test@example.com")
        #expect(vault.lookupToken(token)?.useCount == 4)
    }

    @Test func differentVaultsProduceDifferentTokens() {
        let t1 = Vault().tokenize(category: "person", original: "Zhang Wei")
        let t2 = Vault().tokenize(category: "person", original: "Zhang Wei")
        #expect(t1 != t2, "salt isolation")
    }

    @Test func jsonRoundtripPreservesSalt() throws {
        let vault = Vault()
        let token = vault.tokenize(category: "person", original: "Alice")
        let loaded = try Vault.fromJSON(try vault.toJSON())
        #expect(loaded.tokenize(category: "person", original: "Alice") == token)
        #expect(loaded.entryCount == 1)
    }

    @Test func toJSONWritesVersion2WithSalt() throws {
        let vault = Vault()
        vault.tokenize(category: "email_address", original: "a@b.com")
        let data = try JSONSerialization.jsonObject(with: Data(try vault.toJSON().utf8)) as? [String: Any]
        #expect(data?["version"] as? Int == 2)
        #expect((data?["salt"] as? String)?.count == 32)
        // Same snake_case entry keys as the Rust implementation.
        let entry = (data?["entries"] as? [[String: Any]])?.first
        #expect(Set(entry?.keys.map { $0 } ?? []) == ["token", "original", "category", "context", "created_at", "last_used", "use_count"])
    }

    @Test func v1VaultBackwardCompat() throws {
        let vault = try Vault.fromJSON(v1JSON)
        #expect(vault.entryCount == 1)
        #expect(vault.version == 2)
        #expect(vault.salt.count == 32)
        #expect(vault.lookupToken("[PERSON:e702]")?.original == "Zhang Wei")
        #expect(vault.detokenize("Hello [PERSON:e702]") == "Hello Zhang Wei")
    }

    @Test func newTokensInLoadedV1VaultUse8Hex() throws {
        let vault = try Vault.fromJSON(v1JSON)
        let token = vault.tokenize(category: "person", original: "Li Na")
        #expect(token.hasPrefix("[PERSON:") && token.count == "[PERSON:".count + 9)
        #expect(vault.entryCount == 2)
        // Existing entry keeps its legacy token.
        #expect(vault.tokenize(category: "person", original: "Zhang Wei") == "[PERSON:e702]")
    }

    @Test func canonicallyEquivalentOriginalsStayDistinct() {
        let vault = Vault()
        let composed = "Jos\u{E9}", decomposed = "Jose\u{301}"
        let t1 = vault.tokenize(category: "person", original: composed)
        let t2 = vault.tokenize(category: "person", original: decomposed)
        #expect(t1 != t2)
        #expect(vault.entryCount == 2)
        #expect(Array(vault.detokenize(t2).unicodeScalars) == Array(decomposed.unicodeScalars))
    }

    @Test func hugeUseCountDoesNotTrap() throws {
        let json = #"""
        {"version": 2, "salt": "00000000000000000000000000000000", "entries": [
          {"token": "[P:1]", "original": "x", "category": "p", "context": "", "created_at": "", "last_used": "", "use_count": 9223372036854775807}
        ]}
        """#
        let vault = try Vault.fromJSON(json)
        #expect(vault.tokenize(category: "p", original: "x") == "[P:1]")
    }

    @Test func detokenizeLongestTokenFirst() throws {
        let json = #"""
        {"version": 2, "salt": "00000000000000000000000000000000", "entries": [
          {"token": "[P:1]", "original": "short", "category": "p", "context": "", "created_at": "", "last_used": "", "use_count": 1},
          {"token": "[P:1]x", "original": "long", "category": "p", "context": "x", "created_at": "", "last_used": "", "use_count": 1}
        ]}
        """#
        #expect(try Vault.fromJSON(json).detokenize("[P:1]x [P:1]") == "long short")
    }
}
