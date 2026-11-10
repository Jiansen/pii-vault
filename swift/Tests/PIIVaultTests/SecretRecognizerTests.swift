import Foundation
import Testing
@testable import PIIVault

/// The API-key / token rules ported from detect-secrets (spec/recognizers/*, see each file's
/// `note`). Fake values are assembled at runtime so no literal token-shaped string sits in the
/// source for secret scanners to flag.
@Suite struct SecretRecognizerTests {
    private static func fake(_ count: Int, _ alphabet: String = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") -> String {
        var rng = SplitMix64(seed: UInt64(count) &* 31 &+ UInt64(alphabet.count))
        let chars = Array(alphabet)
        return String((0..<count).map { _ in chars.randomElement(using: &rng)! })
    }

    private static let hex = "0123456789abcdef"
    private static let upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    private static let lower = "abcdefghijklmnopqrstuvwxyz0123456789"
    private static let b64 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"

    struct Case: CustomTestStringConvertible, Sendable {
        let type: String
        let text: String
        /// The detection of `type` must cover exactly this substring.
        let span: String
        var testDescription: String { type }
    }

    static let cases: [Case] = {
        let ghToken = "gh" + "p_" + fake(36)
        let awsID = "AK" + "IA" + fake(16, upper)
        let awsSecret = "aws_secret_access_key = \"" + fake(40, b64) + "\""
        let azure = "Account" + "Key=" + fake(86, b64) + "=="
        let cloudantURL = "https://acct-1:" + fake(64, hex) + "@acct-1.cloudant.com"
        let discord = "M" + fake(23) + "." + fake(6) + "." + fake(27)
        let gitlab = "gl" + "pat-" + fake(20)
        let iam = "ibm_cloud_iam_api_key = \"" + fake(44) + "\""
        let cos = "cos_hmac_secret_access_key: " + fake(48, hex)
        let jwt = "ey" + "JhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0." + fake(43)
        let mailchimp = fake(32, lower) + "-us12"
        let npm = "//registry.npmjs.org/:_auth" + "Token=npm_" + fake(36)
        let openAI = "sk-" + "proj-" + fake(20) + "T3Blbk" + "FJ" + fake(20)
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIE" + fake(60) + "\n" + fake(64) + "\n-----END RSA PRIVATE KEY-----"
        let pypi = "py" + "pi-AgEIcHlwaS5vcmc" + fake(80)
        let sendgrid = "S" + "G." + fake(22) + "." + fake(43)
        let slack = "xo" + "xb-123456789012-1234567890123-" + fake(24, lower)
        let webhook = "https://hooks.slack.com/services/T" + fake(8, upper) + "/B" + fake(8, upper) + "/" + fake(24)
        let softlayer = "softlayer_api_key = " + fake(64, lower)
        let square = "sq0" + "csp-" + fake(43)
        let stripe = "sk" + "_live_" + fake(99)
        let telegram = "123456789:" + fake(35)
        let twilio = "A" + "C" + fake(32, hex)
        return [
            Case(type: "ARTIFACTORY_CREDENTIAL", text: "X-JFrog-Art-Api: AKC" + fake(70), span: "AKC" + fake(70)),
            Case(type: "AWS_ACCESS_KEY_ID", text: "id \(awsID) here", span: awsID),
            Case(type: "AWS_SECRET_ACCESS_KEY", text: awsSecret, span: awsSecret),
            Case(type: "AZURE_STORAGE_KEY", text: "AccountName=a;\(azure);EndpointSuffix=core.windows.net", span: azure),
            Case(type: "BASIC_AUTH_CREDENTIAL", text: "postgres://admin:s3cr3t@db.example.com/app", span: "://admin:s3cr3t@"),
            Case(type: "CLOUDANT_CREDENTIAL", text: cloudantURL + "/db", span: cloudantURL),
            Case(type: "DISCORD_BOT_TOKEN", text: "token: " + discord, span: discord),
            Case(type: "GITHUB_TOKEN", text: "export GITHUB_TOKEN=" + ghToken, span: ghToken),
            Case(type: "GITLAB_TOKEN", text: gitlab + " ", span: gitlab),
            Case(type: "IBM_CLOUD_IAM_KEY", text: iam, span: iam),
            Case(type: "IBM_COS_HMAC_KEY", text: cos, span: cos),
            Case(type: "JWT", text: "Authorization: Bearer " + jwt, span: jwt),
            Case(type: "MAILCHIMP_API_KEY", text: "key " + mailchimp, span: mailchimp),
            Case(type: "NPM_TOKEN", text: npm, span: npm),
            Case(type: "OPENAI_API_KEY", text: "OPENAI_API_KEY=" + openAI, span: openAI),
            Case(type: "PRIVATE_KEY", text: "key:\n" + pem + "\nend", span: pem),
            Case(type: "PYPI_TOKEN", text: pypi, span: pypi),
            Case(type: "SENDGRID_API_KEY", text: sendgrid, span: sendgrid),
            Case(type: "SLACK_TOKEN", text: "SLACK=" + slack, span: slack),
            Case(type: "SLACK_TOKEN", text: webhook, span: webhook),
            Case(type: "SOFTLAYER_API_KEY", text: softlayer, span: softlayer),
            Case(type: "SQUARE_OAUTH_SECRET", text: square, span: square),
            Case(type: "STRIPE_API_KEY", text: "key=" + stripe, span: stripe),
            Case(type: "TELEGRAM_BOT_TOKEN", text: "bot " + telegram, span: telegram),
            Case(type: "TWILIO_API_KEY", text: "twilio " + twilio, span: twilio),
        ]
    }()

    @Test(arguments: cases)
    func detectsAndCoversTheWholeSecret(_ c: Case) {
        let found = specAnalyzer.analyze(c.text).entities.filter { $0.entityType.name == c.type }
        #expect(found.map { $0.text(in: c.text) } == [c.span])
        // Whatever else fires, the redacted ranges must hide the whole secret.
        let redacted = specAnalyzer.analyze(c.text).redactionRanges
        let spanRange = (c.text as NSString).range(of: c.span)
        #expect(redacted.contains { NSIntersectionRange($0, spanRange) == spanRange })
    }

    @Test func truncatedPrivateKeyHeaderStillFlagged() {
        let text = "-----BEGIN OPENSSH " + "PRIVATE KEY-----\nb3BlbnNzaC1rZXk"
        let found = entities(specAnalyzer.analyze(text), ofType: "PRIVATE_KEY")
        #expect(found.map { $0.text(in: text) } == ["BEGIN OPENSSH PRIVATE KEY"])
    }

    @Test(arguments: [
        "AKIA123 is too short",
        "gh" + "p_short_token",
        "sk" + "_test_" + "abcdefghijklmnopqrstuvwx",   // test-mode Stripe key: not covered
        "gl" + "pat-tooshort",
        "The weather is nice today, see https://example.com/page",
        "eyJ alone is not a token",
    ])
    func ignoresLookalikes(_ text: String) {
        let secretTypes = Set(Self.cases.map(\.type))
        #expect(!specAnalyzer.analyze(text).entities.contains { secretTypes.contains($0.entityType.name) })
    }

    @Test func everySecretRuleHasANoteAndSource() throws {
        let types = Set(Self.cases.map(\.type))
        let definitions = try FileManager.default.contentsOfDirectory(at: specRecognizersDir, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "json" }
            .flatMap { try RecognizerLoader.definitions(from: Data(contentsOf: $0)) }
            .filter { types.contains($0.entityType) }
        #expect(Set(definitions.map(\.entityType)) == types)
        let raw = try FileManager.default.contentsOfDirectory(at: specRecognizersDir, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "json" }
            .compactMap { try JSONSerialization.jsonObject(with: Data(contentsOf: $0)) as? [String: Any] }
            .filter { types.contains($0["entity_type"] as? String ?? "") }
        #expect(raw.count == types.count)
        #expect(raw.allSatisfy { ($0["note"] as? String)?.contains("detect-secrets") == true })
    }
}
