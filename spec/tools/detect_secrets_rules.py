"""Generate spec/recognizers/*.json for the API-key / token rules ported from detect-secrets
(https://github.com/Yelp/detect-secrets, Apache-2.0, detect_secrets/plugins/*.py).

    python3 spec/tools/detect_secrets_rules.py            # rewrites the 24 files in spec/recognizers

Edit the rules here, not in the generated JSON: case-insensitive parts are expanded by ci().

Patterns must work in Rust `regex`, ICU (Swift) and JavaScript at once: no lookaround, no
backreferences, no inline flags. Case-insensitive parts are spelled out as [Aa] classes.
"""
import json
import sys
from pathlib import Path

OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "recognizers"
SRC = "detect-secrets (Apache-2.0) detect_secrets/plugins/"


def ci(word):
    """Case-insensitive literal: 'aws' -> '[Aa][Ww][Ss]'; non-letters escaped as needed."""
    out = []
    for c in word:
        if c.isalpha():
            out.append(f"[{c.upper()}{c.lower()}]")
        elif c in ".+*?()[]{}|^$\\":
            out.append("\\" + c)
        else:
            out.append(c)
    return "".join(out)


def alt(*words):
    return "(?:" + "|".join(ci(w) for w in words) + ")"


# build_assignment_regex from detect_secrets/plugins/base.py, minus the `(?<=\W)|(?<=^)`
# lookbehind (replaced by \b before the keyword; the optional [ and quote before it are left out
# of the match) and with IGNORECASE expanded by hand.
def assignment(prefix, keyword, secret):
    return (
        r"\b" + prefix + r"(?:_|\-|)" + keyword
        + r"(?:\"|'|)(?:\]|)(?: *)(?:=|:|:=|=>| +|::)(?: *)(?:\"|'|)" + secret + r"(?:\"|'|)"
    )


KEY_OR_PASS = alt("key", "pwd", "password", "pass", "token")
TOKEN_CHARS = r"[A-Za-z0-9_\-]"

rules = []


def rule(file, name, entity, note, patterns, context, boost=0.15, validators=None):
    d = {
        "name": name,
        "entity_type": entity,
        "version": "1.0.0",
        "note": note,
        "patterns": [{"name": n, "regex": r, "score": s} for n, r, s in patterns],
        "context_words": context,
        "context_score_boost": boost,
    }
    if validators:
        d["validators"] = validators
    d["supported_languages"] = None
    rules.append((file, d))


rule("artifactory_credential.json", "artifactory_credential_recognizer", "ARTIFACTORY_CREDENTIAL",
     "JFrog Artifactory API token (AKC…) and encrypted password (AP…). Source: " + SRC + "artifactory.py. "
     "The original requires whitespace/=/:/\" around the value; here \\b is used instead. The password "
     "form (AP + hex digit/A-F + 8+ alphanumerics) is generic, so it scores low unless 'artifactory' or "
     "'jfrog' appears nearby.",
     [("artifactory_api_token", r"\bAKC[a-zA-Z0-9]{10,}\b", 0.7),
      ("artifactory_password", r"\bAP[0-9ABCDEF][a-zA-Z0-9]{8,}\b", 0.3)],
     ["artifactory", "jfrog", "x-jfrog-art-api", "api key", "password"], 0.4)

rule("aws_access_key_id.json", "aws_access_key_id_recognizer", "AWS_ACCESS_KEY_ID",
     "AWS access key ID: 4-character prefix (AKIA long-term, ASIA temporary STS, ABIA, ACCA, A3T*) + 16 "
     "uppercase alphanumerics. Source: " + SRC + "aws.py (pattern 1). \\b added on both sides because real "
     "key IDs are exactly 20 characters. The key ID alone cannot sign requests; pair it with "
     "AWS_SECRET_ACCESS_KEY.",
     [("aws_access_key_id", r"\b(?:A3T[A-Z0-9]|ABIA|ACCA|AKIA|ASIA)[0-9A-Z]{16}\b", 0.9)],
     ["aws", "access key", "access_key_id", "aws_access_key_id", "iam"])

rule("aws_secret_access_key.json", "aws_secret_access_key_recognizer", "AWS_SECRET_ACCESS_KEY",
     "AWS secret access key (40 base64 characters) assigned near an 'aws' + key/password/token keyword, "
     "e.g. aws_secret_access_key = \"…\". Source: " + SRC + "aws.py (pattern 2, case-insensitive). The match "
     "spans from 'aws' to the closing quote, so the variable name is redacted too. Bare 40-character "
     "strings without the keyword are not detected.",
     [("aws_secret_assignment",
       ci("aws") + r".{0,20}?" + alt("key", "pwd", "pw", "password", "pass", "token")
       + r".{0,20}?['\"][0-9a-zA-Z/+]{40}['\"]", 0.85)],
     ["aws", "secret", "secret_access_key"])

rule("azure_storage_key.json", "azure_storage_key_recognizer", "AZURE_STORAGE_KEY",
     "Azure Storage account access key inside a connection string (AccountKey= followed by 88 base64 "
     "characters). Source: " + SRC + "azure_storage_key.py. The match includes the 'AccountKey=' prefix.",
     [("azure_account_key", r"AccountKey=[a-zA-Z0-9+/=]{88}", 0.95)],
     ["azure", "storage", "connection string", "DefaultEndpointsProtocol"])

URI_FORBIDDEN = r"""[^:/?#\[\]@!$&'()*+,;=\s]"""
rule("basic_auth_credential.json", "basic_auth_credential_recognizer", "BASIC_AUTH_CREDENTIAL",
     "user:password embedded in a URI (scheme://user:password@host). Source: " + SRC + "basic_auth.py. "
     "The original captures only the password; this match covers '://user:password@' so both the "
     "username and password are redacted. Overlaps the URL recognizer, which still covers the whole URL.",
     [("uri_userinfo", "://" + URI_FORBIDDEN + "+:" + URI_FORBIDDEN + "+@", 0.8)],
     ["password", "credentials", "login", "connection"])

CL = alt("cloudant", "cl", "clou")
CL_KEY = r"(?:" + ci("api") + r"|)" + KEY_OR_PASS
CL_URL_HEAD = r"\b" + ci("http") + r"[Ss]?://[\w\-]+:"
CL_URL_TAIL = r"@[\w\-]+\." + ci("cloudant.com")
rule("cloudant_credential.json", "cloudant_credential_recognizer", "CLOUDANT_CREDENTIAL",
     "IBM Cloudant password (64 hex) or API key (24 letters), either assigned to a cloudant/cl/clou + "
     "key/password/token variable or embedded in https://account:secret@account.cloudant.com. Source: "
     + SRC + "cloudant.py (case-insensitive). Assignment matches include the variable name; URL matches "
     "cover scheme to host.",
     [("cloudant_password_assignment", assignment(CL, CL_KEY, r"[0-9a-fA-F]{64}"), 0.8),
      ("cloudant_api_key_assignment", assignment(CL, CL_KEY, r"[a-zA-Z]{24}"), 0.7),
      ("cloudant_password_url", CL_URL_HEAD + r"[0-9a-fA-F]{64}" + CL_URL_TAIL, 0.9),
      ("cloudant_api_key_url", CL_URL_HEAD + r"[a-zA-Z]{24}" + CL_URL_TAIL, 0.9)],
     ["cloudant", "couchdb", "ibm cloud"])

rule("discord_bot_token.json", "discord_bot_token_recognizer", "DISCORD_BOT_TOKEN",
     "Discord bot token: base64 user ID starting with M/N/O, '.', 6-character timestamp, '.', 27-character "
     "HMAC. Source: " + SRC + "discord.py; leading \\b added.",
     [("discord_bot_token", r"\b[MNO]" + TOKEN_CHARS + r"{23,25}\." + TOKEN_CHARS + r"{6}\." + TOKEN_CHARS + "{27}", 0.85)],
     ["discord", "bot", "token"])

rule("github_token.json", "github_token_recognizer", "GITHUB_TOKEN",
     "GitHub token with a type prefix: ghp_ (personal access), gho_ (OAuth), ghu_ (user-to-server), ghs_ "
     "(server-to-server), ghr_ (refresh), + 36 characters. Source: " + SRC + "github_token.py; leading \\b "
     "added. Fine-grained tokens (github_pat_…) are not covered by the original plugin.",
     [("github_token", r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}", 0.95)],
     ["github", "token", "gh"])

rule("gitlab_token.json", "gitlab_token_recognizer", "GITLAB_TOKEN",
     "GitLab tokens by prefix: glpat- (personal access), gldt- (deploy), glft- (feed), glsoat- (SCIM OAuth), "
     "glrt- (runner auth), GR1348941 (runner registration), glcbt- (CI/CD job), glimt- (incoming mail), "
     "glptt- (pipeline trigger), glagent- (Kubernetes agent), gloas- (OAuth app secret). Source: " + SRC
     + "gitlab_token.py. The original's trailing (?!\\w) lookahead is approximated with \\b.",
     [("gitlab_prefixed_token", r"\b(?:glpat|gldt|glft|glsoat|glrt)-" + TOKEN_CHARS + r"{20,50}\b", 0.95),
      ("gitlab_runner_registration", r"\bGR1348941" + TOKEN_CHARS + r"{20,50}\b", 0.9),
      ("gitlab_ci_build_token", r"\bglcbt-(?:[0-9a-fA-F]{2}_)?" + TOKEN_CHARS + r"{20,50}\b", 0.95),
      ("gitlab_incoming_mail_token", r"\bglimt-" + TOKEN_CHARS + r"{25}\b", 0.95),
      ("gitlab_trigger_token", r"\bglptt-" + TOKEN_CHARS + r"{40}\b", 0.95),
      ("gitlab_agent_token", r"\bglagent-" + TOKEN_CHARS + r"{50,1024}\b", 0.95),
      ("gitlab_oauth_secret", r"\bgloas-" + TOKEN_CHARS + r"{64}\b", 0.95)],
     ["gitlab", "token", "runner"])

IBM_PREFIX = (
    r"(?:" + ci("ibm") + r"(?:_|\-|)" + ci("cloud") + r"(?:_|\-|)" + ci("iam") + "|"
    + ci("cloud") + r"(?:_|\-|)" + ci("iam") + "|" + ci("ibm") + r"(?:_|\-|)" + ci("cloud") + "|"
    + ci("ibm") + r"(?:_|\-|)" + ci("iam") + "|" + ci("ibm") + "|" + ci("iam") + "|" + ci("cloud") + "|)"
    + r"(?:_|\-|)(?:" + ci("api") + "|)"
)
rule("ibm_cloud_iam_key.json", "ibm_cloud_iam_key_recognizer", "IBM_CLOUD_IAM_KEY",
     "IBM Cloud IAM API key: 44 characters of [A-Za-z0-9_-] assigned to an (optional ibm/cloud/iam/api "
     "prefix +) key/pwd/password/pass/token variable. Source: " + SRC + "ibm_cloud_iam.py "
     "(case-insensitive). The prefix is optional, so any 44-character token assigned to e.g. 'token' "
     "matches; the score is moderate and boosted when IBM context is nearby. Trailing lookahead "
     "approximated with \\b; the match includes the variable name.",
     [("ibm_cloud_iam_assignment", assignment(IBM_PREFIX, KEY_OR_PASS, TOKEN_CHARS + r"{44}\b"), 0.6)],
     ["ibm", "iam", "ibm cloud", "bluemix", "apikey"], 0.3)

COS_PREFIX = r"(?:(?:" + ci("ibm") + r")?[\-_]?" + ci("cos") + r"[\-_]?(?:" + ci("hmac") + r")?|)"
COS_KEYWORD = r"(?:" + ci("secret") + r"[\-_]?(?:" + ci("access") + r")?[\-_]?" + ci("key") + ")"
rule("ibm_cos_hmac_key.json", "ibm_cos_hmac_key_recognizer", "IBM_COS_HMAC_KEY",
     "IBM Cloud Object Storage HMAC secret access key: 48 hex characters assigned to a secret_access_key-style "
     "variable (optionally prefixed ibm/cos/hmac). Source: " + SRC + "ibm_cos_hmac.py (case-insensitive). "
     "Trailing hex lookahead approximated with \\b; the match includes the variable name.",
     [("ibm_cos_hmac_secret_assignment", assignment(COS_PREFIX, COS_KEYWORD, r"[a-fA-F0-9]{48}\b"), 0.8)],
     ["ibm", "cos", "cloud object storage", "hmac", "s3"])

rule("jwt.json", "jwt_recognizer", "JWT",
     "JSON Web Token: base64url header starting with eyJ ('{\"'), '.', payload, optional '.signature'. "
     "Source: " + SRC + "jwt.py. Two fixes vs. the original: its classes [A-Za-z0-9-_=] contain the range "
     "9-_ (which admits :;<=>?@[\\]^), and its signature part was lazy (*?) and therefore never matched; "
     "here the signature is included so it is redacted. The original's base64/JSON decoding check is not "
     "reproduced.",
     [("jwt", r"\beyJ[A-Za-z0-9_\-=]+\.[A-Za-z0-9_\-=]+(?:\.[A-Za-z0-9_\-+/=]*)?", 0.85)],
     ["jwt", "bearer", "authorization", "token", "id_token", "access_token"])

rule("mailchimp_api_key.json", "mailchimp_api_key_recognizer", "MAILCHIMP_API_KEY",
     "Mailchimp API key: 32 lowercase hex/alphanumerics + '-us' + datacenter number. Source: " + SRC
     + "mailchimp.py; \\b added on both sides.",
     [("mailchimp_api_key", r"\b[0-9a-z]{32}-us[0-9]{1,2}\b", 0.85)],
     ["mailchimp", "mandrill", "api key"])

rule("npm_token.json", "npm_token_recognizer", "NPM_TOKEN",
     "npm auth token in an .npmrc line: //registry/:_authToken=npm_… or a 36-character UUID-style legacy "
     "token. Source: " + SRC + "npm.py. Like the original, the match runs to the end of the line, so the "
     "registry host is redacted too.",
     [("npmrc_auth_token", r"//.+/:_authToken=\s*(?:npm_.+|[A-Fa-f0-9\-]{36}).*", 0.9)],
     ["npm", "npmrc", "registry"])

rule("openai_api_key.json", "openai_api_key_recognizer", "OPENAI_API_KEY",
     "OpenAI API key: sk- (optionally sk-proj-/sk-svcacct-…), then 20 alphanumerics, the 'T3BlbkFJ' marker "
     "(base64 of 'OpenAI'), 20 more. Source: " + SRC + "openai.py; leading \\b added and the original's "
     "[A-Za-z0-9-_] class (accidentally containing the range 9-_) corrected to [A-Za-z0-9_-].",
     [("openai_api_key", r"\bsk-[A-Za-z0-9_\-]*[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}", 0.95)],
     ["openai", "chatgpt", "gpt", "api key"])

PEM_KIND = r"(?:RSA |DSA |EC |OPENSSH |ENCRYPTED |PGP )?"
rule("private_key.json", "private_key_recognizer", "PRIVATE_KEY",
     "Private key material: PEM/OpenSSH/PGP '-----BEGIN … PRIVATE KEY-----' blocks, SSH2 encrypted keys and "
     "PuTTY .ppk files. Source: " + SRC + "private_key.py, which only looks for the header lines; for "
     "redaction the block patterns cover header to footer so the key body is removed. The header-only "
     "pattern (lower score) still flags truncated keys and is dropped when a full block matches. "
     "'ENCRYPTED PRIVATE KEY' (PKCS#8) and PuTTY v3 are additions.",
     [("pem_private_key_block",
       r"-----BEGIN " + PEM_KIND + r"PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END " + PEM_KIND + r"PRIVATE KEY(?: BLOCK)?-----", 0.95),
      ("ssh2_encrypted_private_key_block",
       r"---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----[\s\S]*?---- END SSH2 ENCRYPTED PRIVATE KEY ----", 0.95),
      ("putty_private_key", r"PuTTY-User-Key-File-[23]:[\s\S]*?Private-MAC: [0-9a-fA-F]+", 0.95),
      ("private_key_header",
       r"BEGIN (?:DSA |EC |OPENSSH |RSA |PGP |ENCRYPTED |SSH2 ENCRYPTED )?PRIVATE KEY(?: BLOCK)?|PuTTY-User-Key-File-[23]", 0.8)],
     ["private key", "ssh", "pem", "id_rsa"])

rule("pypi_token.json", "pypi_token_recognizer", "PYPI_TOKEN",
     "PyPI / TestPyPI API token: 'pypi-' + base64 macaroon whose first bytes encode pypi.org "
     "(AgEIcHlwaS5vcmc) or test.pypi.org (AgENdGVzdC5weXBpLm9yZw), 70+ more characters. Source: " + SRC
     + "pypi_token.py; leading \\b added and the [A-Za-z0-9-_] class (range 9-_) corrected.",
     [("pypi_token", r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{70,}", 0.95),
      ("testpypi_token", r"\bpypi-AgENdGVzdC5weXBpLm9yZw[A-Za-z0-9_\-]{70,}", 0.95)],
     ["pypi", "twine", "pip", "upload"])

rule("sendgrid_api_key.json", "sendgrid_api_key_recognizer", "SENDGRID_API_KEY",
     "SendGrid API key: 'SG.' + 22-character key ID + '.' + 43-character secret. Source: " + SRC
     + "sendgrid.py; leading \\b added.",
     [("sendgrid_api_key", r"\bSG\." + TOKEN_CHARS + r"{22}\." + TOKEN_CHARS + "{43}", 0.95)],
     ["sendgrid", "email", "smtp"])

rule("slack_token.json", "slack_token_recognizer", "SLACK_TOKEN",
     "Slack tokens xoxa-/xoxb- (bot)/xoxp- (user)/xoxo-/xoxs-/xoxr- (refresh) and incoming-webhook URLs "
     "(hooks.slack.com/services/T…/B…/…). Source: " + SRC + "slack.py (case-insensitive). The webhook match "
     "overlaps the URL recognizer and outranks it.",
     [("slack_token", r"\b" + ci("xox") + r"[AaBbPpOoSsRr]-(?:[0-9]+-)+[A-Za-z0-9]+", 0.9),
      ("slack_webhook", ci("https://hooks.slack.com/services/") + r"[Tt][a-zA-Z0-9_]+/[Bb][a-zA-Z0-9_]+/[a-zA-Z0-9_]+", 0.9)],
     ["slack", "webhook", "bot token"])

SL = alt("softlayer", "sl") + r"(?:_|\-|)(?:" + ci("api") + "|)"
rule("softlayer_api_key.json", "softlayer_api_key_recognizer", "SOFTLAYER_API_KEY",
     "IBM SoftLayer API key (64 alphanumerics) assigned to a softlayer/sl + key/password/token variable, or "
     "in an api.softlayer.com/soap/v3[.1]/ URL. Source: " + SRC + "softlayer.py (case-insensitive); the "
     "original's unescaped dots in the URL are escaped here. Matches include the variable name or URL.",
     [("softlayer_api_key_assignment", assignment(SL, KEY_OR_PASS, r"[a-zA-Z0-9]{64}"), 0.8),
      ("softlayer_api_key_url",
       ci("http") + r"[Ss]?://" + ci("api.softlayer.com/soap/v3") + r"(?:\.1)?/[a-zA-Z0-9]{64}", 0.9)],
     ["softlayer", "ibm cloud", "bluemix"])

rule("square_oauth_secret.json", "square_oauth_secret_recognizer", "SQUARE_OAUTH_SECRET",
     "Square OAuth application secret: 'sq0csp-' + 43 characters. Source: " + SRC + "square_oauth.py; "
     "leading \\b added.",
     [("square_oauth_secret", r"\bsq0csp-[0-9A-Za-z\\_\-]{43}", 0.95)],
     ["square", "oauth", "client secret"])

rule("stripe_api_key.json", "stripe_api_key_recognizer", "STRIPE_API_KEY",
     "Stripe live secret (sk_live_) or restricted (rk_live_) key. Source: " + SRC + "stripe.py, which "
     "matches exactly 24 characters after the prefix; current keys are often ~99 characters, so this "
     "matches 24 or more to redact the whole key. Test-mode keys (sk_test_) are not covered, as in the "
     "original.",
     [("stripe_live_key", r"\b[rs]k_live_[0-9a-zA-Z]{24,}", 0.95)],
     ["stripe", "secret key", "api key"])

rule("telegram_bot_token.json", "telegram_bot_token_recognizer", "TELEGRAM_BOT_TOKEN",
     "Telegram bot token: 8–10 digit bot ID, ':', 35-character secret. Source: " + SRC
     + "telegram_token.py, which anchors the token to the whole line (^…$); here \\b is used so tokens "
     "inside longer text are found.",
     [("telegram_bot_token", r"\b[0-9]{8,10}:" + TOKEN_CHARS + r"{35}\b", 0.85)],
     ["telegram", "bot", "botfather"])

rule("twilio_api_key.json", "twilio_api_key_recognizer", "TWILIO_API_KEY",
     "Twilio account SID (AC + 32) and API key SID (SK + 32), lowercase alphanumerics. Source: " + SRC
     + "twilio.py; \\b added on both sides. SIDs identify rather than authenticate, and 'AC'/'SK' + 32 "
     "characters can collide with other identifiers, so the base score is moderate.",
     [("twilio_account_sid", r"\bAC[a-z0-9]{32}\b", 0.6),
      ("twilio_api_key_sid", r"\bSK[a-z0-9]{32}\b", 0.6)],
     ["twilio", "account sid", "api key", "auth token"], 0.3)

def dump(d):
    """Same layout as the existing spec files: patterns expanded, context_words on one line."""
    text = json.dumps(d, indent=2, ensure_ascii=False)
    words = json.dumps(d["context_words"], ensure_ascii=False).replace('","', '", "')
    start = text.index('"context_words": [')
    end = text.index("]", start) + 1
    return text[:start] + '"context_words": ' + words + text[end:] + "\n"


for file, d in rules:
    (OUT / file).write_text(dump(d))
print(len(rules), "files")
