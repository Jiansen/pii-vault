/// Validator names accepted in a rule's `validators` array.
enum Validator: String, Sendable {
    case luhn
    case cnIDChecksum = "cn_id_checksum"
    case iban
    case deTaxID = "de_tax_id"
    case auABN = "au_abn"
    case auTFN = "au_tfn"
    case auACN = "au_acn"
    case auMedicare = "au_medicare"
    case ukDrivingLicence = "uk_driving_licence"
    case brCNPJ = "br_cnpj"
    case nlBSN = "nl_bsn"

    func validate(_ matched: String) -> Bool {
        switch self {
        case .luhn: Checksum.luhn(matched)
        case .cnIDChecksum: Checksum.cnID(matched)
        case .iban: Checksum.iban(matched)
        case .deTaxID: Checksum.deTaxID(matched)
        case .auABN: Checksum.auABN(matched)
        case .auTFN: Checksum.auTFN(matched)
        case .auACN: Checksum.auACN(matched)
        case .auMedicare: Checksum.auMedicare(matched)
        case .ukDrivingLicence: Checksum.ukDrivingLicence(matched)
        case .brCNPJ: Checksum.brCNPJ(matched)
        case .nlBSN: Checksum.nlBSN(matched)
        }
    }
}

/// Checksum algorithms used by the validators. Ported 1:1 from `rust/src/recognizer.rs`.
public enum Checksum {
    /// ASCII digits of `s` in order; every other character is skipped.
    private static func asciiDigits(_ s: String) -> [Int] {
        s.utf8.compactMap { $0 >= 0x30 && $0 <= 0x39 ? Int($0 - 0x30) : nil }
    }

    public static func luhn(_ number: String) -> Bool {
        let digits = asciiDigits(number)
        if digits.count < 2 {
            return false
        }
        var sum = 0
        var double = false
        for d in digits.reversed() {
            var val = d
            if double {
                val *= 2
                if val > 9 {
                    val -= 9
                }
            }
            sum += val
            double.toggle()
        }
        return sum % 10 == 0
    }

    public static func cnID(_ id: String) -> Bool {
        let bytes = Array(id.utf8)
        if bytes.count != 18 {
            return false
        }
        let weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
        let checkChars: [UInt8] = Array("10X98765432".utf8)
        var sum = 0
        for i in 0..<17 {
            guard bytes[i] >= 0x30 && bytes[i] <= 0x39 else {
                return false
            }
            sum += Int(bytes[i] - 0x30) * weights[i]
        }
        let last = bytes[17] == UInt8(ascii: "x") ? UInt8(ascii: "X") : bytes[17]
        return last == checkChars[sum % 11]
    }

    public static func iban(_ iban: String) -> Bool {
        let cleaned = Array(iban.unicodeScalars.filter { !$0.properties.isWhitespace && $0 != "-" })
        let byteLength = cleaned.reduce(0) { $0 + String($1).utf8.count }
        if byteLength < 5 || byteLength > 34 || cleaned.count < 4 {
            return false
        }
        let rearranged = cleaned[4...] + cleaned[..<4]
        // Mod-97 of the decimal expansion, one digit at a time (equivalent to Rust's 7-digit chunks).
        var remainder = 0
        for c in rearranged {
            let value = ("0"..."9").contains(c)
                ? Int(c.value) - 0x30
                : Int(c.value) - Int(UnicodeScalar("A").value) + 10
            if value < 0 {
                return false
            }
            for digit in String(value).utf8 {
                remainder = (remainder * 10 + Int(digit - 0x30)) % 97
            }
        }
        return remainder == 1
    }

    public static func deTaxID(_ id: String) -> Bool {
        let d = asciiDigits(id)
        if d.count != 11 || d[0] == 0 {
            return false
        }
        if Set(d[..<10]).count == 1 {
            return false
        }
        var product = 10
        for i in 0..<10 {
            var total = (d[i] + product) % 10
            if total == 0 {
                total = 10
            }
            product = (total * 2) % 11
        }
        let check = 11 - product == 10 ? 0 : 11 - product
        return check == d[10]
    }

    public static func auABN(_ abn: String) -> Bool {
        var d = asciiDigits(abn)
        if d.count != 11 {
            return false
        }
        let weights = [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19]
        d[0] -= 1
        return zip(d, weights).reduce(0) { $0 + $1.0 * $1.1 } % 89 == 0
    }

    public static func auTFN(_ tfn: String) -> Bool {
        let d = asciiDigits(tfn)
        if d.count != 9 {
            return false
        }
        let weights = [1, 4, 3, 7, 5, 8, 6, 9, 10]
        return zip(d, weights).reduce(0) { $0 + $1.0 * $1.1 } % 11 == 0
    }

    public static func auACN(_ acn: String) -> Bool {
        let d = asciiDigits(acn)
        if d.count != 9 {
            return false
        }
        let weights = [8, 7, 6, 5, 4, 3, 2, 1]
        let sum = zip(d[..<8], weights).reduce(0) { $0 + $1.0 * $1.1 }
        return (10 - sum % 10) % 10 == d[8]
    }

    public static func auMedicare(_ medicare: String) -> Bool {
        let d = asciiDigits(medicare)
        if d.count < 10 || d.count > 11 {
            return false
        }
        if d[0] < 2 || d[0] > 6 {
            return false
        }
        let weights = [1, 3, 7, 9, 1, 3, 7, 9]
        let sum = zip(d[..<8], weights).reduce(0) { $0 + $1.0 * $1.1 }
        return sum % 10 == d[8]
    }

    public static func ukDrivingLicence(_ licence: String) -> Bool {
        let text = Array(licence.uppercased().utf8)
        if text.count != 16 {
            return false
        }
        let surname = text[..<5]
        // All 9s = no valid surname
        if surname.allSatisfy({ $0 == UInt8(ascii: "9") }) {
            return false
        }
        // Surname must be letters followed by optional 9-padding (no 9 before a letter)
        var seenNine = false
        for c in surname {
            if c == UInt8(ascii: "9") {
                seenNine = true
            } else if seenNine {
                return false
            }
        }
        // Must start with at least one letter
        return !(text[0] >= 0x30 && text[0] <= 0x39)
    }

    /// CNPJ: 12 base characters (0-9, or A-Z since the July 2026 alphanumeric format) and two
    /// numeric mod-11 check digits. Each character is worth its ASCII code minus 48, so digits
    /// keep their value and "A" is 17; weights run 2...9 from the right, repeating.
    public static func brCNPJ(_ cnpj: String) -> Bool {
        let isDigit = { (b: UInt8) in b >= 0x30 && b <= 0x39 }
        let chars: [UInt8] = cnpj.utf8.compactMap { b in
            if isDigit(b) || (b >= 0x41 && b <= 0x5A) { return b }
            if b >= 0x61 && b <= 0x7A { return b - 0x20 }
            return nil
        }
        if chars.count != 14 || !chars[12...].allSatisfy(isDigit) {
            return false
        }
        // 00.000.000/0000-00, 11.111.111/1111-11 and so on pass the arithmetic but are not issued.
        if chars.allSatisfy({ $0 == chars[0] }) {
            return false
        }
        let values = chars.map { Int($0) - 0x30 }
        func checkDigit(_ n: Int) -> Int {
            let sum = values[..<n].reversed().enumerated().reduce(0) { $0 + $1.element * (2 + $1.offset % 8) }
            return sum % 11 < 2 ? 0 : 11 - sum % 11
        }
        return checkDigit(12) == values[12] && checkDigit(13) == values[13]
    }

    /// BSN 11-proof: 9*d1 + 8*d2 + ... + 2*d8 - d9 must be a positive multiple of 11.
    public static func nlBSN(_ bsn: String) -> Bool {
        let d = asciiDigits(bsn)
        if d.count != 9 {
            return false
        }
        let sum = d[..<8].enumerated().reduce(0) { $0 + $1.element * (9 - $1.offset) } - d[8]
        return sum > 0 && sum % 11 == 0
    }
}
