import Foundation

public enum RecognizerLoadError: Error, CustomStringConvertible {
    case invalidRegex(recognizer: String, pattern: String, regex: String)
    case invalidFile(URL, underlying: Error)

    public var description: String {
        switch self {
        case let .invalidRegex(recognizer, pattern, regex):
            "Invalid regex in \(recognizer)/\(pattern): \(regex)"
        case let .invalidFile(url, underlying):
            "Failed to load \(url.lastPathComponent): \(underlying)"
        }
    }
}

/// Loads rule files in the shared `spec/recognizers` JSON format.
///
/// Unlike the Rust loader, which logs and skips a broken file, these functions throw: silently
/// dropping a rule means silently missing PII.
public enum RecognizerLoader {
    /// Loads every non-hidden `*.json` file in `directory`, in file-name order. Each file holds
    /// either one recognizer definition or an array of them.
    public static func load(directory: URL) throws -> [RegexRecognizer] {
        let files = try FileManager.default
            .contentsOfDirectory(at: directory, includingPropertiesForKeys: nil, options: .skipsHiddenFiles)
            .filter { $0.pathExtension == "json" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
        return try files.flatMap { try load(file: $0) }
    }

    /// Loads one file holding a recognizer definition or an array of them.
    public static func load(file: URL) throws -> [RegexRecognizer] {
        do {
            return try load(json: Data(contentsOf: file))
        } catch let error as RecognizerLoadError {
            throw error
        } catch {
            throw RecognizerLoadError.invalidFile(file, underlying: error)
        }
    }

    /// Parses a recognizer definition or an array of them.
    public static func load(json: Data) throws -> [RegexRecognizer] {
        try definitions(from: json).map(RegexRecognizer.init(definition:))
    }

    public static func definitions(from json: Data) throws -> [RecognizerDefinition] {
        let decoder = JSONDecoder()
        let firstByte = json.first { ![0x20, 0x09, 0x0A, 0x0D, 0xEF, 0xBB, 0xBF].contains($0) }
        if firstByte == UInt8(ascii: "[") {
            return try decoder.decode([RecognizerDefinition].self, from: json)
        }
        return [try decoder.decode(RecognizerDefinition.self, from: json)]
    }
}
