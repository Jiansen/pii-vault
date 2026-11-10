import Foundation

public struct AnalyzerResult: Sendable {
    /// Detections sorted by `start`. Fully-contained, lower-or-equal-scored matches are removed;
    /// partially overlapping matches are kept (same rules as the Rust implementation).
    public let entities: [RecognizerResult]

    /// The UTF-16 ranges that need redacting: every non-empty entity range, with overlapping or
    /// touching ranges merged, sorted by location.
    public var redactionRanges: [NSRange] {
        var merged: [NSRange] = []
        for entity in entities.sorted(by: { $0.start < $1.start }) where entity.end > entity.start {
            if let last = merged.last, entity.start <= NSMaxRange(last) {
                let end = max(NSMaxRange(last), entity.end)
                merged[merged.count - 1] = NSRange(location: last.location, length: end - last.location)
            } else {
                merged.append(entity.nsRange)
            }
        }
        return merged
    }
}

/// Runs a set of recognizers over text and resolves overlapping matches.
///
/// Immutable and `Sendable`: build one at startup and share it across threads/tasks.
public final class Analyzer: Sendable {
    public let recognizers: [any Recognizer]

    /// (recognizer index, pattern index) for every regex pattern, or (index, nil) for a custom
    /// recognizer, in sequential order.
    private let workUnits: [(recognizer: Int, pattern: Int?)]
    /// Indices into `workUnits`, longest regex first: a cheap proxy for matching cost.
    private let scheduleOrder: [Int]

    public init(recognizers: [any Recognizer]) {
        self.recognizers = recognizers
        var units: [(recognizer: Int, pattern: Int?)] = []
        var weights: [Int] = []
        for (r, recognizer) in recognizers.enumerated() {
            if let regexRecognizer = recognizer as? RegexRecognizer {
                for (p, pattern) in regexRecognizer.definition.patterns.enumerated() {
                    units.append((r, p))
                    weights.append(pattern.regex.count)
                }
            } else {
                units.append((r, nil))
                weights.append(Int.max)
            }
        }
        workUnits = units
        scheduleOrder = weights.indices.sorted { weights[$0] > weights[$1] }
    }

    /// Loads every rule file in `directory` (see ``RecognizerLoader/load(directory:)``).
    public convenience init(rulesDirectory: URL) throws {
        self.init(recognizers: try RecognizerLoader.load(directory: rulesDirectory))
    }

    public var recognizerCount: Int { recognizers.count }

    /// Texts shorter than this (in UTF-16 units) are analyzed sequentially by
    /// ``analyzeConcurrently(_:entities:scoreThreshold:)``; below it, waking worker threads
    /// costs about as much as it saves.
    public static let minimumConcurrentLength = 256

    public func analyze(_ text: String, entities: [EntityType] = [], scoreThreshold: Double = 0) -> AnalyzerResult {
        let nsText = utf16Backed(text)
        var all: [RecognizerResult] = []
        for recognizer in recognizers {
            all.append(contentsOf: run(recognizer, text: text, nsText: nsText, entities: entities))
        }
        return Self.finish(all, scoreThreshold: scoreThreshold)
    }

    /// Same result as ``analyze(_:entities:scoreThreshold:)``, with every rule pattern running
    /// in parallel on all cores. Several times faster on long documents (bounded by the slowest
    /// single pattern); texts shorter than ``minimumConcurrentLength`` run sequentially.
    ///
    /// Blocks the caller until every recognizer is done, so call it from a background task, not
    /// the main thread. Custom ``Recognizer``s must tolerate being called concurrently (their
    /// `Sendable` conformance already promises this).
    public func analyzeConcurrently(_ text: String, entities: [EntityType] = [], scoreThreshold: Double = 0) -> AnalyzerResult {
        let nsText = utf16Backed(text)
        guard recognizers.count > 1, nsText.length >= Self.minimumConcurrentLength else {
            var all: [RecognizerResult] = []
            for recognizer in recognizers {
                all.append(contentsOf: run(recognizer, text: text, nsText: nsText, entities: entities))
            }
            return Self.finish(all, scoreThreshold: scoreThreshold)
        }

        // One work item per regex pattern (per recognizer for custom recognizers), so a
        // recognizer with several patterns doesn't serialize them on one core.
        let units = workUnits
        let slots = ResultSlots(count: units.count)
        // A private immutable copy that nothing mutates, so sharing it across threads is safe.
        nonisolated(unsafe) let sharedText = nsText
        DispatchQueue.concurrentPerform(iterations: units.count) { n in
            // Start the most expensive-looking patterns first so they don't become the tail.
            let i = scheduleOrder[n]
            let (r, pattern) = units[i]
            if let pattern, let regexRecognizer = recognizers[r] as? RegexRecognizer {
                slots[i] = regexRecognizer.analyze(sharedText, entities: entities, pattern: pattern)
            } else {
                slots[i] = run(recognizers[r], text: text, nsText: sharedText, entities: entities)
            }
        }
        // Concatenating in (recognizer, pattern) order reproduces the sequential order exactly,
        // which the stable sort below relies on for tie-breaking.
        return Self.finish(slots.joined(), scoreThreshold: scoreThreshold)
    }

    private func run(_ recognizer: any Recognizer, text: String, nsText: NSString, entities: [EntityType]) -> [RecognizerResult] {
        if let regexRecognizer = recognizer as? RegexRecognizer {
            return regexRecognizer.analyze(nsText, entities: entities)
        }
        return recognizer.analyze(text, entities: entities)
    }

    private static func finish(_ results: [RecognizerResult], scoreThreshold: Double) -> AnalyzerResult {
        var all = results
        all.removeAll { $0.score < scoreThreshold }
        all = Self.stableSorted(all) { a, b in
            a.start != b.start ? a.start < b.start : a.score > b.score
        }
        return AnalyzerResult(entities: Self.resolveOverlaps(all))
    }

    private static func resolveOverlaps(_ results: [RecognizerResult]) -> [RecognizerResult] {
        var output: [RecognizerResult] = []
        for result in results {
            let dominated = output.contains { existing in
                existing.start <= result.start && existing.end >= result.end && existing.score >= result.score
            }
            if dominated {
                continue
            }
            output.removeAll { existing in
                result.start <= existing.start && result.end >= existing.end && result.score >= existing.score
            }
            output.append(result)
        }
        return stableSorted(output) { $0.start < $1.start }
    }

    /// Rust's `sort_by` is stable; tie order decides which recognizer wins an exact overlap,
    /// so keep it explicit rather than rely on `sort`'s implementation.
    private static func stableSorted(
        _ items: [RecognizerResult],
        by areInIncreasingOrder: (RecognizerResult, RecognizerResult) -> Bool
    ) -> [RecognizerResult] {
        items.enumerated()
            .sorted { lhs, rhs in
                if areInIncreasingOrder(lhs.element, rhs.element) { return true }
                if areInIncreasingOrder(rhs.element, lhs.element) { return false }
                return lhs.offset < rhs.offset
            }
            .map(\.element)
    }
}

/// One result array per recognizer for ``Analyzer/analyzeConcurrently(_:entities:scoreThreshold:)``.
/// Each slot is written by exactly one `concurrentPerform` iteration and read only after all of
/// them return, so the unsynchronized access is race-free.
private final class ResultSlots: @unchecked Sendable {
    private let storage: UnsafeMutableBufferPointer<[RecognizerResult]>

    init(count: Int) {
        storage = .allocate(capacity: count)
        storage.initialize(repeating: [])
    }

    deinit {
        storage.deinitialize()
        storage.deallocate()
    }

    subscript(index: Int) -> [RecognizerResult] {
        get { storage[index] }
        set { storage[index] = newValue }
    }

    func joined() -> [RecognizerResult] {
        Array(storage.joined())
    }
}
