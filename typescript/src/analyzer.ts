import { EntityType, RecognizerResult } from './entity';
import { Recognizer } from './recognizer';

export interface AnalyzerResult {
  entities: RecognizerResult[];
}

export class Analyzer {
  constructor(private readonly recognizers: Recognizer[]) {}

  analyze(text: string, entities: EntityType[] = [], scoreThreshold = 0.0): AnalyzerResult {
    let allResults: RecognizerResult[] = [];

    for (const recognizer of this.recognizers) {
      const results = recognizer.analyze(text, entities);
      allResults.push(...results);
    }

    allResults = allResults.filter(r => r.score >= scoreThreshold);
    allResults.sort((a, b) => a.start - b.start || b.score - a.score);

    const deduped = this.resolveOverlaps(allResults);
    return { entities: deduped };
  }

  get recognizerCount(): number {
    return this.recognizers.length;
  }

  private resolveOverlaps(results: RecognizerResult[]): RecognizerResult[] {
    const output: RecognizerResult[] = [];
    for (const result of results) {
      const dominated = output.some(
        existing =>
          existing.start <= result.start &&
          existing.end >= result.end &&
          existing.score >= result.score
      );
      if (dominated) continue;

      const toRemove = new Set<number>();
      output.forEach((existing, i) => {
        if (
          result.start <= existing.start &&
          result.end >= existing.end &&
          result.score >= existing.score
        ) {
          toRemove.add(i);
        }
      });

      const filtered = output.filter((_, i) => !toRemove.has(i));
      output.length = 0;
      output.push(...filtered, result);
    }
    output.sort((a, b) => a.start - b.start);
    return output;
  }
}
