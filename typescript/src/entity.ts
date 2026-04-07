export class EntityType {
  constructor(public readonly name: string) {
    this.name = name.toUpperCase();
  }

  toString(): string {
    return this.name;
  }

  equals(other: EntityType): boolean {
    return this.name === other.name;
  }
}

export interface RecognizerResult {
  entityType: EntityType;
  start: number;
  end: number;
  score: number;
  recognizerName?: string;
}

export function resultText(result: RecognizerResult, input: string): string {
  return input.slice(result.start, result.end);
}
