/* tslint:disable */
/* eslint-disable */

export class WasmAnalyzer {
    free(): void;
    [Symbol.dispose](): void;
    analyze(text: string, score_threshold: number): any;
    anonymize(text: string, score_threshold: number): string;
    constructor(recognizer_jsons: string);
}

export class WasmVault {
    free(): void;
    [Symbol.dispose](): void;
    detokenize(text: string): string;
    entry_count(): number;
    constructor();
    tokenize(entity_type: string, original: string): string;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_wasmanalyzer_free: (a: number, b: number) => void;
    readonly __wbg_wasmvault_free: (a: number, b: number) => void;
    readonly wasmanalyzer_analyze: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly wasmanalyzer_anonymize: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly wasmanalyzer_new: (a: number, b: number) => [number, number, number];
    readonly wasmvault_detokenize: (a: number, b: number, c: number) => [number, number];
    readonly wasmvault_entry_count: (a: number) => number;
    readonly wasmvault_new: () => number;
    readonly wasmvault_tokenize: (a: number, b: number, c: number, d: number, e: number) => [number, number];
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
