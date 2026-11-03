// The page's side of the client loop. The wasm client never fetches: a call
// returns `need` (files and byte ranges), the page fetches them all at once
// with `fetch` and `Promise.all`, supplies each body, and calls `step`
// until `done`. One `need` list is one round, one network round trip.
// Nothing here verifies anything; the client checks every byte it is given.

import type { Need, RequestLog, Step, StepLog, Trip } from "./protocol.ts";

/// The wasm `Client` as the page uses it (wasm-bindgen's generated class).
export interface ClientLike {
  free(): void;
  open(): string;
  account(key: string, baseline: boolean): string;
  storage(key: string, slot: string, baseline: boolean): string;
  code(hash: string): string;
  supply(i: number, status: number, body?: Uint8Array | null, error?: string | null): void;
  step(): string;
  head(): string;
  /// The open snapshot's tables and where their pages sit (visualizer).
  tables(): string;
  /// Where the read in progress's entries sit in a response body (the
  /// visualizer's tamper demonstration).
  tamper_targets(file: string, offset: number, body: Uint8Array): string;
}

/// Optional observers of a drive, for the visualizer. None of them changes
/// what is fetched; `alter` may change the bytes of a round's responses
/// before they are supplied (and only the tamper demonstration uses it).
export interface DriveHooks {
  /// A round's requests are going out, `at` ms after the drive began.
  onRound?(round: number, need: Need[], at: number): void;
  /// One response landed (before it is supplied).
  onResponse?(entry: RequestLog): void;
  /// The client computed: `round` 0 is the call that began, `n` the step
  /// after round `n`.
  onStep?(s: StepLog): void;
  /// Every response of the round has landed; the hook may change bodies in
  /// place. When set, a round's responses are supplied together after it
  /// returns instead of as each lands (the client reads none of them
  /// before `step` either way).
  alter?(round: number, need: Need[], bodies: (Uint8Array | undefined)[]): void;
}

export interface WasmModule {
  default: (input?: unknown) => Promise<unknown>;
  /// `tier`: "best" (the attested head when newer, else the finalized
  /// one; the default), "finalized" or "attested".
  Client: new (checkpoint: string, now_ms: number, prefetch: number, top_levels: number, tier?: string) => ClientLike;
  version: () => string;
}

/// Load the wasm-bindgen module from `pkg/`, next to the page.
export async function loadWasm(): Promise<WasmModule> {
  const url = new URL("../pkg/csl_eth_wasm.js", import.meta.url).href;
  const wasm = (await import(/* @vite-ignore */ url)) as WasmModule;
  await wasm.default();
  return wasm;
}

const timeoutMs = 15_000;

interface Fetched {
  status: number;
  body?: Uint8Array;
  error?: string;
  ms: number;
}

async function fetchOne(base: string, n: Need): Promise<Fetched> {
  const t0 = performance.now();
  const headers: Record<string, string> = {};
  if (n.offset !== undefined && n.length !== undefined) {
    if (n.length <= 0) return { status: 0, error: "zero-length range", ms: 0 };
    headers.Range = `bytes=${n.offset}-${n.offset + n.length - 1}`;
  }
  try {
    // `no-store` bypasses the HTTP cache: Chromium serialises in-flight
    // requests for one URL behind its cache lock, which would turn a round
    // of ranges on the same run file back into a queue.
    const resp = await fetch(`${base}/${n.file}`, { headers, cache: "no-store", signal: AbortSignal.timeout(timeoutMs) });
    const body = new Uint8Array(await resp.arrayBuffer());
    return { status: resp.status, body, ms: performance.now() - t0 };
  } catch (e) {
    const error = e instanceof Error ? `${e.name}: ${e.message}` : String(e);
    return { status: 0, error, ms: performance.now() - t0 };
  }
}

/// Drive one call of the client to its answer. `start` makes the call
/// (`client.open()`, `client.account(key)`, …) and returns its first step.
export async function drive<T>(
  client: ClientLike,
  base: string,
  start: () => string,
  hooks: DriveHooks = {},
): Promise<{ result: T; trip: Trip }> {
  const t0 = performance.now();
  const log: RequestLog[] = [];
  const steps: StepLog[] = [];
  const timed = (round: number, f: () => string): Step => {
    const s0 = performance.now() - t0;
    const out = f();
    const s: StepLog = { round, start: s0, end: performance.now() - t0 };
    steps.push(s);
    hooks.onStep?.(s);
    return JSON.parse(out) as Step;
  };
  let rounds = 0;
  let step = timed(0, start);
  while ("need" in step) {
    rounds += 1;
    const round = rounds;
    const need = step.need;
    hooks.onRound?.(round, need, performance.now() - t0);
    const held: (Fetched | undefined)[] = [];
    await Promise.all(
      need.map(async (n, i) => {
        const sent = performance.now() - t0;
        const r = await fetchOne(base, n);
        const entry: RequestLog = {
          round,
          file: n.file,
          offset: n.offset ?? null,
          length: n.length ?? null,
          status: r.status,
          bytes: r.body?.length ?? 0,
          ms: r.ms,
          index: i,
          start: sent,
          end: performance.now() - t0,
          ...(r.error ? { error: r.error } : {}),
        };
        log.push(entry);
        hooks.onResponse?.(entry);
        if (hooks.alter) held[i] = r;
        else client.supply(i, r.status, r.body ?? null, r.error ?? null);
      }),
    );
    if (hooks.alter) {
      hooks.alter(
        round,
        need,
        held.map((r) => r?.body),
      );
      held.forEach((r, i) => r && client.supply(i, r.status, r.body ?? null, r.error ?? null));
    }
    step = timed(round, () => client.step());
  }
  if ("error" in step) throw new Error(step.error);
  return { result: step.done as T, trip: { log, rounds, ms: performance.now() - t0, steps } };
}
