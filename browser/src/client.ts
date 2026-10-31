// The page's side of the client loop. The wasm client never fetches: a call
// returns `need` (files and byte ranges), the page fetches them all at once
// with `fetch` and `Promise.all`, supplies each body, and calls `step`
// until `done`. One `need` list is one round, one network round trip.
// Nothing here verifies anything; the client checks every byte it is given.

import type { Need, RequestLog, Step, Trip } from "./protocol.ts";

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
}

export interface WasmModule {
  default: (input?: unknown) => Promise<unknown>;
  Client: new (checkpoint: string, now_ms: number, prefetch: number, top_levels: number) => ClientLike;
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
export async function drive<T>(client: ClientLike, base: string, start: () => string): Promise<{ result: T; trip: Trip }> {
  const t0 = performance.now();
  const log: RequestLog[] = [];
  let rounds = 0;
  let step = JSON.parse(start()) as Step;
  while ("need" in step) {
    rounds += 1;
    const round = rounds;
    const need = step.need;
    await Promise.all(
      need.map(async (n, i) => {
        const r = await fetchOne(base, n);
        log.push({
          round,
          file: n.file,
          offset: n.offset ?? null,
          length: n.length ?? null,
          status: r.status,
          bytes: r.body?.length ?? 0,
          ms: r.ms,
        });
        client.supply(i, r.status, r.body ?? null, r.error ?? null);
      }),
    );
    step = JSON.parse(client.step()) as Step;
  }
  if ("error" in step) throw new Error(step.error);
  return { result: step.done as T, trip: { log, rounds, ms: performance.now() - t0 } };
}
