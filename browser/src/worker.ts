// The client worker: a module Web Worker that owns one wasm `Client` and
// answers the page's requests. The client is synchronous; it fetches
// through `globalThis.cslFetch`, which performs synchronous XHR, allowed in
// workers only. Verification (head and state) happens in here, in wasm.

import { install } from "./fetch.ts";
import type { Head, InitReply, OpenReply, ReadResult, Reply, Request } from "./protocol.ts";

interface ClientLike {
  free(): void;
  head(): string;
  account(key: string): string;
  storage(key: string, slot: string): string;
  code(hash: string): string;
}

interface WasmModule {
  default: (input?: unknown) => Promise<unknown>;
  Client: new (base: string, checkpoint: string, now_ms: number, prefetch: number, top_levels: number) => ClientLike;
  version: () => string;
}

let wasm: WasmModule | null = null;
let client: ClientLike | null = null;

async function init(): Promise<InitReply> {
  install();
  const t0 = performance.now();
  // Resolved at run time, next to the page; wasm-bindgen's `init()` finds
  // `_bg.wasm` beside its glue.
  const url = new URL("../pkg/csl_eth_wasm.js", self.location.href).href;
  wasm = (await import(/* @vite-ignore */ url)) as WasmModule;
  await wasm.default();
  return { version: wasm.version(), init_ms: performance.now() - t0 };
}

function open(base: string, checkpoint: string, prefetch: number, top_levels: number): OpenReply {
  if (!wasm) throw new Error("init first");
  client?.free();
  client = null;
  client = new wasm.Client(base, checkpoint, Date.now(), prefetch, top_levels);
  return { head: JSON.parse(client.head()) as Head };
}

function need(): ClientLike {
  if (!client) throw new Error("open a bucket first");
  return client;
}

self.onmessage = (ev: MessageEvent<Request>) => {
  const req = ev.data;
  const send = (reply: Reply) => (self as unknown as { postMessage: (m: Reply) => void }).postMessage(reply);
  const run = async (): Promise<unknown> => {
    switch (req.type) {
      case "init":
        return init();
      case "open":
        return open(req.base, req.checkpoint, req.prefetch, req.top_levels);
      case "account":
        return JSON.parse(need().account(req.key)) as ReadResult;
      case "storage":
        return JSON.parse(need().storage(req.key, req.slot)) as ReadResult;
      case "code":
        return JSON.parse(need().code(req.hash)) as ReadResult;
    }
  };
  run().then(
    (data) => send({ id: req.id, ok: true, data }),
    (e: unknown) => send({ id: req.id, ok: false, error: e instanceof Error ? e.message : String(e) }),
  );
};
