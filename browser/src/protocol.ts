// Messages between the page and the client worker. The worker owns the wasm
// `Client`; the page only renders what comes back.

export type Request =
  | { id: number; type: "init" }
  | { id: number; type: "open"; base: string; checkpoint: string; prefetch: number; top_levels: number }
  | { id: number; type: "account"; key: string }
  | { id: number; type: "storage"; key: string; slot: string }
  | { id: number; type: "code"; hash: string };

export type Call = Request extends infer R ? (R extends { id: number } ? Omit<R, "id"> : never) : never;

export type Reply = { id: number; ok: true; data: unknown } | { id: number; ok: false; error: string };

export interface HttpLogEntry {
  file: string;
  offset: number | null;
  length: number | null;
  status: number;
  bytes: number;
  ms: number;
}

export interface Head {
  checkpoint: string;
  slot: number;
  period: number;
  beacon_root: string;
  participants: number;
  updates_applied: number;
  finality_lag_secs: number;
  block_number: number;
  block_hash: string;
  state_root: string;
  timestamp: number;
  snapshot: { block_number: number; block_hash: string; state_root: string; prefix: string };
  open: { requests: number; bytes: number; ms: number; log: HttpLogEntry[] };
}

export interface Cost {
  requests: number;
  bytes: number;
  rounds: number;
  repairs: number;
  nodes: number;
}

export interface ReadResult {
  status: "verified" | "absent" | "insufficient" | "error";
  why?: string | null;
  error?: string;
  hashed?: string;
  address?: string | null;
  hashed_slot?: string;
  nonce?: number;
  balance?: string;
  storage_root?: string;
  code_hash?: string;
  has_code?: boolean;
  has_storage?: boolean;
  value?: string;
  value_dec?: string;
  size?: number;
  prefix?: string;
  cost?: Cost;
  http?: { requests: number; bytes: number; log: HttpLogEntry[] };
  ms?: number;
}

export interface InitReply {
  version: string;
  init_ms: number;
}

export interface OpenReply {
  head: Head;
}
