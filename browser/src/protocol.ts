// What the wasm client says and what the page shows. The client owns the
// shapes of `done`; the page adds timing and the request log, which only it
// can know.

/// One thing the client needs before it can continue: a whole file, or a
/// byte range of one.
export interface Need {
  file: string;
  offset?: number;
  length?: number;
}

/// One call of the client: more to fetch, or the answer, or a refusal.
export type Step = { need: Need[] } | { done: unknown } | { error: string };

/// One request the page made, as the page saw it.
export interface RequestLog {
  round: number;
  file: string;
  offset: number | null;
  length: number | null;
  status: number;
  bytes: number;
  ms: number;
}

/// What driving a call cost on the page's side.
export interface Trip {
  log: RequestLog[];
  rounds: number;
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
  open: { requests: number; bytes: number; rounds: number };
}

export interface Cost {
  requests: number;
  bytes: number;
  rounds: number;
  repairs: number;
  nodes: number;
}

export interface ReadResult {
  status: "verified" | "absent" | "insufficient";
  why?: string | null;
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
  cost: Cost;
}
