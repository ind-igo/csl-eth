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
  /// Position in the round's `need` list.
  index?: number;
  /// When it was sent and when its body had landed, in ms since the drive
  /// began (the visualizer's time axis).
  start?: number;
  end?: number;
  /// Why no response came back (network error, timeout), when none did.
  error?: string;
}

/// One computation of the client: `round` 0 is the call that began the
/// drive, `n` the `step` after round `n`; ms since the drive began.
export interface StepLog {
  round: number;
  start: number;
  end: number;
}

/// What driving a call cost on the page's side.
export interface Trip {
  log: RequestLog[];
  rounds: number;
  ms: number;
  steps?: StepLog[];
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
  /// Model pages this read fetched: the cold part of a read, zero once
  /// the key's neighbourhoods are known.
  model_pages: number;
}

export interface ReadResult {
  status: "verified" | "absent" | "insufficient";
  why?: string | null;
  hashed?: string;
  address?: string | null;
  hashed_slot?: string;
  /// The read went the content-addressed way (every node by hash).
  baseline?: boolean;
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
  /// The final walk(s), node by node (see `ReadTrace`).
  trace?: ReadTrace;
}

/// Where a traced node's bytes came from.
export type NodeFrom =
  | { kind: "cache" }
  | { kind: "embedded" }
  | { kind: "page"; table: number; name: string; page: number }
  | { kind: "not_served"; table?: number; name?: string; page?: number };

/// One node of the client's final walk, as `csl-eth-client`'s trace has it.
export interface TraceNode {
  depth: number;
  /// The nibbles consumed to reach it, hex.
  at: string;
  /// The hash its parent committed to; null for a node embedded in its parent.
  hash: string | null;
  len: number;
  /// The table key it was looked up by.
  key: string | null;
  from: NodeFrom;
  /// The client computation that first accepted it (0: the call that began
  /// the read; n: the step after round n); null where the walk stopped on it.
  checked_at: number | null;
  kind: "branch" | "extension" | "leaf" | "missing" | "invalid";
  occupied?: number;
  next?: number;
  taken?: boolean;
  nibbles?: string;
  follows?: boolean;
  rest?: string;
  matches?: boolean;
  value?: string;
  account?: { nonce: number; balance: string; storage_root: string; code_hash: string };
  word?: { hex: string; dec: string };
  what?: string;
  got?: string | null;
}

export interface WalkTrace {
  trie: "account" | "storage";
  table: number;
  name: string;
  by_hash: boolean;
  root: string;
  key: string;
  nodes: TraceNode[];
}

export interface TraceEnd {
  status: "verified" | "absent" | "insufficient";
  by?: string;
  reason?: string;
  kind?: string;
  table?: number;
  key?: string;
  what?: string;
  error?: string;
}

export interface ReadTrace {
  walks: WalkTrace[];
  code: { code_hash: string; table: number; name: string; page: number | null; blob: string | null; len: number | null } | null;
  end: TraceEnd;
}

/// A table of the open snapshot and where its pages sit (`Client.tables`).
export interface TableInfo {
  id: number;
  name: string;
  file: string;
  page_count: number;
  entry_count: number;
  epsilon_pages: number;
  page_bytes: number;
  record_bytes: number;
  data_off: number;
  model_off: number;
  model_bytes: number;
  model_pages: number;
  model_record_bytes: number;
  total_len: number;
  error: string | null;
}

export interface TamperTarget {
  table: number;
  trie: "account" | "storage";
  depth: number;
  key: string;
  page: number;
  value_off: number;
  value_len: number;
}
