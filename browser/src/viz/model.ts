// The visualizer's data: what one drive of the client recorded (its
// requests, the client's computations, its answer and trace), and the
// timeline a view is drawn at. Everything here comes from the drive's own
// log and the client's `done`; nothing is synthesised. Times are ms since
// the scene began, on the clock `performance.now()` keeps.

import type { Head, ReadResult, RequestLog, StepLog, TableInfo, TraceNode } from "../protocol.ts";

/// A page of a run file: page 0 (the header and top model), a data page
/// (1-based, as `csl-run` numbers records), or a model page (1-based).
export interface PageRef {
  table: number;
  kind: "page0" | "data" | "model";
  index: number;
}

export const pageKey = (p: PageRef) => `${p.table}:${p.kind}:${p.index}`;

/// The pages of `file` that the byte range `[offset, offset + length)`
/// covers, from the layout the client reported (`Client.tables`). A whole
/// file (head, manifest, blob) is no table's page.
export function pagesOf(tables: TableInfo[], file: string, offset: number | null, length: number | null): PageRef[] {
  const t = tables.find((x) => x.file === file);
  if (!t || offset === null || length === null || length <= 0) return [];
  const out: PageRef[] = [];
  const end = offset + length;
  if (offset < t.data_off) out.push({ table: t.id, kind: "page0", index: 0 });
  const dataEnd = t.data_off + t.page_count * t.record_bytes;
  if (t.record_bytes > 0 && end > t.data_off && offset < dataEnd) {
    const a = Math.max(offset, t.data_off);
    const b = Math.min(end, dataEnd);
    const first = Math.floor((a - t.data_off) / t.record_bytes) + 1;
    const last = Math.floor((b - 1 - t.data_off) / t.record_bytes) + 1;
    for (let i = first; i <= last; i++) out.push({ table: t.id, kind: "data", index: i });
  }
  if (t.model_pages > 0 && t.model_record_bytes > 0 && end > t.model_off) {
    const a = Math.max(offset, t.model_off);
    const b = Math.min(end, t.model_off + t.model_pages * t.model_record_bytes);
    if (b > a) {
      const first = Math.floor((a - t.model_off) / t.model_record_bytes) + 1;
      const last = Math.floor((b - 1 - t.model_off) / t.model_record_bytes) + 1;
      for (let m = first; m <= last; m++) out.push({ table: t.id, kind: "model", index: m });
    }
  }
  return out;
}

/// The byte the page flipped for the tamper demonstration, and where.
export interface TamperNote {
  round: number;
  /// Index of the request in the round's `need`.
  index: number;
  file: string;
  table: number;
  page: number;
  trie: "account" | "storage";
  depth: number;
  /// Absolute offset of the flipped byte in the run file.
  byte: number;
  before: number;
  after: number;
}

export interface Req extends RequestLog {
  start: number;
  end: number;
  pages: PageRef[];
  tampered?: TamperNote;
}

export type LaneName = "open" | "path" | "baseline";

/// One client's drive within a scene.
export interface Lane {
  name: LaneName;
  /// When its drive began, ms after the scene began.
  offset: number;
  reqs: Req[];
  steps: StepLog[];
  /// Requests sent but not landed: index in `need` by round.
  sent: { round: number; index: number; file: string; offset: number | null; length: number | null; start: number }[];
  done: boolean;
  ms: number;
  rounds: number;
  result?: ReadResult;
  head?: Head;
  error?: string;
  /// The tamper demonstration: what was flipped, or `null` when it was
  /// asked for and the read's responses held no node to flip.
  tamper?: TamperNote | null;
}

export type What = "open" | "account" | "storage" | "code";

export interface Scene {
  id: number;
  kind: "open" | "read" | "race";
  what: What;
  /// The key as typed, and the slot for a storage read.
  key: string;
  slot?: string;
  lanes: Lane[];
  /// `performance.now()` when the scene began.
  t0: number;
  tables: TableInfo[];
}

export function newLane(name: LaneName, offset: number): Lane {
  return { name, offset, reqs: [], steps: [], sent: [], done: false, ms: 0, rounds: 0 };
}

/// A node the client checked (or stopped on), at the end of the client
/// computation that first accepted it: the trace's `checked_at` names it.
export interface Check {
  lane: number;
  walk: number;
  node: number;
  t: number;
  fail: boolean;
}

/// The end of the computation `round` of a lane, on the scene's clock.
export function stepEnd(lane: Lane, round: number): number | undefined {
  const s = lane.steps.find((x) => x.round === round);
  return s === undefined ? undefined : lane.offset + s.end;
}

export function nodeFailed(n: TraceNode): boolean {
  return n.kind === "missing" || n.kind === "invalid";
}

/// Every node check of a finished scene, in the order the client made
/// them: by the computation that made them, then in walk order.
export function checksOf(scene: Scene): Check[] {
  const out: (Check & { order: number })[] = [];
  scene.lanes.forEach((lane, li) => {
    const tr = lane.result?.trace;
    if (!tr || !lane.done) return;
    const last = lane.steps[lane.steps.length - 1];
    let order = 0;
    tr.walks.forEach((w, wi) => {
      w.nodes.forEach((n, ni) => {
        const fail = nodeFailed(n);
        const at = n.checked_at ?? (fail && last ? last.round : null);
        const t = at === null ? undefined : stepEnd(lane, at);
        if (t !== undefined) out.push({ lane: li, walk: wi, node: ni, t, fail, order: order++ });
      });
    });
    if (tr.code && last) out.push({ lane: li, walk: -1, node: 0, t: lane.offset + last.end, fail: tr.end.status !== "verified", order: order++ });
  });
  out.sort((a, b) => a.t - b.t || a.lane - b.lane || a.order - b.order);
  return out.map(({ order: _, ...c }) => c);
}

/// Where a view is drawn: the scene's clock, and how many of its checks
/// have been shown (checks take display time of their own, see `Timeline`).
export interface Cursor {
  t: number;
  checks: number;
}

export type Ev =
  | { kind: "send"; t: number; lane: number; round: number; reqs: number[] }
  | { kind: "land"; t: number; lane: number; req: number }
  | { kind: "check"; t: number; check: number }
  | { kind: "done"; t: number; lane: number };

/// A finished scene as events, and the display time each takes when
/// replayed: network time scaled by `slow`, each check `checkMs` (the
/// client's checks take microseconds; the replay pauses the clock on them
/// and says so).
export class Timeline {
  evs: Ev[] = [];
  at: number[] = [];
  checks: Check[];
  total = 0;

  constructor(
    readonly scene: Scene,
    readonly slow: number,
    readonly checkMs: number,
  ) {
    this.checks = checksOf(scene);
    const evs: Ev[] = [];
    scene.lanes.forEach((lane, li) => {
      const rounds = new Map<number, number[]>();
      lane.reqs.forEach((r, ri) => {
        const l = rounds.get(r.round) ?? [];
        l.push(ri);
        rounds.set(r.round, l);
      });
      for (const [round, reqs] of rounds) {
        const t = lane.offset + Math.min(...reqs.map((i) => lane.reqs[i]!.start));
        evs.push({ kind: "send", t, lane: li, round, reqs });
      }
      lane.reqs.forEach((r, ri) => evs.push({ kind: "land", t: lane.offset + r.end, lane: li, req: ri }));
      evs.push({ kind: "done", t: lane.offset + lane.ms, lane: li });
    });
    this.checks.forEach((c, i) => evs.push({ kind: "check", t: c.t, check: i }));
    const rank = { send: 0, land: 1, check: 2, done: 3 } as const;
    evs.sort((a, b) => a.t - b.t || rank[a.kind] - rank[b.kind] || (a.kind === "check" && b.kind === "check" ? a.check - b.check : 0));
    this.evs = evs;
    let d = 0;
    let t = 0;
    for (const e of evs) {
      d += Math.max(0, e.t - t) * slow;
      t = Math.max(t, e.t);
      if (e.kind === "check") d += checkMs;
      this.at.push(d);
    }
    this.total = d;
  }

  /// The cursor at display time `d` (ms since the replay began).
  cursorAt(d: number): Cursor {
    let t = 0;
    let checks = 0;
    let prevD = 0;
    for (let i = 0; i < this.evs.length; i++) {
      const e = this.evs[i]!;
      const ed = this.at[i]!;
      if (e.kind === "check") {
        const startD = ed - this.checkMs;
        if (d < startD) return { t: t + (d - prevD) / this.slow, checks };
        t = e.t;
        if (d < ed) return { t, checks };
        checks += 1;
      } else {
        if (d < ed) return { t: t + (d - prevD) / this.slow, checks };
        t = e.t;
      }
      prevD = ed;
    }
    return { t: Math.max(t, t + (d - prevD) / this.slow), checks };
  }

  /// The cursor just after event `i` (step-by-step).
  cursorAfter(i: number): Cursor {
    let checks = 0;
    let t = 0;
    for (let j = 0; j <= i && j < this.evs.length; j++) {
      const e = this.evs[j]!;
      t = Math.max(t, e.t);
      if (e.kind === "check") checks += 1;
    }
    return { t, checks };
  }

  end(): Cursor {
    return { t: Math.max(0, ...this.scene.lanes.map((l) => l.offset + l.ms)), checks: this.checks.length };
  }
}

/// The request of a lane that brought a page, if any.
export function reqOfPage(lane: Lane, p: PageRef): number {
  return lane.reqs.findIndex((r) => r.pages.some((q) => q.table === p.table && q.kind === p.kind && q.index === p.index));
}

/// The page a traced node's bytes came from (or was searched for it).
export function pageOfNode(n: TraceNode): PageRef | null {
  const f = n.from;
  if ((f.kind === "page" || f.kind === "not_served") && f.table !== undefined && f.page !== undefined) {
    return { table: f.table, kind: "data", index: f.page };
  }
  return null;
}

// --- formatting -------------------------------------------------------------

export const kb = (b: number) => (b < 1024 ? `${b} B` : b < 1024 * 1024 ? `${(b / 1024).toFixed(b < 10240 ? 1 : 0)} KB` : `${(b / 1048576).toFixed(2)} MB`);
export const ms = (x: number) => (x < 10 ? `${x.toFixed(1)} ms` : x < 10000 ? `${Math.round(x)} ms` : `${(x / 1000).toFixed(1)} s`);
export const short = (h: string | null | undefined, n = 4) => (!h ? "" : h.length <= 2 + 2 * n ? h : `${h.slice(0, 2 + n)}…${h.slice(-n)}`);
export const plural = (n: number, w: string, ws = `${w}s`) => `${n.toLocaleString()} ${n === 1 ? w : ws}`;
export const esc = (s: unknown) =>
  String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c] ?? c);
export const fileShort = (f: string) => {
  if (f.startsWith("head/")) return f;
  const i = f.lastIndexOf("/");
  return i >= 0 ? f.slice(i + 1) : f;
};
export const eth = (wei: string) => {
  const w = BigInt(wei);
  const whole = w / 10n ** 18n;
  const frac = (w % 10n ** 18n).toString().padStart(18, "0").slice(0, 4);
  return `${whole.toLocaleString()}.${frac} ETH`;
};
