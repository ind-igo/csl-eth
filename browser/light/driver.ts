// The I/O half of the light client: runs `read` from verify.ts, fetches
// every byte range it asks for in one parallel round, and repeats until it
// answers or refuses. Nothing here is trusted: it moves bytes, and a byte it
// gets wrong can only end in a refusal.

import { adopt, CHECKPOINT, Held, hintsLater, Pending, read, Refused, Session, takeHints, type Answer, type Query, type Want } from "./verify.ts";

export type Stats = { rounds: number; requests: number; bytes: number; ms: number };
export type Outcome = {
  answer?: Answer;
  refused?: string;
  /** Refused while proving the head. */
  head?: boolean;
  stats: Stats;
  tampered?: string;
  /** Why a remembered checkpoint was dropped for the built-in one before this answer. */
  fellBack?: string;
};
/** Called with each fetched body before the verifier sees it; may change it in place. */
export type Mutate = (w: Want, body: Uint8Array, round: number) => string | null;

const MAX_ROUNDS = 40;

async function fetchWant(base: string, w: Want): Promise<Uint8Array> {
  const url = `${base}/${w.path}`;
  const ranged = w.off !== undefined && w.len !== undefined;
  const res = await fetch(url, ranged ? { headers: { Range: `bytes=${w.off}-${w.off! + w.len! - 1}` } } : {});
  if (res.status !== (ranged ? 206 : 200)) throw new Error(`${w.path}: HTTP ${res.status}`);
  const body = new Uint8Array(await res.arrayBuffer());
  if (ranged && body.length !== w.len) throw new Error(`${w.path}: short read (${body.length} of ${w.len} bytes)`);
  return body;
}

/** Run `f` over fetched bytes, round after round, until it returns or refuses. */
async function loop<T>(base: string, session: Session, f: (h: Held) => T, mutate?: Mutate): Promise<{ value?: T; refused?: string; head?: boolean; stats: Stats; tampered?: string }> {
  const h = new Held(session);
  const stats: Stats = { rounds: 0, requests: 0, bytes: 0, ms: 0 };
  const t0 = performance.now();
  let tampered: string | undefined;
  const done = <O extends object>(o: O) => ({ ...o, stats: { ...stats, ms: Math.round(performance.now() - t0) }, ...(tampered ? { tampered } : {}) });
  for (;;) {
    h.wants.clear();
    try {
      return done({ value: f(h) });
    } catch (e) {
      if (!(e instanceof Pending)) return done({ refused: e instanceof Error ? e.message : String(e), ...(e instanceof Refused && e.head ? { head: true } : {}) });
    }
    const wants = [...h.wants.values()];
    if (!wants.length) return done({ refused: "internal: pending with nothing to fetch" });
    if (stats.rounds === MAX_ROUNDS) return done({ refused: `no answer after ${MAX_ROUNDS} rounds` });
    stats.rounds++;
    // Touching ranges of one file go as one request, as the full client's.
    const sorted = [...wants].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : (a.off ?? 0) - (b.off ?? 0)));
    const merged: Want[] = [];
    for (const w of sorted) {
      const m = merged[merged.length - 1];
      if (m && w.off !== undefined && m.off !== undefined && m.path === w.path && m.off + m.len! === w.off) m.len! += w.len!;
      else merged.push({ path: w.path, off: w.off, len: w.len });
    }
    // A failed request fails only its own wants: the verifier refuses whatever needed them, and may answer from another run.
    const got = await Promise.allSettled(merged.map((w) => fetchWant(base, w)));
    stats.requests += merged.length;
    stats.bytes += got.reduce((n, r) => n + (r.status === "fulfilled" ? r.value.length : 0), 0);
    wants.forEach((w) => {
      const i = merged.findIndex((m) => m.path === w.path && (w.off === undefined || (m.off! <= w.off && w.off + w.len! <= m.off! + m.len!)));
      const r = got[i]!;
      if (r.status === "rejected") return h.fail(w, `fetch failed: ${r.reason instanceof Error ? r.reason.message : r.reason}`);
      const body = w.off === undefined ? r.value : r.value.slice(w.off - merged[i]!.off!, w.off - merged[i]!.off! + w.len!);
      if (mutate && !tampered) tampered = mutate(w, body, stats.rounds) ?? undefined;
      h.put(w, body);
    });
  }
}

/** One read: head, manifest and pages fetched and checked; `session` keeps what earlier reads checked. */
export async function run(base: string, q: Query, mutate?: Mutate, session = new Session()): Promise<Outcome> {
  const { value, ...o } = await loop(base, session, (h) => read(h, q), mutate);
  return value ? { ...o, answer: value } : o;
}

/** Adopt the checkpoint `head/checkpoint` names, if this session's head proved it (verify.ts `adopt`). */
export const rotate = (base: string, session: Session) => loop(base, session, (h) => adopt(h));

/** Fetch the hint files earlier reads planned without; one that fails leaves its layer unhinted. */
export async function fetchHints(base: string, session: Session): Promise<number> {
  const wants = hintsLater(session);
  const got = await Promise.allSettled(wants.map((w) => fetchWant(base, w)));
  wants.forEach((w, i) => takeHints(session, w.path, got[i]!.status === "fulfilled" ? (got[i] as PromiseFulfilledResult<Uint8Array>).value : null));
  return got.reduce((n, r) => n + (r.status === "fulfilled" ? r.value.length : 0), 0);
}

/** Where a page remembers its newest proven checkpoint: localStorage, or nothing. */
export type CheckpointStore = { get(): string | null; set(root: string | null): void };
const ROOT_RE = /^0x[0-9a-f]{64}$/;

/**
 * A page's reader: one session of checked index pages, trie nodes and
 * committees, started from the newest checkpoint the page remembers.
 *
 * The remembered checkpoint is a cache of something this code proved: a
 * root `adopt` took only after period updates, signed by the committees
 * the built-in checkpoint leads to, proved it finalized. Reading it back
 * proves nothing by itself, and need not: whoever can write this page's
 * storage (on storage.googleapis.com, any bucket's page, since buckets
 * share the origin) can only name a root, and the root is then held to
 * everything the built-in one is: its bootstrap, from this page's bucket,
 * must hash to it and prove its committee, and every head after it must
 * be signed by committees that bootstrap leads to. It must also be newer
 * than the built-in checkpoint and older than the clock (verify.ts), so it
 * can never roll the page back. A root the bucket has no honest bootstrap
 * for, garbage, or a value that fails any check, refuses the head; the
 * reader then reads again from the built-in checkpoint, and forgets the
 * remembered one if that works. Only a bucket that serves forged
 * bootstraps could make a written root stick, and that bucket serves this
 * page's code too.
 */
export class Reader {
  session: Session;
  /** The after-read work (rotation, hint files) of the latest read. */
  idle: Promise<void> = Promise.resolve();
  private rotated = false;
  constructor(
    readonly base: string,
    readonly store?: CheckpointStore,
  ) {
    const r = store?.get()?.toLowerCase();
    this.session = new Session(r && ROOT_RE.test(r) && r !== CHECKPOINT ? r : CHECKPOINT);
  }

  /** A tampered read starts a session of its own from the same checkpoint, so the targeted page is fetched, not remembered. */
  async read(q: Query, mutate?: Mutate): Promise<Outcome> {
    if (mutate) return run(this.base, q, mutate, new Session(this.session.checkpoint));
    let o = await run(this.base, q, undefined, this.session);
    if (o.head && this.session.checkpoint !== CHECKPOINT) {
      const first = o;
      this.session = new Session();
      o = await run(this.base, q, undefined, this.session);
      for (const k of ["rounds", "requests", "bytes", "ms"] as const) o.stats[k] += first.stats[k];
      o.fellBack = first.refused;
      if (!o.head) this.store?.set(null);
    }
    if (o.answer) this.idle = this.afterRead();
    return o;
  }

  /** Once a page: adopt a newer checkpoint for the next visit. Then the hint files for the next read. */
  private async afterRead() {
    if (!this.rotated) {
      this.rotated = true;
      const r = await rotate(this.base, this.session);
      if (r.value) this.store?.set(r.value.root);
    }
    await fetchHints(this.base, this.session);
  }
}
