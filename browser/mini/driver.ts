// The I/O half of the minimal client: runs `read` from verify.ts, fetches
// every byte range it asks for in one parallel round, and repeats until it
// answers or refuses. Nothing here is trusted: it moves bytes, and a byte it
// gets wrong can only end in a refusal.

import { Held, Pending, read, type Answer, type Query, type Want } from "./verify.ts";

export type Stats = { rounds: number; requests: number; bytes: number; ms: number };
export type Outcome = { answer?: Answer; refused?: string; stats: Stats; tampered?: string };
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

/** One read from nothing: head, manifest, pages, all fetched and checked afresh. */
export async function run(base: string, q: Query, mutate?: Mutate): Promise<Outcome> {
  const h = new Held();
  const stats: Stats = { rounds: 0, requests: 0, bytes: 0, ms: 0 };
  const t0 = performance.now();
  let tampered: string | undefined;
  const done = (o: Omit<Outcome, "stats">): Outcome => ({ ...o, stats: { ...stats, ms: Math.round(performance.now() - t0) }, ...(tampered ? { tampered } : {}) });
  for (;;) {
    h.wants.clear();
    try {
      return done({ answer: read(h, q) });
    } catch (e) {
      if (!(e instanceof Pending)) return done({ refused: e instanceof Error ? e.message : String(e) });
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
    let got: Uint8Array[];
    try {
      got = await Promise.all(merged.map((w) => fetchWant(base, w)));
    } catch (e) {
      return done({ refused: `fetch failed: ${e instanceof Error ? e.message : e}` });
    }
    stats.requests += merged.length;
    stats.bytes += got.reduce((n, b) => n + b.length, 0);
    const bodies = wants.map((w) => {
      const i = merged.findIndex((m) => m.path === w.path && (w.off === undefined || (m.off! <= w.off && w.off + w.len! <= m.off! + m.len!)));
      return w.off === undefined ? got[i]! : got[i]!.slice(w.off - merged[i]!.off!, w.off - merged[i]!.off! + w.len!);
    });
    wants.forEach((w, i) => {
      if (mutate && !tampered) tampered = mutate(w, bodies[i]!, stats.rounds) ?? undefined;
      h.put(w, bodies[i]!);
    });
  }
}
