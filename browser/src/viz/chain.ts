// The chain of trust, as the opening drive walked it: from the one trusted
// input (a beacon block root) through the sync committee's signatures to
// the finalized execution header, its state root, the snapshot's manifest
// and each table's page 0. A link lights when its file has landed and the
// client's next computation has accepted it (the drive's own log and step
// timings), with the numbers the client reported.

import type { Head } from "../protocol.ts";
import { type Cursor, type Lane, type Scene, esc, kb, short } from "./model.ts";

type State = "wait" | "fetch" | "check" | "ok" | "warn" | "bad";

interface Item {
  title: string;
  sub: string;
  state: State;
  reqs: string[];
}

function stepEndOf(l: Lane, round: number): number | undefined {
  const s = l.steps.find((x) => x.round === round);
  return s ? l.offset + s.end : undefined;
}

/// The state of the requests whose file satisfies `pick`, at the cursor.
function stateOf(l: Lane, li: number, cur: Cursor, pick: (file: string, offset: number | null) => boolean): { state: State; reqs: string[]; status: number[]; bytes: number; round: number } {
  const rs = l.reqs.filter((r) => pick(r.file, r.offset));
  const sent = l.sent.filter((q) => pick(q.file, q.offset) && l.offset + q.start <= cur.t);
  const reqs = rs.map((r) => `${li}:${r.round}:${r.index ?? 0}`);
  if (!rs.length && !sent.length) return { state: "wait", reqs, status: [], bytes: 0, round: 0 };
  if (sent.length || rs.some((r) => l.offset + r.start > cur.t)) {
    if (rs.every((r) => l.offset + r.start > cur.t) && !sent.length) return { state: "wait", reqs, status: [], bytes: 0, round: 0 };
  }
  const landed = rs.filter((r) => l.offset + r.end <= cur.t);
  const bytes = landed.reduce((s, r) => s + r.bytes, 0);
  const status = landed.map((r) => r.status);
  const round = rs[0]?.round ?? 0;
  if (sent.length || landed.length < rs.length) return { state: "fetch", reqs, status, bytes, round };
  const done = stepEndOf(l, round);
  if (done === undefined || done > cur.t) return { state: "check", reqs, status, bytes, round };
  return { state: "ok", reqs, status, bytes, round };
}

export function renderChain(scene: Scene | null, cur: Cursor, checkpoint: string, focusReqs: Set<string>): string {
  const items: Item[] = [];
  items.push({ title: "checkpoint", sub: `${short(checkpoint, 6)} · the one thing trusted: a beacon block root`, state: "ok", reqs: [] });
  const li = scene ? scene.lanes.findIndex((l) => l.name === "open") : -1;
  const l = li >= 0 ? scene!.lanes[li]! : null;
  const head: Head | undefined = l?.head;
  if (!l) {
    for (const t of ["sync committee (bootstrap)", "period updates", "finality update", "execution header", "state root", "manifest", "each table's page 0"]) items.push({ title: t, sub: "", state: "wait", reqs: [] });
    return draw(items, focusReqs);
  }
  const boot = stateOf(l, li, cur, (f) => f.startsWith("head/bootstrap/"));
  items.push({ title: "sync committee", sub: boot.state === "ok" ? `the bootstrap's 512 keys, proven against the checkpoint · ${kb(boot.bytes)}` : "head/bootstrap", state: boot.state, reqs: boot.reqs });
  // Period updates: each hands over to the next committee. The current
  // period's file is not published until the period ends: a 404 there is
  // expected, and the finality update is checked with the committee in hand.
  const ups = l.reqs.filter((r) => r.file.startsWith("head/updates/"));
  const upSent = l.sent.filter((q) => q.file.startsWith("head/updates/"));
  const upFiles = [...new Set([...ups.map((r) => r.file), ...upSent.map((q) => q.file)])];
  if (!upFiles.length) items.push({ title: "period update", sub: "", state: boot.state === "ok" ? "fetch" : "wait", reqs: [] });
  for (const f of upFiles) {
    const s = stateOf(l, li, cur, (x) => x === f);
    const period = f.slice("head/updates/".length);
    const missing = s.status.length > 0 && s.status.every((x) => x === 404);
    const sub = missing ? `period ${period}: not published yet (the current period); fine, the committee in hand signs the head` : s.state === "ok" ? `period ${period}: the next committee, signed by the last · ${kb(s.bytes)}` : `head/updates/${period}`;
    items.push({ title: missing ? "period update (none yet)" : "period update", sub, state: missing && s.state === "ok" ? "ok" : s.state, reqs: s.reqs });
  }
  const fin = stateOf(l, li, cur, (f) => f === "head/finality");
  const signers = head && fin.state === "ok" ? `signed by ${head.participants} of 512 committee members` : "head/finality";
  items.push({ title: "finality update", sub: signers + (fin.state === "ok" ? ` · ${kb(fin.bytes)}` : ""), state: fin.state, reqs: fin.reqs });
  // The execution header rides in the finality update, under a Merkle
  // branch to the beacon block; the client checks it in the same step.
  const exec = fin.state === "ok" ? "ok" : fin.state === "wait" ? "wait" : "check";
  items.push({ title: "execution header", sub: head && exec === "ok" ? `finalized block ${head.block_number.toLocaleString()}` : "inside the finality update", state: exec, reqs: fin.reqs });
  items.push({ title: "state root", sub: head && exec === "ok" ? `${short(head.state_root, 6)} · every answer is checked against this` : "", state: exec, reqs: [] });
  const tableFiles = new Set(scene!.tables.map((t) => t.file));
  const man = stateOf(l, li, cur, (f) => f.includes("manifest"));
  items.push({ title: "manifest", sub: man.state === "ok" ? `the snapshot at this block and state root · ${kb(man.bytes)}` : "names the snapshot's run files", state: man.state, reqs: man.reqs });
  for (const t of scene!.tables) {
    const s = stateOf(l, li, cur, (f, off) => f === t.file && off === 0);
    items.push({ title: `${t.name}, page 0`, sub: s.state === "ok" ? `header and top model: ${t.page_count.toLocaleString()} pages, ${t.model_pages.toLocaleString()} model pages` : "the table's header and top model", state: s.state, reqs: s.reqs });
  }
  void tableFiles;
  if (l.error) items.push({ title: "refused", sub: l.error, state: "bad", reqs: [] });
  return draw(items, focusReqs);
}

const ICON: Record<State, string> = { wait: "", fetch: "", check: "", ok: "✓", warn: "!", bad: "✗" };

function draw(items: Item[], focus: Set<string>): string {
  return `<ol class="chain">${items
    .map((it) => {
      const foc = it.reqs.some((r) => focus.has(r));
      return `<li class="ch ch-${it.state}${foc ? " focus" : ""}" data-reqs="${it.reqs.join(" ")}"><span class="dot">${ICON[it.state]}</span><div><b>${esc(it.title)}</b>${it.sub ? `<span>${esc(it.sub)}</span>` : ""}${it.state === "fetch" ? `<span class="tag">fetching…</span>` : it.state === "check" ? `<span class="tag">checking…</span>` : ""}</div></li>`;
    })
    .join("")}</ol>`;
}
