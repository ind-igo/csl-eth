// The chain of trust, as the opening drive walked it: from the one trusted
// input (a beacon block root) through the sync committee's signatures to
// the finalized execution header, its state root, the snapshot's manifest
// and each table's page 0. A link is drawn from the client's verdict, not
// from timing: it turns green only once the client has accepted it, and
// red at the step where the client refused it. The head comes in at most
// two rounds: the bootstrap with the finality update, then the period
// updates between them (the bootstrap's period up to the one the finality
// update was signed in; none when they share it), asked for only once the
// bootstrap proved the checkpoint and the finality update was found fresh.
// So a request for an update is the client's acceptance of the bootstrap,
// the manifest's request is its acceptance of every update and the
// finality update (the verifier checks them in order before it asks), and
// a refusal names the step it stopped at: the bootstrap, a period's
// update, or the finality update (a stale head among them). Links before
// that step were accepted, links after it were never checked. Times come
// from the drive's own log and step timings.

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

/// A file's place in the chain: links are verified in this order. `null`
/// for a file that is no link (`latest`, the newest snapshot's manifest,
/// which the client fetches only to explain a refusal).
function rankOf(file: string, offset: number | null, manifest: string | null): number | null {
  if (file.startsWith("head/bootstrap/")) return 0;
  if (file.startsWith("head/updates/")) return 1 + Math.min(0.999, Number(file.slice(13)) / 1e9);
  if (file === "head/finality") return 2;
  if (file === manifest) return 3;
  if (!file.startsWith("head/") && !file.includes("manifest") && file !== "latest" && offset === 0) return 4;
  return null;
}

interface Verdict {
  /// The client accepted every link of rank below this (or all of them).
  acceptedBelow: number;
  /// The open failed, and the cursor has reached its refusal.
  refused: boolean;
  /// The rank of the link the refusal names, when it names one: links
  /// above it were never checked.
  refusedAt: number | null;
}

/// The state of the requests whose file satisfies `pick`, at the cursor,
/// judged by the client's verdict on the link of rank `rank`.
function stateOf(l: Lane, li: number, cur: Cursor, v: Verdict, rank: number, pick: (file: string, offset: number | null) => boolean): { state: State; reqs: string[]; status: number[]; bytes: number; round: number; unchecked?: boolean } {
  const rs = l.reqs.filter((r) => pick(r.file, r.offset));
  const sent = l.sent.filter((q) => pick(q.file, q.offset) && l.offset + q.start <= cur.t);
  const reqs = rs.map((r) => `${li}:${r.round}:${r.index ?? 0}`);
  if (!sent.length && rs.every((r) => l.offset + r.start > cur.t)) return { state: "wait", reqs, status: [], bytes: 0, round: 0 };
  const landed = rs.filter((r) => l.offset + r.end <= cur.t);
  const bytes = landed.reduce((s, r) => s + r.bytes, 0);
  const status = landed.map((r) => r.status);
  const round = Math.max(0, ...rs.map((r) => r.round));
  if (sent.length || landed.length < rs.length) return { state: "fetch", reqs, status, bytes, round };
  // The step that read these responses: the client's verdict is its output.
  const done = stepEndOf(l, round);
  if (done === undefined || done > cur.t) return { state: "check", reqs, status, bytes, round };
  if (rank < v.acceptedBelow) return { state: "ok", reqs, status, bytes, round };
  if (v.refused && v.refusedAt !== null && rank > v.refusedAt) return { state: "wait", reqs, status, bytes, round, unchecked: true };
  if (v.refused) return { state: "bad", reqs, status, bytes, round };
  return { state: "check", reqs, status, bytes, round };
}

export function renderChain(scene: Scene | null, cur: Cursor, focusReqs: Set<string>): string {
  const items: Item[] = [];
  const checkpoint = scene?.config.checkpoint ?? "";
  const li = scene ? scene.lanes.findIndex((l) => l.name === "open") : -1;
  const l = li >= 0 ? scene!.lanes[li]! : null;
  if (!l) {
    items.push({ title: "checkpoint", sub: `${short(checkpoint, 6)} · the one thing trusted: a beacon block root`, state: "ok", reqs: [] });
    for (const t of ["sync committee (bootstrap)", "period updates", "finality update", "execution header", "state root", "manifest", "each table's page 0"]) items.push({ title: t, sub: "", state: "wait", reqs: [] });
    return draw(items, focusReqs);
  }
  // The verdict, as of the cursor. The open's answer (its head, or its
  // error) is known from the end of its last step.
  const endT = l.offset + l.ms;
  const answered = l.done && cur.t >= endT - 1e-6;
  const head: Head | undefined = answered ? l.head : undefined;
  const refused = answered && !!l.error;
  // The snapshot's manifest is the first manifest the open fetched.
  const manifest = l.reqs.find((r) => r.file.includes("manifest"))?.file ?? l.sent.find((q) => q.file.includes("manifest"))?.file ?? null;
  // Links below the highest rank the client went on to request were
  // accepted (the requests are recorded; a request exists from the end of
  // the step that accepted what came before it). All are, once it answered
  // with a head.
  // The finality update is asked for with the bootstrap, so its request
  // accepts nothing; the updates are asked for together, so theirs
  // accepts the bootstrap only.
  let acceptedBelow = 0;
  for (const r of [...l.reqs, ...l.sent]) {
    const k = rankOf(r.file, r.offset, manifest);
    if (k === null || k === 2 || l.offset + r.start > cur.t) continue;
    acceptedBelow = Math.max(acceptedBelow, Math.floor(k));
  }
  if (head) acceptedBelow = Infinity;
  // A refusal names the step the verifier stopped at: everything before
  // it was accepted, whatever was requested.
  const at = refusalAt(refused ? l.error : undefined);
  if (refused && at.rank !== null) acceptedBelow = at.rank;
  else if (refused && at.headOk) acceptedBelow = Math.max(acceptedBelow, 3);
  const v: Verdict = { acceptedBelow, refused, refusedAt: at.rank };
  const failedAtStart = refused && l.reqs.length === 0;

  items.push({ title: "checkpoint", sub: failedAtStart ? `${short(checkpoint, 6)} · refused: ${l.error}` : `${short(checkpoint, 6)} · the one thing trusted: a beacon block root`, state: failedAtStart ? "bad" : "ok", reqs: [] });
  const boot = stateOf(l, li, cur, v, 0, (f) => f.startsWith("head/bootstrap/"));
  items.push({ title: "sync committee", sub: boot.state === "ok" ? `the bootstrap's 512 keys, proven against the checkpoint · ${kb(boot.bytes)}` : boot.state === "bad" ? `refused: ${l.error}` : "head/bootstrap", state: boot.state, reqs: boot.reqs });
  // Period updates: each hands over to the next committee, from the
  // bootstrap's period up to the one the finality update was signed in.
  // Only those are asked for; every one of them is required.
  const ups = l.reqs.filter((r) => r.file.startsWith("head/updates/"));
  const upSent = l.sent.filter((q) => q.file.startsWith("head/updates/"));
  const upFiles = [...new Set([...ups.map((r) => r.file), ...upSent.map((q) => q.file)])].sort((a, b) => Number(a.slice(13)) - Number(b.slice(13)));
  if (!upFiles.length) {
    if (head || (refused && at.headOk) || (refused && at.rank !== null && at.rank >= 3)) items.push({ title: "period updates (none)", sub: "the finality update is signed in the bootstrap's period, by the committee it proves", state: "ok", reqs: [] });
    else if (refused && at.rank !== null) items.push({ title: "period updates", sub: at.rank >= 2 ? "not asked for: the finality update was refused first" : "not asked for", state: "wait", reqs: [] });
    else items.push({ title: "period updates", sub: "", state: "wait", reqs: [] });
  }
  for (const f of upFiles) {
    const rank = rankOf(f, null, manifest)!;
    const s = stateOf(l, li, cur, v, rank, (x) => x === f);
    const period = f.slice("head/updates/".length);
    const missing = s.status.length > 0 && s.status.every((x) => x === 404);
    let sub = `head/updates/${period}`;
    let title = "period update";
    if (s.state === "ok") sub = `period ${period}: the next committee, signed by the last · ${kb(s.bytes)}`;
    else if (s.unchecked) sub = `period ${period}: not checked; the client refused an earlier link`;
    else if (s.state === "bad") {
      if (missing) title = "period update (not published)";
      sub = `period ${period}: refused: ${l.error}`;
    }
    items.push({ title, sub, state: s.state, reqs: s.reqs });
  }
  const fin = stateOf(l, li, cur, v, 2, (f) => f === "head/finality");
  const signers = fin.state === "bad" ? (at.stale ? `stale: ${l.error}` : `refused: ${l.error}`) : fin.unchecked ? "not checked; the client refused an earlier link" : head ? `signed by ${head.participants} of 512 committee members · ${kb(fin.bytes)}` : fin.state === "ok" ? `signed by the committee in hand · ${kb(fin.bytes)}` : "head/finality";
  items.push({ title: "finality update", sub: signers, state: fin.state, reqs: fin.reqs });
  // The execution header rides in the finality update, under a Merkle
  // branch to the beacon block; the client checks it in the same step.
  const exec: State = fin.state === "ok" ? "ok" : fin.state === "bad" || fin.state === "wait" ? "wait" : "check";
  items.push({ title: "execution header", sub: head ? `finalized block ${head.block_number.toLocaleString()}` : "inside the finality update", state: exec, reqs: fin.reqs });
  items.push({ title: "state root", sub: head ? `${short(head.state_root, 6)} · every answer is checked against this` : "", state: exec, reqs: [] });
  const man = stateOf(l, li, cur, v, 3, (f) => f === manifest);
  items.push({ title: "manifest", sub: man.state === "ok" ? `the snapshot at this block and state root · ${kb(man.bytes)}` : man.state === "bad" ? `refused: ${l.error}` : "names the snapshot's run files", state: man.state, reqs: man.reqs });
  if (scene!.tables.length) {
    for (const t of scene!.tables) {
      const s = stateOf(l, li, cur, v, 4, (f, off) => f === t.file && off === 0);
      // The open can succeed with a table it could not read: that table
      // answers nothing, and says why.
      const bad = !!t.error && (s.state === "ok" || !!head);
      items.push({
        title: `${t.name}, page 0`,
        sub: bad ? `unusable: ${t.error}` : s.state === "ok" ? `header and top model: ${t.page_count.toLocaleString()} pages, ${t.model_pages.toLocaleString()} model pages` : "the table's header and top model",
        state: bad ? "bad" : s.state,
        reqs: s.reqs,
      });
    }
  } else {
    // No layout reported (the open did not succeed): the page 0 requests as sent.
    const s = stateOf(l, li, cur, v, 4, (f, off) => rankOf(f, off, manifest) === 4);
    items.push({ title: "each table's page 0", sub: s.state === "bad" ? `refused: ${l.error}` : "the tables' headers and top models", state: s.state, reqs: s.reqs });
  }
  if (refused) items.push({ title: "refused", sub: l.error ?? "", state: "bad", reqs: [] });
  return draw(items, focusReqs);
}

/// Where a refused open stopped: the rank of the link its error names
/// (the bootstrap, a period's update, the finality update, the manifest),
/// or `null` with `headOk` for a refusal after the head (the snapshot's
/// own reads), or `null` alone when the error names no link.
function refusalAt(err: string | undefined): { rank: number | null; stale?: boolean; headOk?: boolean } {
  if (!err) return { rank: null };
  if (/head\/bootstrap\/|bootstrap rejected/.test(err)) return { rank: 0 };
  const m = err.match(/update for period (\d+) rejected/) ?? err.match(/head\/updates\/(\d+)/);
  if (m) return { rank: rankOf(`head/updates/${m[1]}`, null, null) };
  if (/stale head:/.test(err)) return { rank: 2, stale: true };
  if (/finality update rejected|head\/finality|no execution payload/.test(err)) return { rank: 2 };
  if (/no snapshot at finalized/.test(err)) return { rank: 3 };
  if (/snapshot:/.test(err)) return { rank: null, headOk: true };
  return { rank: null };
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
