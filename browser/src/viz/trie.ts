// The trie path: the client's final walk from the state root down, node by
// node, as its trace reports it. A branch is its 16 slots (occupied dim,
// empty hollow, the one the key takes lit); an extension shows the nibbles
// it skips; a leaf shows the account or the slot. A node lights green when
// the client's check of it is reached on the timeline, and the link from
// its parent's slot turns solid: the bytes hashed to what the parent
// committed. The walk ends on the answer, the node that proves absence, or
// the node that failed.

import type { ReadResult, TraceNode, WalkTrace } from "../protocol.ts";
import type { Focus } from "./bucket.ts";
import { type Check, type Cursor, type Lane, type Scene, esc, eth, kb, ms, short } from "./model.ts";
import { C, LANE, rgba } from "./palette.ts";

const ROW = 58;
const LEAF_ROW = 64;
const LINK = 16;
const ROOT_H = 34;

interface Col {
  title: string;
  color?: string;
  lane: number;
  walks: number[];
}

/// Plain words for why a walk ended where it did.
export function explainEnd(lane: Lane, tampered: boolean): { tone: "ok" | "warn" | "bad"; head: string; body: string } | null {
  const r = lane.result;
  const tr = r?.trace;
  if (!r || !tr) return null;
  const end = tr.end;
  const w = tr.walks[tr.walks.length - 1];
  const last = w?.nodes[w.nodes.length - 1];
  const what = w?.trie === "storage" ? "slot" : "account";
  if (end.status === "verified") {
    if (tr.code) return { tone: "ok", head: "✓ verified", body: `The bytecode hashes to the code hash asked for: ${r.size?.toLocaleString()} bytes of bytecode, proven.` };
    if (r.value !== undefined) {
      const v = (r.value_dec ?? "").length > 18 ? short(r.value, 8) : `${r.value_dec} (${short(r.value, 6)})`;
      return { tone: "ok", head: "✓ verified", body: `Slot value ${v}. Every node on both paths hashed to what its parent committed: storage root, account leaf, state root.` };
    }
    return { tone: "ok", head: "✓ verified", body: `Nonce ${r.nonce?.toLocaleString()}, balance ${eth(r.balance ?? "0")}. Every node on the path hashed to what its parent committed, up to the state root.` };
  }
  if (end.status === "absent") {
    const at = last ? `depth ${last.depth}` : "";
    switch (end.by) {
      case "EmptySlot":
        return { tone: "ok", head: "✓ proven absent", body: `This branch (${at}) has no child for nibble ${last?.next?.toString(16)}: nothing can exist below it, so this ${what} does not exist in this state.` };
      case "ExtensionMismatch":
        return { tone: "ok", head: "✓ proven absent", body: `This extension (${at}) says every key below it continues with “${last?.nibbles}”; this key does not, so nothing below can match.` };
      case "LeafMismatch":
        return { tone: "ok", head: "✓ proven absent", body: `The only key under this position (${at}) ends “…${last?.rest?.slice(-6)}”, not this key: the ${what} does not exist.` };
      case "EmptyTrie":
        return { tone: "ok", head: "✓ proven absent", body: "The account's storage root is the empty trie: it has no storage at all." };
      default:
        return { tone: "ok", head: "✓ proven absent", body: String(end.by) };
    }
  }
  if (tampered && end.kind === "invalid") {
    return { tone: "bad", head: "✗ tampered byte caught", body: `The bytes served for the node at depth ${last?.depth} hash to ${short(last?.got, 6)}, not the ${short(last?.hash, 6)} its parent committed to. The client stops here: insufficient, never a wrong answer.` };
  }
  if (end.kind === "missing" && last?.from.kind === "not_served" && last.from.page) {
    return {
      tone: "warn",
      head: "! insufficient",
      body: `Page ${last.from.page.toLocaleString()} of ${last.from.name} is where this node would be, and it is not there: the bucket does not publish this part of the state. With nothing to check, the client says insufficient, never absent.`,
    };
  }
  if (end.kind === "invalid") {
    return { tone: "warn", head: "! insufficient", body: `A node at depth ${last?.depth} did not verify (${end.what}): the client refuses to answer from it.` };
  }
  return { tone: "warn", head: "! insufficient", body: end.reason ?? "the read could not be answered" };
}

function nodeState(scene: Scene, checks: Check[], cur: Cursor, lane: number, walk: number, node: number): "pending" | "ok" | "bad" | "warn" {
  for (let i = 0; i < Math.min(cur.checks, checks.length); i++) {
    const c = checks[i]!;
    if (c.lane === lane && c.walk === walk && c.node === node) {
      const n = scene.lanes[lane]!.result!.trace!.walks[walk]!.nodes[node]!;
      return n.kind === "invalid" ? "bad" : n.kind === "missing" ? "warn" : "ok";
    }
  }
  return "pending";
}

function columns(scene: Scene): Col[] {
  const cols: Col[] = [];
  scene.lanes.forEach((l, li) => {
    const walks = l.result?.trace?.walks ?? [];
    const label = l.name === "baseline" ? "baseline · each node by its hash" : "path-keyed · nodes by position";
    if (scene.kind === "race") {
      cols.push({ title: label, color: LANE[l.name], lane: li, walks: walks.map((_, i) => i) });
    } else if (walks.length === 2 && scene.kind === "read") {
      cols.push({ title: "account trie", lane: li, walks: [0] });
      cols.push({ title: "storage trie of this account", lane: li, walks: [1] });
    } else {
      cols.push({ title: scene.what === "code" ? "code table" : "account trie", lane: li, walks: walks.map((_, i) => i) });
    }
  });
  return cols;
}

const nodeH = (n: TraceNode, narrow = false) => (n.kind === "leaf" ? LEAF_ROW + (narrow ? 14 : 0) : ROW);

function originText(n: TraceNode, narrow: boolean): string {
  const f = n.from;
  switch (f.kind) {
    case "cache":
      return narrow ? "cached" : "top-level cache (kept from an earlier read)";
    case "embedded":
      return narrow ? "in its parent" : "inside its parent's bytes";
    case "page":
      return narrow ? `p. ${f.page.toLocaleString()}` : `${f.name} · page ${f.page.toLocaleString()}`;
    case "not_served":
      return f.page ? (narrow ? `p. ${f.page.toLocaleString()} lacks it` : `${f.name} · page ${f.page.toLocaleString()} lacks it`) : "not served";
  }
}

export function renderTrie(scene: Scene | null, checks: Check[], cur: Cursor, focus: Focus, width: number, opts: { stateRoot?: string; tampered: boolean }): { svg: string; height: number; latest: string | null } {
  const W = Math.max(280, width);
  if (!scene || scene.kind === "open") {
    const msg = scene?.kind === "open" ? (scene.lanes.every((l) => l.done) ? "The head is proven. Pick a key above and read it: its path from the state root down appears here." : "The head is being proven…") : "Open the bucket to begin.";
    return { svg: `<svg width="${W}" height="120" viewBox="0 0 ${W} 120"><text x="${W / 2}" y="60" text-anchor="middle" class="t-muted" font-size="13">${esc(msg)}</text></svg>`, height: 120, latest: null };
  }
  const cols = columns(scene);
  const pad = 12;
  const cw = (W - pad * (cols.length + 1)) / cols.length;
  const parts: string[] = [];
  let maxH = 0;
  let latest: string | null = null;
  const leafPos = new Map<number, { x: number; y: number; w: number; h: number }>();
  const rootPos = new Map<number, { x: number; y: number }>();
  cols.forEach((col, ci) => {
    const x0 = pad + ci * (cw + pad);
    const lane = scene.lanes[col.lane]!;
    const tr = lane.result?.trace;
    let y = 4;
    parts.push(`<g>`);
    if (col.color) parts.push(`<circle cx="${x0 + 5}" cy="${y + 9}" r="4.5" fill="${col.color}"/>`);
    parts.push(`<text x="${x0 + (col.color ? 15 : 0)}" y="${y + 13}" class="t-head">${esc(col.title)}</text>`);
    y += 24;
    if (!tr) {
      const root = opts.stateRoot;
      parts.push(rootBox(x0, y, cw, "state root", root ?? "", "signed into the finalized header", "pending"));
      const msg = lane.error ? `error: ${lane.error}` : lane.done ? `done in ${ms(lane.ms)}; its walk is drawn when both have finished` : "fetching the path's pages…";
      parts.push(`<text x="${x0 + 10}" y="${y + ROOT_H + 24}" class="t-muted" font-size="12">${esc(msg)}</text>`);
      maxH = Math.max(maxH, y + ROOT_H + 40);
      parts.push(`</g>`);
      return;
    }
    if (tr.code && col.walks.length === 0) {
      const c = tr.code;
      const done = cur.checks > 0 && checks.findIndex((k) => k.lane === col.lane && k.walk === -1) < cur.checks;
      const tone = !done ? "pending" : tr.end.status === "verified" ? "ok" : "warn";
      parts.push(rootBox(x0, y, cw, "code hash", c.code_hash, "the key: the bytecode must hash to it", "ok"));
      y += ROOT_H + LINK;
      parts.push(link(x0 + 22, y - LINK, x0 + 22, y, tone));
      const where = c.page ? `${c.name} · page ${c.page.toLocaleString()}` : "code table";
      const blob = c.blob ? ` → ${c.blob.slice(0, 18)}…` : "";
      parts.push(card(x0, y, cw, 50, tone, "code entry", where + blob, c.len !== null ? `${kb(c.len)} of bytecode · keccak(bytecode) = code hash` : "bytecode not served"));
      y += 50;
      if (done) {
        const e = explainEnd(lane, false);
        if (e) {
          const ec = endCard(x0, y + 10, cw, e.tone, e.head, e.body);
          parts.push(ec.svg);
          y += 10 + ec.h;
        }
      }
      maxH = Math.max(maxH, y + 10);
      parts.push(`</g>`);
      return;
    }
    col.walks.forEach((wi, k) => {
      const w = tr.walks[wi]!;
      const title = w.trie === "account" ? "state root" : "storage root";
      const sub = w.trie === "account" ? "signed into the finalized header" : "committed in the account leaf";
      // The storage root is known once the account leaf holding it is checked.
      const ai = tr.walks.findIndex((x) => x.trie === "account");
      const aw = tr.walks[ai];
      const known = w.trie === "account" || (aw !== undefined && aw.nodes.length > 0 && nodeState(scene, checks, cur, col.lane, ai, aw.nodes.length - 1) !== "pending");
      if (k > 0) y += 8;
      rootPos.set(ci * 10 + k, { x: x0, y });
      parts.push(rootBox(x0, y, cw, title, known ? w.root : "", known ? sub : "learned from the account leaf, once it is checked", known ? "ok" : "pending"));
      y += ROOT_H;
      if (w.nodes.length === 0) {
        if (known) parts.push(`<text x="${x0 + 10}" y="${y + 20}" class="t-ink2" font-size="12">the empty trie: no storage at all</text>`);
        y += 30;
        return;
      }
      let prevSlot: number = x0 + 22;
      let waiting = false;
      w.nodes.forEach((n, ni) => {
        if (waiting) return;
        const st = nodeState(scene, checks, cur, col.lane, wi, ni);
        const id = `${col.lane}:${wi}:${ni}`;
        y += LINK;
        if (st === "pending") {
          // Not checked yet at this point of the timeline: nothing is
          // drawn of it (its bytes may not even have arrived).
          waiting = true;
          parts.push(link(prevSlot, y - LINK, x0 + 22, y, "pending"));
          parts.push(`<rect x="${x0}" y="${y}" width="${cw}" height="30" rx="7" fill="none" stroke="${C.line}" stroke-dasharray="3 4"/><text x="${x0 + 10}" y="${y + 19}" class="t-muted" font-size="11.5">${lane.done ? "next: depth " + n.depth + ", not checked yet" : "waiting for pages…"}</text>`);
          y += 30;
          return;
        }
        latest = id;
        parts.push(link(prevSlot, y - LINK, x0 + 22, y, n.hash ? st : "embedded"));
        const h = nodeH(n, cw < 440);
        const r = drawNode(n, w, x0, y, cw, st, focus.nodes.has(id), id);
        parts.push(r.svg);
        prevSlot = r.out;
        if (n.kind === "leaf" && w.trie === "account") leafPos.set(ci, { x: x0, y, w: cw, h });
        y += h;
      });
    });
    // The end of the lane's walk, once every check is shown.
    const laneChecks = checks.map((c, i) => [c, i] as const).filter(([c]) => c.lane === col.lane);
    const lastIdx = laneChecks.length ? laneChecks[laneChecks.length - 1]![1] : -1;
    const lastCol = cols.filter((c) => c.lane === col.lane).pop() === col;
    if (lastCol && lane.done && cur.checks > lastIdx) {
      const e = explainEnd(lane, opts.tampered && !!lane.tamper);
      if (e) {
        y += 10;
        const ec = endCard(x0, y, cw, e.tone, e.head, e.body);
        parts.push(ec.svg);
        y += ec.h;
      }
    }
    maxH = Math.max(maxH, y + 8);
    parts.push(`</g>`);
  });
  // A storage read: the account leaf's storage root is where the storage walk starts.
  if (cols.length === 2 && scene.kind === "read") {
    const leaf = leafPos.get(0);
    const root = rootPos.get(10);
    if (leaf && root) {
      const x1 = leaf.x + leaf.w;
      const y1 = leaf.y + 30;
      const x2 = root.x;
      const y2 = root.y + ROOT_H / 2;
      parts.push(`<path d="M${x1},${y1} C${x1 + 10},${y1} ${x2 - 14},${y2} ${x2},${y2}" fill="none" stroke="${C.ok}" stroke-width="1.5" stroke-dasharray="3 3" opacity="0.8"/>`);
    }
  }
  const height = Math.max(maxH, 160);
  return { svg: `<svg width="${W}" height="${height}" viewBox="0 0 ${W} ${height}">${parts.join("")}</svg>`, height, latest };
}

function toneColor(t: string) {
  return t === "ok" ? C.ok : t === "bad" ? C.bad : t === "warn" ? C.warn : C.line;
}

function rootBox(x: number, y: number, w: number, title: string, hash: string, sub: string, tone: string): string {
  const col = tone === "pending" ? C.line : C.ok;
  return `<g><rect x="${x}" y="${y}" width="${w}" height="${ROOT_H}" rx="7" fill="${C.panel2}" stroke="${col}" stroke-width="1.2"/>
    <text x="${x + 10}" y="${y + 14}" class="t-ink" font-size="12" font-weight="600">${esc(title)}</text>
    <text x="${x + 10}" y="${y + 27}" class="t-muted" font-size="10.5">${esc(sub)}</text>
    ${hash ? `<text x="${x + w - 10}" y="${y + 14}" text-anchor="end" class="mono t-ink2" font-size="11">${esc(short(hash, w > 380 ? 8 : 5))}</text>` : ""}</g>`;
}

function link(x1: number, y1: number, x2: number, y2: number, tone: string): string {
  const col = tone === "pending" ? C.faint : tone === "embedded" ? C.ok : toneColor(tone);
  const dash = tone === "pending" ? ` stroke-dasharray="2 3"` : "";
  const my = (y1 + y2) / 2;
  const mark =
    tone === "ok"
      ? `<circle cx="${(x1 + x2) / 2}" cy="${my}" r="5.5" fill="${C.bg}" stroke="${C.ok}" stroke-width="1"/><path d="M${(x1 + x2) / 2 - 2.5},${my} l1.8,1.9 l3.2,-3.6" fill="none" stroke="${C.ok}" stroke-width="1.3"/>`
      : tone === "bad"
        ? `<circle cx="${(x1 + x2) / 2}" cy="${my}" r="5.5" fill="${C.bg}" stroke="${C.bad}" stroke-width="1"/><path d="M${(x1 + x2) / 2 - 2.3},${my - 2.3} l4.6,4.6 M${(x1 + x2) / 2 + 2.3},${my - 2.3} l-4.6,4.6" stroke="${C.bad}" stroke-width="1.3"/>`
        : "";
  return `<path d="M${x1},${y1} C${x1},${my} ${x2},${my} ${x2},${y2}" fill="none" stroke="${col}" stroke-width="${tone === "pending" ? 1 : 1.6}"${dash}/>${mark}`;
}

function drawNode(n: TraceNode, w: WalkTrace, x: number, y: number, cw: number, st: string, focused: boolean, id: string): { svg: string; out: number } {
  const h = nodeH(n, cw < 440);
  const tone = st === "pending" ? C.line : toneColor(st);
  const fill = st === "bad" ? rgba(C.bad, 0.08) : st === "warn" ? rgba(C.warn, 0.07) : C.panel2;
  const p: string[] = [];
  p.push(`<g class="node" data-node="${id}">`);
  p.push(`<rect x="${x}" y="${y}" width="${cw}" height="${h}" rx="7" fill="${fill}" stroke="${focused ? "#ffffff" : tone}" stroke-width="${focused ? 2 : st === "pending" ? 1 : 1.3}"/>`);
  const label = n.kind === "branch" ? "branch" : n.kind === "extension" ? "extension" : n.kind === "leaf" ? (w.trie === "account" ? "account leaf" : "slot leaf") : n.kind === "missing" ? "missing node" : "rejected node";
  const keep = cw < 440 ? 6 : 12;
  const pathTxt = n.at.length > keep + 2 ? `…${n.at.slice(-keep)}` : n.at || "(root)";
  p.push(`<text x="${x + 10}" y="${y + 15}" font-size="11.5"><tspan class="t-ink" font-weight="600">${label}</tspan><tspan class="t-muted" dx="6">depth ${n.depth}</tspan><tspan class="mono t-ink2" dx="6" font-size="10.5">${esc(pathTxt)}</tspan></text>`);
  p.push(`<text x="${x + cw - 10}" y="${y + 15}" text-anchor="end" class="t-muted" font-size="10.5">${esc(originText(n, cw < 440))}</text>`);
  let out = x + 22;
  const bodyY = y + 22;
  const hashLine = n.hash ? `keccak ${short(n.hash, cw > 420 ? 8 : 5)} · ${n.len} B` : `${n.len} B, covered by its parent's hash`;
  if (n.kind === "branch") {
    const s = Math.max(8, Math.min(18, Math.floor((cw - 20) / 16) - 3));
    const occ = n.occupied ?? 0;
    for (let i = 0; i < 16; i++) {
      const sx = x + 10 + i * (s + 3);
      const has = (occ >> i) & 1;
      const taken = i === n.next;
      let f = "none";
      let sk = C.faint;
      if (has) {
        f = "#2a3344";
        sk = "#3a4458";
      }
      if (taken) {
        sk = has ? (st === "pending" ? C.ink2 : toneColor(st)) : C.ok;
        f = has ? (st === "pending" ? rgba(C.ink2, 0.25) : rgba(toneColor(st), 0.35)) : "none";
      }
      p.push(`<rect x="${sx}" y="${bodyY}" width="${s}" height="${s}" rx="2.5" fill="${f}" stroke="${sk}" stroke-width="${taken ? 1.6 : 1}"${!has && taken ? ` stroke-dasharray="2 2"` : ""}/>`);
      if (s >= 12) p.push(`<text x="${sx + s / 2}" y="${bodyY + s / 2 + 3.5}" text-anchor="middle" font-size="9" class="mono ${taken ? "t-ink" : "t-muted"}">${i.toString(16)}</text>`);
      if (taken) out = sx + s / 2;
    }
    const bx = x + 10 + 16 * (s + 3) + 6;
    if (x + cw - bx > 120) p.push(`<text x="${x + cw - 10}" y="${bodyY + s / 2 + 4}" text-anchor="end" class="mono t-muted" font-size="10">${esc(hashLine)}</text>`);
    else p.push(`<text x="${x + 10}" y="${y + h - 5}" class="mono t-muted" font-size="10">${esc(hashLine)}</text>`);
  } else if (n.kind === "extension") {
    const txt = `skips ${n.nibbles?.length ?? 0} nibbles: ${n.nibbles ?? ""}`;
    p.push(`<rect x="${x + 10}" y="${bodyY}" width="${Math.min(cw - 20, 14 + txt.length * 6.6)}" height="18" rx="9" fill="${rgba(C.ink2, 0.08)}" stroke="${n.follows === false ? C.ok : C.line}"/>`);
    p.push(`<text x="${x + 18}" y="${bodyY + 13}" class="mono t-ink2" font-size="10.5">${esc(txt)}</text>`);
    p.push(`<text x="${x + 10}" y="${y + h - 6}" class="mono t-muted" font-size="10">${esc(hashLine)}</text>`);
  } else if (n.kind === "leaf") {
    let a = "";
    let b = "";
    if (n.account) {
      a = `nonce ${n.account.nonce.toLocaleString()} · balance ${eth(n.account.balance)}`;
      b = `storage ${short(n.account.storage_root, 4)} · code ${short(n.account.code_hash, 4)}`;
    } else if (n.word) {
      a = `value ${n.word.dec.length > 24 ? short(n.word.hex, 8) : n.word.dec}`;
      b = `rest of key …${n.rest?.slice(-8)}`;
    }
    if (n.matches === false) {
      a = `holds a different key: …${n.rest?.slice(-8)}`;
      b = "";
    }
    p.push(`<text x="${x + 10}" y="${bodyY + 12}" class="t-ink" font-size="12">${esc(a)}</text>`);
    if (b) p.push(`<text x="${x + 10}" y="${bodyY + 27}" class="mono t-muted" font-size="10">${esc(b)}</text>`);
    if (cw < 440) p.push(`<text x="${x + 10}" y="${bodyY + 41}" class="mono t-muted" font-size="10">${esc(hashLine)}</text>`);
    else p.push(`<text x="${x + cw - 10}" y="${bodyY + 27}" text-anchor="end" class="mono t-muted" font-size="10">${esc(hashLine)}</text>`);
  } else if (n.kind === "missing") {
    p.push(`<text x="${x + 10}" y="${bodyY + 13}" class="t-warn" font-size="12">expected ${esc(short(n.hash, 6))}; the bucket has no such node</text>`);
  } else {
    p.push(`<text x="${x + 10}" y="${bodyY + 13}" class="t-bad" font-size="12">expected ${esc(short(n.hash, 5))}</text>`);
    p.push(`<text x="${x + 10}" y="${bodyY + 28}" class="t-bad" font-size="12">served bytes hash to ${esc(short(n.got, 5))}</text>`);
  }
  p.push(`</g>`);
  return { svg: p.join(""), out };
}

function card(x: number, y: number, w: number, h: number, tone: string, title: string, a: string, b: string): string {
  const col = tone === "pending" ? C.line : toneColor(tone);
  return `<g><rect x="${x}" y="${y}" width="${w}" height="${h}" rx="7" fill="${C.panel2}" stroke="${col}" stroke-width="1.3"/>
  <text x="${x + 10}" y="${y + 16}" class="t-ink" font-size="12" font-weight="600">${esc(title)}</text>
  <text x="${x + w - 10}" y="${y + 16}" text-anchor="end" class="t-muted" font-size="10.5">${esc(a)}</text>
  <text x="${x + 10}" y="${y + 36}" class="t-ink2" font-size="12">${esc(b)}</text></g>`;
}

function wrap(text: string, width: number, size: number): string[] {
  const per = Math.max(20, Math.floor(width / (size * 0.53)));
  const words = text.split(" ");
  const lines: string[] = [];
  let cur = "";
  for (const w of words) {
    if ((cur + " " + w).trim().length > per) {
      lines.push(cur.trim());
      cur = w;
    } else cur += " " + w;
  }
  if (cur.trim()) lines.push(cur.trim());
  return lines;
}

function endCard(x: number, y: number, w: number, tone: "ok" | "warn" | "bad", head: string, body: string): { svg: string; h: number } {
  const col = toneColor(tone);
  const lines = wrap(body, w - 20, 11.5).slice(0, 5);
  const h = 26 + lines.length * 13 + 4;
  const svg = `<g class="end"><rect x="${x}" y="${y}" width="${w}" height="${h}" rx="8" fill="${rgba(col, 0.1)}" stroke="${col}" stroke-width="1.4"/>
  <text x="${x + 10}" y="${y + 16}" font-size="12.5" font-weight="700" fill="${col}">${esc(head)}</text>
  ${lines.map((l, i) => `<text x="${x + 10}" y="${y + 31 + i * 13}" class="t-ink" font-size="11.5">${esc(l)}</text>`).join("")}</g>`;
  return { svg, h: h + 6 };
}

export type { ReadResult };
