// The rounds: every request the page made, as a bar from when it was sent
// to when its body landed, on the drive's real clock, grouped by round.
// The client's own computations (each `step`) are the small ticks on the
// lane's line: everything between them is waiting on the network. A race
// puts both clients on one axis, after their two opening drives (drawn
// collapsed, one row each). A failed request stays drawn, outlined red; the
// tamper demonstration's flip is marked at the moment it happened.

import type { Focus } from "./bucket.ts";
import { type Cursor, type Lane, type PageRef, type Scene, esc, fileShort, kb, ms, pagesOf } from "./model.ts";
import { C, LANE, rgba, roundColor } from "./palette.ts";

const ROW = 15;
const HEAD = 18;
const AXIS = 20;

/// What a request fetched, in words: which pages of which table, or which file.
export function reqLabel(scene: Scene, file: string, offset: number | null, length: number | null): string {
  const pages = pagesOf(scene.tables, file, offset, length);
  const t = scene.tables.find((x) => x.file === file);
  if (t && pages.length) return `${t.name} ${pagesText(pages)}`;
  if (file.startsWith("head/bootstrap/")) return "head/bootstrap";
  if (file.startsWith("head/")) return file;
  if (file.endsWith("manifest.json") || file.includes("manifest")) return "manifest";
  if (file.startsWith("blobs/")) return `blob ${file.slice(6, 14)}…`;
  return fileShort(file);
}

export function pagesText(pages: PageRef[]): string {
  const p0 = pages.some((p) => p.kind === "page0");
  const data = pages.filter((p) => p.kind === "data").map((p) => p.index);
  const model = pages.filter((p) => p.kind === "model").map((p) => p.index);
  const span = (xs: number[]) => (xs.length === 1 ? `${xs[0]!.toLocaleString()}` : `${xs[0]!.toLocaleString()}–${xs[xs.length - 1]!.toLocaleString()}`);
  const parts: string[] = [];
  if (p0) parts.push("page 0");
  if (data.length) parts.push(`${data.length === 1 ? "page" : "pages"} ${span(data)}`);
  if (model.length) parts.push(`model ${model.length === 1 ? "page" : "pages"} ${span(model)}`);
  return parts.join(" + ");
}

interface Row {
  lane: number;
  round: number;
  index: number;
  start: number;
  end: number | null;
  label: string;
  bytes: number;
  status: number;
  failed: boolean;
  /// When the tamper demonstration flipped a byte of this response.
  tamperT: number | null;
}

function rowsOf(scene: Scene, li: number): Row[] {
  const l = scene.lanes[li]!;
  const rows: Row[] = l.reqs.map((r) => ({
    lane: li,
    round: r.round,
    index: r.index ?? 0,
    start: l.offset + r.start,
    end: l.offset + r.end,
    label: reqLabel(scene, r.file, r.offset, r.length),
    bytes: r.bytes,
    status: r.status,
    failed: r.failed,
    tamperT: r.tampered ? r.tampered.t : null,
  }));
  for (const q of l.sent) {
    rows.push({ lane: li, round: q.round, index: q.index, start: l.offset + q.start, end: null, label: reqLabel(scene, q.file, q.offset, q.length), bytes: 0, status: 0, failed: false, tamperT: null });
  }
  rows.sort((a, b) => a.round - b.round || a.index - b.index);
  return rows;
}

export function sceneEnd(scene: Scene): number {
  let t = 0;
  for (const l of [...scene.setup, ...scene.lanes]) {
    t = Math.max(t, l.offset + l.ms);
    for (const r of l.reqs) t = Math.max(t, l.offset + r.end);
  }
  return t;
}

function niceStep(span: number, px: number): number {
  const target = span / Math.max(2, px / 90);
  const p = 10 ** Math.floor(Math.log10(target));
  for (const m of [1, 2, 5, 10]) if (m * p >= target) return m * p;
  return 10 * p;
}

export function renderWaterfall(scene: Scene | null, cur: Cursor, focus: Focus, width: number, fixedEnd: number | null): string {
  const W = Math.max(300, width);
  if (!scene) return `<svg width="${W}" height="40"></svg>`;
  const race = scene.kind === "race";
  const gutter = Math.min(280, Math.max(252, W * 0.22));
  const right = 70;
  const lanes = scene.lanes.map((_, i) => rowsOf(scene, i));
  const T = Math.max(fixedEnd ?? 0, sceneEnd(scene), cur.t, 20);
  const x = (t: number) => gutter + (Math.max(0, t) / T) * (W - gutter - right);
  const parts: string[] = [];
  // Rows: per lane a header line, then per round a label and its requests.
  let y = AXIS + 4;
  const laneY: number[] = [];
  const body: string[] = [];
  const steps = (l: Lane) => {
    for (const s of l.steps) {
      const a = l.offset + s.start;
      if (a > cur.t) continue;
      const b = Math.min(l.offset + s.end, cur.t);
      const w = Math.max(2, x(b) - x(a));
      body.push(`<rect x="${x(a)}" y="${y + 3}" width="${w}" height="10" rx="1.5" fill="${C.ink2}" opacity="0.8"><title>client computed ${ms(s.end - s.start)}${s.round === 0 ? " (the call that began the drive)" : ` (step after round ${s.round})`}</title></rect>`);
    }
  };
  // A race's setup: each fresh client proving the head, collapsed to one row.
  scene.setup.forEach((l, si) => {
    if (l.offset > cur.t) return;
    const who = l.name === "baseline" ? "by-hash" : "path-keyed";
    body.push(`<text x="4" y="${y + 12}" font-size="11" font-weight="600" class="t-muted">${esc(`setup · opening the ${who} client`)}</text>`);
    body.push(`<line x1="${gutter}" x2="${W - right}" y1="${y + 8}" y2="${y + 8}" stroke="${C.grid}"/>`);
    steps(l);
    const shown = l.reqs.filter((r) => l.offset + r.start <= cur.t);
    const inflight = l.sent.filter((q) => l.offset + q.start <= cur.t).length;
    const rounds = new Set(shown.map((r) => r.round)).size;
    y += HEAD - 2;
    body.push(`<text x="42" y="${y + 11}" font-size="10.5" class="t-muted">${esc(`${shown.length} requests, ${rounds} rounds${inflight ? `, ${inflight} in flight` : ""}${l.error ? ` · failed: ${l.error}` : ""}`)}</text>`);
    for (const r of shown) {
      const id = `s${si}:${r.round}:${r.index ?? 0}`;
      const a = l.offset + r.start;
      const landed = l.offset + r.end <= cur.t;
      const e = landed ? l.offset + r.end : cur.t;
      const bad = landed && r.failed;
      body.push(`<g class="req" data-req="${id}"><rect x="${x(a)}" y="${y + 4}" width="${Math.max(2, x(e) - x(a))}" height="${ROW - 8}" rx="2" fill="${bad ? "none" : rgba(C.slate, landed ? 0.75 : 0.3)}"${bad ? ` stroke="${C.bad}"` : ""}${focus.reqs.has(id) ? ` stroke="#fff" stroke-width="1.2"` : ""}/></g>`);
    }
    y += ROW + 6;
  });
  lanes.forEach((rows, li) => {
    const l = scene.lanes[li]!;
    laneY.push(y);
    const lc = race ? LANE[l.name] : C.ink2;
    const title = l.name === "open" ? "opening" : l.name === "baseline" ? "baseline · by hash" : race ? "path-keyed" : "this read";
    body.push(`<text x="4" y="${y + 12}" font-size="11.5" font-weight="600" fill="${lc}">${esc(title)}</text>`);
    // The client's computations, on the lane's line.
    body.push(`<line x1="${gutter}" x2="${W - right}" y1="${y + 8}" y2="${y + 8}" stroke="${C.grid}"/>`);
    steps(l);
    if (l.done && l.offset + l.ms <= cur.t) {
      body.push(`<text x="${x(l.offset + l.ms) + 6}" y="${y + 12}" font-size="11" class="t-ink2">${esc(ms(l.ms))}</text>`);
    }
    y += HEAD;
    let lastRound = -1;
    for (const r of rows) {
      if (r.start > cur.t) continue;
      const col = race ? LANE[l.name] : roundColor(r.round);
      if (r.round !== lastRound) {
        lastRound = r.round;
        body.push(`<line x1="0" x2="${W}" y1="${y + 0.5}" y2="${y + 0.5}" stroke="${C.grid}"/>`);
        body.push(`<rect x="4" y="${y + 2}" width="30" height="11" rx="2.5" fill="${roundColor(r.round)}" opacity="0.9"/><text x="19" y="${y + 10.5}" text-anchor="middle" font-size="9.5" font-weight="700" fill="#0d1016">R${r.round}</text>`);
      }
      const id = `${r.lane}:${r.round}:${r.index}`;
      const foc = focus.reqs.has(id);
      const landed = r.end !== null && r.end <= cur.t;
      const e = landed ? r.end! : cur.t;
      const bx = x(r.start);
      const bw = Math.max(2, x(e) - bx);
      const failed = landed && r.failed;
      const flipped = r.tamperT !== null && r.tamperT <= cur.t;
      const fill = failed ? rgba(C.bad, 0.12) : landed ? col : rgba(col, 0.35);
      body.push(`<g class="req" data-req="${id}">`);
      body.push(`<rect x="0" y="${y}" width="${W}" height="${ROW}" fill="${foc ? rgba("#ffffff", 0.06) : "transparent"}"/>`);
      body.push(`<text x="42" y="${y + 11}" font-size="10.5" class="mono ${foc ? "t-ink" : "t-ink2"}">${esc(r.label)}</text>`);
      body.push(`<rect x="${bx}" y="${y + 3}" width="${bw}" height="${ROW - 6}" rx="2" fill="${fill}"${foc ? ` stroke="#fff" stroke-width="1.2"` : failed ? ` stroke="${C.bad}" stroke-width="1.2"` : ""}${landed ? "" : ` stroke="${col}" stroke-dasharray="2 2"`}/>`);
      let tx = bx + bw + 5;
      if (flipped) {
        // The flip: after the whole round landed, before the client's step.
        const fx = x(r.tamperT!);
        body.push(`<line x1="${fx}" x2="${fx}" y1="${y + 1}" y2="${y + ROW - 1}" stroke="${C.bad}" stroke-width="2"/><path d="M${fx} ${y + 2} l4 5 l-4 5 l-4 -5 z" fill="${C.bad}"/>`);
        tx = Math.max(tx, fx + 7);
      }
      if (landed) {
        const st = r.status === 206 || r.status === 200 ? "" : r.status === 0 ? " · failed" : ` · HTTP ${r.status}`;
        const tag = flipped ? " · 1 byte flipped here" : "";
        const label = kb(r.bytes) + st + tag;
        // Near the right edge, the label goes inside the bar's end instead.
        if (tx + label.length * 5.6 > W - 2 && bw > label.length * 5.6 + 16) {
          const ix = (flipped ? x(r.tamperT!) : bx + bw) - 8;
          body.push(`<text x="${ix}" y="${y + 10.5}" font-size="10" font-weight="600" text-anchor="end" fill="#ffffff">${esc(label)}</text>`);
        } else body.push(`<text x="${tx}" y="${y + 11}" font-size="10" class="${failed || flipped ? "t-bad" : "t-muted"}">${esc(label)}</text>`);
      }
      body.push(`</g>`);
      y += ROW;
    }
    y += 6;
  });
  const H = y + 4;
  // The axis, and gridlines down the whole height.
  const step = niceStep(T, W - gutter - right);
  for (let t = 0; t <= T + 1e-6; t += step) {
    parts.push(`<line x1="${x(t)}" x2="${x(t)}" y1="${AXIS - 4}" y2="${H}" stroke="${C.grid}"/>`);
    parts.push(`<text x="${x(t)}" y="${AXIS - 8}" text-anchor="middle" font-size="10" class="t-muted">${esc(ms(t))}</text>`);
  }
  parts.push(...body);
  // The cursor: where on the real clock the views are.
  if (cur.t < T - 0.5 || fixedEnd !== null) {
    parts.push(`<line x1="${x(cur.t)}" x2="${x(cur.t)}" y1="${AXIS - 4}" y2="${H}" stroke="#ffffff" stroke-opacity="0.55" stroke-width="1"/>`);
  }
  void laneY;
  return `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}">${parts.join("")}</svg>`;
}

export type { Lane };
