// The bucket: every page of every table as a cell, page 0 and the model
// pages marked. A request's pages flash in its round's colour as its body
// lands and stay tinted for the scene; the pages that held the walk's
// nodes get a ring once the client has checked the node; pages fetched
// earlier in the session keep a faint heat. Cells are mapped from the
// layout the client reports (`Client.tables`), never guessed; a table the
// client rejected is not drawn. The layout is the bucket's claim, so the
// drawing is bounded by the canvas, not by it: when the pages outnumber
// the cells that fit, one cell stands for a run of consecutive pages.

import type { TableInfo } from "../protocol.ts";
import { type Cursor, type Lane, type PageRef, type Scene, pageKey, pageOfNode, pagesOf } from "./model.ts";
import { C, LANE, mix, rgba, roundColor } from "./palette.ts";

export interface Focus {
  pages: Set<string>;
  reqs: Set<string>;
  nodes: Set<string>;
}

interface Grid {
  table: TableInfo;
  y: number;
  labelY: number;
  cols: number;
  rows: number;
  /// Data cells and model cells (each `per` pages).
  data: number;
  model: number;
}

const LABEL = 18;
const GAP = 10;

export class BucketView {
  private ctx: CanvasRenderingContext2D;
  private base = document.createElement("canvas");
  private tables: TableInfo[] = [];
  private grids: Grid[] = [];
  private pitch = 3;
  private cell = 2;
  private w = 0;
  private h = 0;
  private dpr = 1;
  private dirty = true;
  /// Pages per cell: 1 unless the layout claims more pages than fit.
  per = 1;
  /// Times each page was delivered this session, from finished scenes,
  /// keyed by run file and page (a reopened snapshot is other files).
  private heatMap = new Map<string, number>();

  constructor(
    private canvas: HTMLCanvasElement,
    onHover: (p: PageRef | null, ev: MouseEvent) => void,
  ) {
    this.ctx = canvas.getContext("2d")!;
    canvas.addEventListener("mousemove", (e) => onHover(this.pageAt(e), e));
    canvas.addEventListener("mouseleave", (e) => onHover(null, e));
  }

  setTables(t: TableInfo[]) {
    this.tables = t.filter((x) => !x.error && x.page_count > 0);
    this.dirty = true;
  }

  private heatKey(p: PageRef): string | null {
    const t = this.tables.find((x) => x.id === p.table);
    return t ? `${t.file}|${pageKey(p)}` : null;
  }

  /// Times this page (of the file now drawn) was delivered this session.
  heat(p: PageRef): number {
    const k = this.heatKey(p);
    return k ? (this.heatMap.get(k) ?? 0) : 0;
  }

  /// Fit the grids to the canvas's box: the largest cell pitch that shows
  /// every page of every table.
  resize() {
    const r = this.canvas.getBoundingClientRect();
    this.dpr = window.devicePixelRatio || 1;
    this.w = Math.max(100, Math.floor(r.width));
    this.h = Math.max(100, Math.floor(r.height));
    this.canvas.width = this.w * this.dpr;
    this.canvas.height = this.h * this.dpr;
    this.base.width = this.canvas.width;
    this.base.height = this.canvas.height;
    const fits = (p: number, per: number) => {
      const cols = Math.floor((this.w - 2) / p);
      return this.tables.reduce((s, t) => s + LABEL + Math.ceil(this.cellsOf(t, per) / cols) * p + GAP, 0) <= this.h;
    };
    let pitch = 2;
    let per = 1;
    const p9 = [9, 8, 7, 6, 5, 4, 3, 2].find((p) => fits(p, 1));
    if (p9 !== undefined) pitch = p9;
    else {
      // More pages than cells: the smallest power-of-two run per cell that
      // fits at the smallest pitch.
      per = 2;
      while (!fits(2, per) && per < 1e300) per *= 2;
    }
    this.pitch = pitch;
    this.per = per;
    this.cell = pitch >= 3 ? pitch - 1 : pitch;
    const cols = Math.floor((this.w - 2) / pitch);
    // Never more cells than the canvas holds, whatever the layout claims.
    const cap = cols * Math.ceil(this.h / pitch);
    let y = 0;
    this.grids = this.tables.map((t) => {
      const data = Math.min(cap, Math.ceil(t.page_count / per));
      const model = Math.min(cap, Math.ceil(t.model_pages / per));
      const rows = Math.ceil((1 + data + model) / cols);
      const g = { table: t, labelY: y + 12, y: y + LABEL, cols, rows, data, model };
      y += LABEL + rows * pitch + GAP;
      return g;
    });
    this.dirty = true;
  }

  /// Cells of a table: page 0, the data pages, then the model pages.
  private cellsOf(t: TableInfo, per: number) {
    return 1 + Math.ceil(t.page_count / per) + Math.ceil(t.model_pages / per);
  }

  private cellIndex(g: Grid, p: PageRef) {
    const i = Math.floor((p.index - 1) / this.per);
    return p.kind === "page0" ? 0 : p.kind === "data" ? 1 + i : 1 + g.data + i;
  }

  /// The first page a cell stands for.
  private pageOfCell(g: Grid, c: number): PageRef {
    const t = g.table;
    if (c === 0) return { table: t.id, kind: "page0", index: 0 };
    if (c <= g.data) return { table: t.id, kind: "data", index: (c - 1) * this.per + 1 };
    return { table: t.id, kind: "model", index: (c - 1 - g.data) * this.per + 1 };
  }

  private xy(g: Grid, c: number): [number, number] {
    return [1 + (c % g.cols) * this.pitch, g.y + Math.floor(c / g.cols) * this.pitch];
  }

  private pageAt(e: MouseEvent): PageRef | null {
    const r = this.canvas.getBoundingClientRect();
    const x = e.clientX - r.left;
    const y = e.clientY - r.top;
    for (const g of this.grids) {
      if (y < g.y || y >= g.y + g.rows * this.pitch) continue;
      const c = Math.floor((y - g.y) / this.pitch) * g.cols + Math.floor((x - 1) / this.pitch);
      if (x < 1 || c < 0 || c >= 1 + g.data + g.model || Math.floor((x - 1) / this.pitch) >= g.cols) return null;
      return this.pageOfCell(g, c);
    }
    return null;
  }

  /// Where a page's cell is, in CSS pixels relative to the canvas.
  cellCentre(p: PageRef): [number, number] | null {
    const g = this.grids.find((x) => x.table.id === p.table);
    if (!g) return null;
    const [x, y] = this.xy(g, this.cellIndex(g, p));
    return [x + this.cell / 2, y + this.cell / 2];
  }

  /// Count the pages a finished scene's responses delivered.
  addHeat(scene: Scene) {
    for (const l of [...scene.setup, ...scene.lanes])
      for (const r of l.reqs)
        for (const p of r.pages) {
          const t = scene.tables.find((x) => x.id === p.table);
          if (!t) continue;
          const k = `${t.file}|${pageKey(p)}`;
          this.heatMap.set(k, (this.heatMap.get(k) ?? 0) + 1);
        }
    this.dirty = true;
  }

  private drawBase() {
    const b = this.base.getContext("2d")!;
    b.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
    b.clearRect(0, 0, this.w, this.h);
    for (const g of this.grids) {
      const t = g.table;
      b.font = "600 11px ui-sans-serif, system-ui, sans-serif";
      b.fillStyle = C.ink2;
      b.fillText(t.name, 1, g.labelY);
      const nameW = b.measureText(t.name).width;
      b.font = "11px ui-sans-serif, system-ui, sans-serif";
      b.fillStyle = C.muted;
      const extra = t.id === 3 ? " · the baseline's table" : "";
      const per = this.per > 1 ? ` · one cell is ${this.per.toLocaleString()} pages` : "";
      b.fillText(`  ${t.page_count.toLocaleString()} pages${extra}${per}`, 1 + nameW, g.labelY);
      const n = 1 + g.data + g.model;
      for (let c = 0; c < n; c++) {
        const [x, y] = this.xy(g, c);
        const p = this.pageOfCell(g, c);
        const h = this.per === 1 ? this.heat(p) : 0;
        b.fillStyle = c === 0 ? C.page0 : p.kind === "model" ? C.model : h ? mix(C.cell, C.heat, Math.min(1, 0.45 + 0.18 * Math.log2(h + 1))) : C.cell;
        b.fillRect(x, y, this.cell, this.cell);
      }
    }
    this.dirty = false;
  }

  draw(scene: Scene | null, cur: Cursor, focus: Focus, checkPages: { page: PageRef; state: "ok" | "bad" | "warn" }[]) {
    if (this.dirty) this.drawBase();
    const ctx = this.ctx;
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);
    ctx.drawImage(this.base, 0, 0);
    ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
    const cs = this.cell;
    const sq = (p: PageRef, grow: number, fill: string | null, stroke: string | null, lw = 1.5) => {
      const c = this.cellCentre(p);
      if (!c) return;
      const s = cs + grow * 2;
      if (fill) {
        ctx.fillStyle = fill;
        ctx.fillRect(c[0] - s / 2, c[1] - s / 2, s, s);
      }
      if (stroke) {
        ctx.strokeStyle = stroke;
        ctx.lineWidth = lw;
        ctx.strokeRect(c[0] - s / 2, c[1] - s / 2, s, s);
      }
    };
    if (scene) {
      const race = scene.kind === "race";
      const laneColor = (l: Lane, round: number) => (race ? LANE[l.name] : roundColor(round));
      for (const l of [...scene.setup, ...scene.lanes]) {
        for (const r of l.reqs) {
          const s = l.offset + r.start;
          const e = l.offset + r.end;
          if (cur.t < s) continue;
          const col = laneColor(l, r.round);
          if (r.failed) {
            // Asked for, never delivered: outlined in red once it failed.
            for (const p of cur.t < e ? r.asked : []) sq(p, 2, null, rgba(col, 0.6), 1);
            if (cur.t >= e) for (const p of r.asked) sq(p, 2, null, C.bad, 1.5);
            continue;
          }
          for (const p of r.pages) {
            if (cur.t < e) {
              const pulse = 0.5 + 0.5 * Math.sin((cur.t - s) / 60);
              sq(p, 2, null, rgba(col, 0.45 + 0.4 * pulse), 1);
            } else {
              const age = cur.t - e;
              const f = Math.max(0, 1 - age / 700);
              if (f > 0) sq(p, 1 + 5 * f, rgba(col, 0.25 + 0.5 * f), null);
              sq(p, 1, col, null);
            }
          }
        }
        // In-flight requests the live drive has sent but not landed yet.
        for (const q of l.sent) {
          if (cur.t < l.offset + q.start) continue;
          const pages = pagesOfSent(scene, q);
          for (const p of pages) sq(p, 2, null, rgba(laneColor(l, q.round), 0.8), 1);
        }
      }
    }
    for (const c of checkPages) sq(c.page, 3, null, c.state === "ok" ? C.ok : c.state === "bad" ? C.bad : C.warn, 1.5);
    for (const k of focus.pages) {
      const [table, kind, index] = k.split(":");
      const p = { table: Number(table), kind: kind as PageRef["kind"], index: Number(index) };
      sq(p, 5, null, "#ffffff", 2);
      const c = this.cellCentre(p);
      if (c) {
        ctx.strokeStyle = rgba("#ffffff", 0.35);
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(0, c[1] + 0.5);
        ctx.lineTo(c[0] - cs - 6, c[1] + 0.5);
        ctx.stroke();
      }
    }
  }
}

function pagesOfSent(scene: Scene, q: Lane["sent"][number]): PageRef[] {
  return pagesOf(scene.tables, q.file, q.offset, q.length);
}

/// The pages the walk's checked nodes came from, with the state to ring
/// them in: green for a node checked, red for one whose bytes failed,
/// amber for the page that should have held a node and did not.
export function checkedPages(scene: Scene | null, cur: Cursor, checks: { lane: number; walk: number; node: number; fail: boolean }[]) {
  const out: { page: PageRef; state: "ok" | "bad" | "warn" }[] = [];
  if (!scene) return out;
  for (const c of checks.slice(0, cur.checks)) {
    const lane = scene.lanes[c.lane];
    const tr = lane?.result?.trace;
    if (!tr) continue;
    if (c.walk < 0) {
      const p = tr.code?.page;
      if (p) out.push({ page: { table: tr.code!.table, kind: "data", index: p }, state: c.fail ? "warn" : "ok" });
      continue;
    }
    const n = tr.walks[c.walk]?.nodes[c.node];
    if (!n) continue;
    const p = pageOfNode(n);
    if (p) out.push({ page: p, state: n.kind === "invalid" ? "bad" : n.kind === "missing" ? "warn" : "ok" });
  }
  return out;
}
