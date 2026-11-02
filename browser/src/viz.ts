// The visualizer: the same wasm client and driver as the main page. Live,
// on the real clock: every request this tab makes and every step its
// client computes. After a read answers: the client's trace of its final
// verified walk, each node check attributed to the client step that made
// it, replayed. Nothing is simulated: what moves is what this tab fetched
// and what its client reported, in the order and at the times they
// happened (replays may slow the clock down, and say so).

import { drive, loadWasm, type ClientLike, type DriveHooks, type WasmModule } from "./client.ts";
import type { Head, Need, ReadResult, TableInfo, TamperTarget } from "./protocol.ts";
import { BucketView, checkedPages, type Focus } from "./viz/bucket.ts";
import { renderChain } from "./viz/chain.ts";
import {
  type Check,
  type Config,
  type Cursor,
  type Lane,
  type PageRef,
  type Scene,
  type TamperNote,
  type What,
  Timeline,
  checksOf,
  esc,
  kb,
  landedPages,
  ms,
  newLane,
  pageKey,
  pageOfNode,
  pagesOf,
  plural,
  reqFailed,
  short,
} from "./viz/model.ts";
import { C, LANE, roundColor } from "./viz/palette.ts";
import { explainEnd, renderTrie } from "./viz/trie.ts";
import { reqLabel, renderWaterfall, sceneEnd } from "./viz/waterfall.ts";

const DEFAULT_BASE = "https://pub-a977a488180546bfb335de69b6f2e207.r2.dev";
const DEFAULT_CHECKPOINT = "0xe59d78041964322427cc209a44edcad243487378b78895a6cc0bfa7a7577cf0b";
/// Display time each node check takes in a replay or after a live read.
const CHECK_MS = 160;

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const el = {
  kind: $<HTMLSelectElement>("kind"),
  key: $<HTMLInputElement>("key"),
  slotWrap: $<HTMLLabelElement>("slotwrap"),
  slot: $<HTMLInputElement>("slot"),
  read: $<HTMLButtonElement>("read"),
  race: $<HTMLButtonElement>("race"),
  tamper: $<HTMLInputElement>("tamper"),
  chips: $<HTMLDivElement>("chips"),
  replay: $<HTMLDivElement>("replay"),
  stepPrev: $<HTMLButtonElement>("stepprev"),
  stepNext: $<HTMLButtonElement>("stepnext"),
  caption: $<HTMLDivElement>("caption"),
  chain: $<HTMLDivElement>("chain"),
  trieHead: $<HTMLDivElement>("triehead"),
  trie: $<HTMLDivElement>("trie"),
  bucket: $<HTMLCanvasElement>("bucket"),
  bucketWrap: $<HTMLDivElement>("bucketwrap"),
  bucketNote: $<HTMLDivElement>("bucketnote"),
  falls: $<HTMLDivElement>("falls"),
  readout: $<HTMLDivElement>("readout"),
  tip: $<HTMLDivElement>("tip"),
  base: $<HTMLInputElement>("base"),
  checkpoint: $<HTMLInputElement>("checkpoint"),
  prefetch: $<HTMLInputElement>("prefetch"),
  toplevels: $<HTMLInputElement>("toplevels"),
  reopen: $<HTMLButtonElement>("reopen"),
  status: $<HTMLSpanElement>("status"),
};

const params = new URLSearchParams(location.search);
el.base.value = params.get("bucket") ?? DEFAULT_BASE;
el.checkpoint.value = params.get("checkpoint") ?? DEFAULT_CHECKPOINT;

// --- state --------------------------------------------------------------------

let wasm: WasmModule | null = null;
let client: ClientLike | null = null;
let raceClients: ClientLike[] = [];
/// What the open client was opened with; races open theirs the same way,
/// whatever the settings panel says now.
let opened: Config | null = null;
let head: Head | null = null;
let tables: TableInfo[] = [];
let topLevels = 4;
let busy = false;
let sceneId = 0;

/// The opening drive (the chain of trust is drawn from it) and the scene
/// the other views show.
let openScene: Scene | null = null;
let scene: Scene | null = null;

/// How the views are driven: live (the real clock, as it happens), the
/// checks of a finished live read shown one by one, a slowed replay, or
/// one event at a time.
type Mode =
  | { kind: "idle" }
  | { kind: "live" }
  | { kind: "checks"; since: number; tl: Timeline }
  | { kind: "replay"; since: number; tl: Timeline; slow: number }
  | { kind: "step"; i: number; tl: Timeline };
let mode: Mode = { kind: "idle" };

const focus: Focus = { pages: new Set(), reqs: new Set(), nodes: new Set() };
let focusSig = "";

const bucket = new BucketView(el.bucket, (p, ev) => hoverPage(p, ev));

// --- recording a drive ------------------------------------------------------------

function newScene(kind: Scene["kind"], what: What, key: string, config: Config, slot?: string): Scene {
  return { id: ++sceneId, kind, what, key, slot, lanes: [], setup: [], t0: performance.now(), tables, config, head: head ?? undefined };
}

function readConfig(): Config {
  return {
    bucket: el.base.value.trim().replace(/\/+$/, ""),
    checkpoint: el.checkpoint.value.trim(),
    prefetch: Number(el.prefetch.value),
    topLevels: Number(el.toplevels.value),
  };
}

/// The pages a response asked for and delivered, from the scene's layout.
function placeReq(s: Scene, e: Parameters<NonNullable<DriveHooks["onResponse"]>>[0]) {
  return { pages: landedPages(s.tables, e), asked: pagesOf(s.tables, e.file, e.offset, e.length), failed: reqFailed(e) };
}

/// Drive `start` on `c`, recording into a new lane of `s` (of its setup
/// when `setup`).
async function record<T>(s: Scene, lane: Lane, c: ClientLike, start: () => string, tamper: boolean, setup = false): Promise<T> {
  lane.offset = performance.now() - s.t0;
  (setup ? s.setup : s.lanes).push(lane);
  const hooks: DriveHooks = {
    onRound(round: number, need: Need[], at: number) {
      lane.rounds = round;
      need.forEach((n, i) => lane.sent.push({ round, index: i, file: n.file, offset: n.offset ?? null, length: n.length ?? null, start: at }));
    },
    onResponse(e) {
      lane.sent = lane.sent.filter((q) => !(q.round === e.round && q.index === e.index));
      lane.reqs.push({ ...e, start: e.start ?? 0, end: e.end ?? 0, ...placeReq(s, e) });
    },
    onStep(st) {
      lane.steps.push(st);
    },
  };
  if (tamper) {
    lane.tamper = null;
    hooks.alter = (round, need, bodies) => {
      if (lane.tamper) return;
      const note = chooseTamper(c, round, need, bodies, performance.now() - s.t0);
      if (!note) return;
      lane.tamper = note;
      const r = lane.reqs.find((x) => x.round === round && x.index === note.index);
      if (r) r.tampered = note;
    };
  }
  try {
    const { result, trip } = await drive<T>(c, s.config.bucket, start, hooks);
    lane.ms = trip.ms;
    lane.rounds = trip.rounds;
    return result;
  } catch (e) {
    lane.error = e instanceof Error ? e.message : String(e);
    lane.ms = performance.now() - s.t0 - lane.offset;
    throw e;
  } finally {
    lane.sent = [];
    lane.done = true;
  }
}

/// The tamper demonstration's one flipped byte: among this round's
/// responses, the entries the client asked for that sit on fetched data
/// pages; the deepest node (the storage trie before the account trie on a
/// tie, then the first response) has the middle byte of its encoding
/// inverted. Deterministic for a given round's responses. `t` is when, on
/// the scene's clock: after the whole round landed, before the client's
/// step.
function chooseTamper(c: ClientLike, round: number, need: Need[], bodies: (Uint8Array | undefined)[], t: number): TamperNote | null {
  let best: { t: TamperTarget; i: number } | null = null;
  need.forEach((n, i) => {
    const b = bodies[i];
    if (!b || n.offset === undefined) return;
    const out = JSON.parse(c.tamper_targets(n.file, n.offset, b)) as { targets?: TamperTarget[] };
    // Only a non-empty value wholly inside this body is a target.
    const inside = (x: TamperTarget) => Number.isInteger(x.value_off) && Number.isInteger(x.value_len) && x.value_len > 0 && x.value_off >= 0 && x.value_off + x.value_len <= b.length;
    for (const t of (out.targets ?? []).filter(inside)) {
      const rank = (x: TamperTarget) => x.depth * 2 + (x.trie === "storage" ? 1 : 0);
      if (!best || rank(t) > rank(best.t)) best = { t, i };
    }
  });
  if (!best) return null;
  const { t: tg, i } = best as { t: TamperTarget; i: number };
  const body = bodies[i]!;
  const at = tg.value_off + Math.floor(tg.value_len / 2);
  const before = body[at]!;
  body[at] = before ^ 0xff;
  const n = need[i]!;
  return { round, index: i, file: n.file, table: tg.table, page: tg.page, trie: tg.trie, depth: tg.depth, byte: (n.offset ?? 0) + at, before, after: body[at]!, t };
}

// --- actions ---------------------------------------------------------------------

function setBusy(b: boolean) {
  busy = b;
  for (const x of [el.read, el.race, el.reopen]) x.disabled = b || (x !== el.reopen && !client);
  for (const x of el.chips.querySelectorAll("button")) (x as HTMLButtonElement).disabled = b || !client;
  updateReplayButtons();
}

/// A fresh client opened the way `cfg` says. Throws on a malformed
/// checkpoint.
function newClient(cfg: Config): ClientLike {
  return new wasm!.Client(cfg.checkpoint, Date.now(), cfg.prefetch, cfg.topLevels);
}

/// The client's layout, with each recorded request placed in it.
function adoptTables(s: Scene, c: ClientLike): TableInfo[] {
  const t = JSON.parse(c.tables()) as { tables: TableInfo[]; top_levels: number };
  s.tables = t.tables;
  for (const l of [...s.setup, ...s.lanes]) for (const r of l.reqs) Object.assign(r, placeReq(s, r));
  return t.tables;
}

async function open() {
  if (busy || !wasm) return;
  setBusy(true);
  client?.free();
  client = null;
  freeRace();
  head = null;
  tables = [];
  bucket.setTables([]);
  bucket.resize();
  const cfg = readConfig();
  topLevels = cfg.topLevels;
  const s = newScene("open", "open", "", cfg);
  openScene = s;
  scene = s;
  mode = { kind: "live" };
  status("proving the head from the checkpoint…");
  const lane = newLane("open", 0);
  let c: ClientLike | null = null;
  try {
    try {
      c = newClient(cfg);
    } catch (e) {
      // Refused before any request: the checkpoint itself.
      lane.offset = 0;
      lane.done = true;
      lane.error = e instanceof Error ? e.message : String(e);
      s.lanes.push(lane);
      throw e;
    }
    const cc = c;
    const h = await record<Head>(s, lane, cc, () => cc.open(), false);
    lane.head = h;
    head = h;
    s.head = h;
    client = cc;
    opened = cfg;
    tables = adoptTables(s, cc);
    topLevels = (JSON.parse(cc.tables()) as { top_levels: number }).top_levels;
    bucket.setTables(tables);
    bucket.resize();
    bucket.addHeat(s);
    const lag = h.finality_lag_secs;
    const ago = lag < 7200 ? `${Math.round(lag / 60)} min` : `${(lag / 3600).toFixed(1)} h`;
    const bad = tables.filter((t) => t.error).map((t) => `${t.name} (${t.error})`);
    status(`head verified: block ${h.block_number.toLocaleString()}, finalized ${ago} ago, signed by ${h.participants} of 512. ${bad.length ? `Unusable: ${bad.join(", ")}.` : "Pick a key."}`, bad.length > 0);
  } catch (e) {
    if (c && client !== c) c.free();
    status(`not verified: ${e instanceof Error ? e.message : e}`, true);
  } finally {
    mode = { kind: "idle" };
    setBusy(false);
    dirtyAll();
  }
}

function readStart(c: ClientLike, what: What, key: string, slot: string, baseline: boolean): () => string {
  return what === "account" ? () => c.account(key, baseline) : what === "storage" ? () => c.storage(key, slot || "0", baseline) : () => c.code(key);
}

async function read() {
  if (busy || !client) return;
  const what = el.kind.value as What;
  const key = el.key.value.trim();
  const slot = el.slot.value.trim();
  if (!key) return;
  setBusy(true);
  const tamper = el.tamper.checked;
  const s = newScene("read", what, key, opened!, what === "storage" ? slot || "0" : undefined);
  scene = s;
  mode = { kind: "live" };
  clearFocus();
  status(tamper ? "reading; one byte of one fetched page will be flipped before the client sees it…" : "reading…");
  const lane = newLane("path", 0);
  try {
    const c = client;
    lane.result = await record<ReadResult>(s, lane, c, readStart(c, what, key, slot, false), tamper);
    afterRead(s);
  } catch (e) {
    status(`error: ${e instanceof Error ? e.message : e}`, true);
    mode = { kind: "idle" };
  } finally {
    if (tamper) el.tamper.checked = false;
    setBusy(false);
    dirtyAll();
  }
}

/// The same key, path-keyed and by hash, on two fresh clients opened on
/// the same checkpoint the way the shown client was (each with its own
/// store: equally cold), started at the same moment. Their opening drives
/// are recorded as the scene's setup. The race is refused if either client
/// proves a different head or snapshot from the one shown, or from each
/// other.
async function race() {
  if (busy || !client || !wasm || !opened || !head) return;
  const what = el.kind.value as What;
  if (what === "code") {
    status("a race compares trie walks: pick an account or a storage slot", true);
    return;
  }
  const key = el.key.value.trim();
  const slot = el.slot.value.trim();
  if (!key) return;
  setBusy(true);
  clearFocus();
  freeRace();
  const shown = head;
  const s = newScene("race", what, key, opened, what === "storage" ? slot || "0" : undefined);
  scene = s;
  mode = { kind: "live" };
  status("opening two fresh clients on the same checkpoint (neither has read anything yet)…");
  try {
    const pair = [newClient(s.config), newClient(s.config)];
    raceClients = pair;
    const setup = [newLane("path", 0), newLane("baseline", 0)];
    const heads = await Promise.all(pair.map((c, i) => record<Head>(s, setup[i]!, c, () => c.open(), false, true)));
    heads.forEach((h, i) => (setup[i]!.head = h));
    // Both must stand where the shown snapshot stands.
    const at = (h: Head) => `${h.block_hash}|${h.state_root}|${h.snapshot.block_hash}|${h.snapshot.state_root}`;
    const differ = heads.find((h) => at(h) !== at(shown));
    if (differ) {
      const blk = (h: Head) => `block ${h.block_number.toLocaleString()} (${short(h.block_hash, 4)}, state root ${short(h.state_root, 4)})`;
      throw new Error(`refused: the race clients proved ${heads.map(blk).join(" and ")}, the page shows ${blk(shown)}. Reopen, then race.`);
    }
    const ts = pair.map((c) => JSON.stringify((JSON.parse(c.tables()) as { tables: TableInfo[] }).tables.map((t) => [t.file, t.page_count, t.model_off, t.error])));
    if (ts[0] !== ts[1]) throw new Error("refused: the two race clients report different table layouts");
    s.head = heads[0];
    adoptTables(s, pair[0]!);
    status("racing: path-keyed and by hash, started together…");
    const lanes = [newLane("path", 0), newLane("baseline", 0)];
    const out = await Promise.allSettled(pair.map((c, i) => record<ReadResult>(s, lanes[i]!, c, readStart(c, what, key, slot, i === 1), false)));
    out.forEach((o, i) => {
      if (o.status === "fulfilled") lanes[i]!.result = o.value;
    });
    afterRead(s);
  } catch (e) {
    status(`race: ${e instanceof Error ? e.message : e}`, true);
    bucket.addHeat(s);
    mode = { kind: "idle" };
  } finally {
    setBusy(false);
    dirtyAll();
  }
}

function freeRace() {
  for (const c of raceClients) c.free();
  raceClients = [];
}

function afterRead(s: Scene) {
  bucket.addHeat(s);
  const tl = new Timeline(s, 1, CHECK_MS);
  mode = { kind: "checks", since: performance.now(), tl };
  const l = s.lanes[0]!;
  const r = l.result;
  if (s.kind === "race") {
    const [a, b] = s.lanes;
    status(`path-keyed: ${plural(a?.rounds ?? 0, "round")}, ${ms(a?.ms ?? 0)} · by hash: ${plural(b?.rounds ?? 0, "round")}, ${ms(b?.ms ?? 0)}. Now showing the ${tl.checks.length} node checks one by one.`);
  } else if (r) {
    const e = explainEnd(l, !!l.tamper);
    const tam = l.tamper === null ? " (tamper: this read's responses held no node to flip, so nothing was changed)" : "";
    status(`${e?.head ?? r.status} in ${ms(l.ms)}, ${plural(l.rounds, "round")}. Now showing ${s.what === "code" ? "the client's check of the code" : `the ${plural(tl.checks.length, "node check")} the client made, one by one`}.${tam}`);
  }
  // A contract's code is one click away.
  updateCodeChip(s);
}

// --- replay ------------------------------------------------------------------------

function replay(slow: number) {
  if (busy || !scene || !scene.lanes.every((l) => l.done)) return;
  mode = { kind: "replay", since: performance.now(), tl: new Timeline(scene, slow, CHECK_MS * Math.max(1, slow / 4)), slow };
  dirtyAll();
}

function stepBy(d: number) {
  if (busy || !scene || !scene.lanes.every((l) => l.done)) return;
  const tl = mode.kind === "step" ? mode.tl : new Timeline(scene, 1, CHECK_MS);
  const i = mode.kind === "step" ? Math.max(-1, Math.min(tl.evs.length - 1, mode.i + d)) : d > 0 ? 0 : tl.evs.length - 1;
  mode = { kind: "step", i, tl };
  dirtyAll();
}

function updateReplayButtons() {
  const can = !busy && !!scene && scene.lanes.length > 0 && scene.lanes.every((l) => l.done);
  for (const b of el.replay.querySelectorAll("button")) (b as HTMLButtonElement).disabled = !can;
}

// --- the cursor ------------------------------------------------------------------

function cursorNow(now: number): { cur: Cursor; checks: Check[]; fixedEnd: number | null; caption: string } {
  const s = scene;
  if (!s) return { cur: { t: 0, checks: 0 }, checks: [], fixedEnd: null, caption: "" };
  switch (mode.kind) {
    case "live": {
      const t = now - s.t0;
      const inflight = s.lanes.reduce((n, l) => n + l.sent.length, 0);
      const round = Math.max(0, ...s.lanes.map((l) => l.rounds));
      return { cur: { t, checks: 0 }, checks: [], fixedEnd: null, caption: `<b>live</b> · real time · round ${round}${inflight ? `, ${plural(inflight, "request")} in flight` : ""}` };
    }
    case "checks": {
      const tl = mode.tl;
      const n = Math.min(tl.checks.length, Math.floor((now - mode.since) / CHECK_MS) + 1);
      if (n >= tl.checks.length && now - mode.since > tl.checks.length * CHECK_MS + 400) mode = { kind: "idle" };
      return { cur: { t: tl.end().t, checks: n }, checks: tl.checks, fixedEnd: null, caption: checkCaption(s, tl.checks, n, "The final verified walk, from the client's trace: each check happened in the client step marked on the rounds axis (grey ticks); replayed one by one.") };
    }
    case "replay": {
      const tl = mode.tl;
      const d = now - mode.since;
      if (d > tl.total + 600) {
        mode = { kind: "idle" };
        return { cur: tl.end(), checks: tl.checks, fixedEnd: sceneEnd(s), caption: "" };
      }
      const cur = tl.cursorAt(d);
      const paused = cur.checks < tl.checks.length && tl.checks[cur.checks] && Math.abs(tl.checks[cur.checks]!.t - cur.t) < 1e-6 && checkPending(tl, d);
      const speed = mode.slow === 1 ? "real time" : `${mode.slow}× slower than real time`;
      return { cur, checks: tl.checks, fixedEnd: sceneEnd(s), caption: `<b>replay</b> · ${speed} · t = ${ms(cur.t)}${paused ? " · clock paused while a node check is shown (each takes microseconds)" : ""}` };
    }
    case "step": {
      const tl = mode.tl;
      const cur = mode.i < 0 ? { t: 0, checks: 0 } : tl.cursorAfter(mode.i);
      return { cur, checks: tl.checks, fixedEnd: sceneEnd(s), caption: stepCaption(s, tl, mode.i) };
    }
    case "idle": {
      const all = s.lanes.every((l) => l.done);
      const checks = all ? checksOf(s) : [];
      const end = all ? { t: Math.max(sceneEnd(s), 0), checks: checks.length } : { t: now - s.t0, checks: 0 };
      return { cur: end, checks, fixedEnd: null, caption: "" };
    }
  }
}

function checkPending(tl: Timeline, d: number): boolean {
  for (let i = 0; i < tl.evs.length; i++) {
    if (tl.evs[i]!.kind === "check" && d >= tl.at[i]! - tl.checkMs && d < tl.at[i]!) return true;
  }
  return false;
}

function nodeWords(s: Scene, c: Check): string {
  const l = s.lanes[c.lane]!;
  const tr = l.result?.trace;
  if (!tr) return "";
  if (c.walk < 0) return `the code entry: keccak of the bytecode equals the code hash asked for`;
  const w = tr.walks[c.walk]!;
  const n = w.nodes[c.node]!;
  const who = s.kind === "race" ? `${l.name === "baseline" ? "by hash" : "path-keyed"}: ` : "";
  const trie = w.trie === "account" ? "account trie" : "storage trie";
  if (n.kind === "invalid") return `${who}${trie} depth ${n.depth}: the bytes hash to ${short(n.got, 4)}, not ${short(n.hash, 4)}. Rejected.`;
  if (n.kind === "missing") return `${who}${trie} depth ${n.depth}: ${n.from.kind === "not_served" && n.from.page ? "the page that would hold the node does not" : "the node's bytes never reached the client"}. Nothing to check, so no answer.`;
  const what = n.kind === "branch" ? `branch, taking slot ${n.next?.toString(16)}` : n.kind === "extension" ? `extension over ${n.nibbles?.length} nibbles` : "leaf";
  const how = n.hash ? `hashes to ${short(n.hash, 4)}, the hash its ${n.depth === 0 ? (w.trie === "account" ? "state root" : "storage root") : "parent"} committed to` : "is inside its parent's bytes, already covered by its hash";
  return `${who}${trie} depth ${n.depth}: ${what}. Its ${n.len} bytes ${how}.`;
}

function checkIcon(s: Scene, c: Check): string {
  const n = c.walk >= 0 ? s.lanes[c.lane]?.result?.trace?.walks[c.walk]?.nodes[c.node] : undefined;
  return n?.kind === "invalid" ? "✗" : n?.kind === "missing" ? "!" : c.fail ? "!" : "✓";
}

function checkCaption(s: Scene, checks: Check[], n: number, lead: string): string {
  const c = checks[n - 1];
  return `${lead}${c ? ` <span class="cap-ev">${checkIcon(s, c)} ${esc(nodeWords(s, c))}</span>` : ""}`;
}

function stepCaption(s: Scene, tl: Timeline, i: number): string {
  if (i < 0) return `<b>step</b> · before anything was sent`;
  const e = tl.evs[i]!;
  const pre = `<b>step ${i + 1} of ${tl.evs.length}</b> · t = ${ms(e.t)} · `;
  const lane = (n: number) => (s.kind === "race" ? `${s.lanes[n]!.name === "baseline" ? "by hash" : "path-keyed"}: ` : "");
  switch (e.kind) {
    case "send": {
      const l = s.lanes[e.lane]!;
      const files = e.reqs.map((r) => {
        const q = l.reqs[r]!;
        return reqLabel(s, q.file, q.offset, q.length);
      });
      return `${pre}${lane(e.lane)}round ${e.round} goes out: ${plural(e.reqs.length, "request")} at once (${esc(files.slice(0, 3).join("; "))}${files.length > 3 ? "; …" : ""})`;
    }
    case "land": {
      const l = s.lanes[e.lane]!;
      const q = l.reqs[e.req]!;
      const how = q.failed ? `failed (${q.status ? `HTTP ${q.status}` : q.error ?? "no response"}), ${kb(q.bytes)}` : `${kb(q.bytes)}`;
      return `${pre}${lane(e.lane)}${esc(reqLabel(s, q.file, q.offset, q.length))} landed: ${esc(how)} after ${ms(q.end - q.start)}`;
    }
    case "tamper": {
      const tm = s.lanes[e.lane]!.tamper!;
      return `${pre}${lane(e.lane)}<span class="t-bad">the whole round has landed: the page flips byte ${tm.byte.toLocaleString()} of ${esc(pageName({ table: tm.table, kind: "data", index: tm.page }))} (0x${tm.before.toString(16).padStart(2, "0")} → 0x${tm.after.toString(16).padStart(2, "0")}) before the client's step reads it</span>`;
    }
    case "check":
      return `${pre}<span class="cap-ev">${checkIcon(s, tl.checks[e.check]!)} ${esc(nodeWords(s, tl.checks[e.check]!))}</span>`;
    case "done": {
      const l = s.lanes[e.lane]!;
      const x = explainEnd(l, !!l.tamper);
      return `${pre}${lane(e.lane)}done: ${esc(x?.head ?? l.result?.status ?? l.error ?? "")}`;
    }
  }
}

// --- hover linking -----------------------------------------------------------------

function clearFocus() {
  focus.pages.clear();
  focus.reqs.clear();
  focus.nodes.clear();
  el.tip.hidden = true;
}

function nodesOnPage(s: Scene, p: PageRef): string[] {
  const out: string[] = [];
  s.lanes.forEach((l, li) =>
    l.result?.trace?.walks.forEach((w, wi) =>
      w.nodes.forEach((n, ni) => {
        const q = pageOfNode(n);
        if (q && pageKey(q) === pageKey(p)) out.push(`${li}:${wi}:${ni}`);
      }),
    ),
  );
  return out;
}

function reqsWithPage(s: Scene, p: PageRef): string[] {
  const out: string[] = [];
  s.lanes.forEach((l, li) => l.reqs.forEach((r) => r.pages.some((q) => pageKey(q) === pageKey(p)) && out.push(`${li}:${r.round}:${r.index ?? 0}`)));
  return out;
}

function showTip(html: string, ev: MouseEvent) {
  el.tip.innerHTML = html;
  el.tip.hidden = false;
  const r = el.tip.getBoundingClientRect();
  let x = ev.clientX + 14;
  let y = ev.clientY + 14;
  if (x + r.width > innerWidth - 8) x = ev.clientX - r.width - 14;
  if (y + r.height > innerHeight - 8) y = ev.clientY - r.height - 14;
  el.tip.style.left = `${Math.max(8, x)}px`;
  el.tip.style.top = `${Math.max(8, y)}px`;
}

function pageName(p: PageRef, cell = false): string {
  const t = (scene?.tables ?? tables).find((x) => x.id === p.table);
  const name = t?.name ?? `table ${p.table}`;
  // A bucket cell may stand for a run of pages (a layout too large to draw).
  const run = cell && bucket.per > 1 && p.kind !== "page0" ? `s ${p.index.toLocaleString()}–${(p.index + bucket.per - 1).toLocaleString()} (one cell)` : ` ${p.index.toLocaleString()}`;
  return p.kind === "page0" ? `${name}, page 0 (header and top model)` : p.kind === "model" ? `${name}, model page${run}` : `${name}, page${run}`;
}

function hoverPage(p: PageRef | null, ev: MouseEvent) {
  clearFocus();
  if (p && scene) {
    focus.pages.add(pageKey(p));
    for (const r of reqsWithPage(scene, p)) focus.reqs.add(r);
    for (const n of nodesOnPage(scene, p)) focus.nodes.add(n);
    const heat = bucket.per === 1 ? bucket.heat(p) : 0;
    const lines = [`<b>${esc(pageName(p, true))}</b>`];
    if (focus.reqs.size) lines.push(`delivered to this ${scene.kind === "open" ? "opening" : "read"} (${[...focus.reqs].map((r) => `round ${r.split(":")[1]}`).join(", ")})`);
    if (focus.nodes.size) lines.push(`holds ${plural(focus.nodes.size, "node")} of the path: ${[...focus.nodes].map((id) => `depth ${depthOf(id)}`).join(", ")}`);
    if (bucket.per === 1) lines.push(heat ? `delivered ${plural(heat, "time")} this session` : "not delivered this session");
    showTip(lines.join("<br>"), ev);
  }
  dirtyAll();
}

function depthOf(id: string): number {
  const [l, w, n] = id.split(":").map(Number);
  return scene?.lanes[l!]?.result?.trace?.walks[w!]?.nodes[n!]?.depth ?? 0;
}

function hoverNode(id: string | null, ev: MouseEvent) {
  clearFocus();
  if (id && scene) {
    const [li, wi, ni] = id.split(":").map(Number);
    const l = scene.lanes[li!]!;
    const n = l.result?.trace?.walks[wi!]?.nodes[ni!];
    if (n) {
      focus.nodes.add(id);
      const p = pageOfNode(n);
      const lines = [`<b>${n.kind} at depth ${n.depth}</b>`, n.hash ? `keccak <span class="mono">${esc(short(n.hash, 10))}</span>` : "embedded in its parent"];
      if (p) {
        focus.pages.add(pageKey(p));
        for (const r of reqsWithPage(scene, p)) if (Number(r.split(":")[0]) === li) focus.reqs.add(r);
        lines.push(`${n.from.kind === "not_served" ? "looked for on" : "from"} ${esc(pageName(p))}`);
        if (focus.reqs.size) lines.push(`brought by round ${[...focus.reqs].map((r) => r.split(":")[1]).join(", ")}`);
      } else if (n.from.kind === "cache") lines.push(`from the top-level cache: verified on an earlier read (depth below ${topLevels})`);
      if (n.key) lines.push(`table key <span class="mono">${esc(short(n.key, 8))}</span>`);
      showTip(lines.join("<br>"), ev);
    }
  }
  dirtyAll();
}

function hoverReq(id: string | null, ev: MouseEvent) {
  clearFocus();
  if (id && scene) {
    const setup = id.startsWith("s");
    const [li, round, idx] = id.replace(/^s/, "").split(":").map(Number);
    const l = (setup ? scene.setup : scene.lanes)[li!]!;
    const r = l.reqs.find((x) => x.round === round && (x.index ?? 0) === idx);
    if (r) {
      focus.reqs.add(id);
      for (const p of r.pages) {
        focus.pages.add(pageKey(p));
        if (!setup) for (const n of nodesOnPage(scene, p)) if (Number(n.split(":")[0]) === li) focus.nodes.add(n);
      }
      const range = r.offset === null ? "whole file" : `bytes ${r.offset.toLocaleString()}–${(r.offset + (r.length ?? 0) - 1).toLocaleString()}`;
      const who = setup ? `setup: opening the ${l.name === "baseline" ? "by-hash" : "path-keyed"} client · ` : "";
      const lines = [`<b>${esc(reqLabel(scene, r.file, r.offset, r.length))}</b>`, `${who}round ${r.round} · ${range}`, `${r.status ? `HTTP ${r.status}` : `failed${r.error ? `: ${esc(r.error)}` : ""}`} · ${kb(r.bytes)} · ${ms(r.end - r.start)}`];
      if (r.failed) lines.push(`<span class="t-bad">no usable body: ${r.asked.length ? `${plural(r.asked.length, "page")} asked for, none delivered` : "nothing delivered"}</span>`);
      if (focus.nodes.size) lines.push(`held ${plural(focus.nodes.size, "node")} of the final path`);
      if (r.tampered) lines.push(`<span class="t-bad">byte ${r.tampered.byte.toLocaleString()} flipped (0x${r.tampered.before.toString(16).padStart(2, "0")} → 0x${r.tampered.after.toString(16).padStart(2, "0")}) at ${ms(r.tampered.t - l.offset)}, after the whole round landed and before the client's step read it</span>`);
      showTip(lines.join("<br>"), ev);
    }
  }
  dirtyAll();
}

el.trie.addEventListener("mousemove", (e) => {
  const g = (e.target as Element).closest?.("[data-node]");
  const id = g?.getAttribute("data-node") ?? null;
  if (id !== [...focus.nodes][0] || !focus.nodes.size) hoverNode(id, e);
  else if (id) showTip(el.tip.innerHTML, e);
});
el.trie.addEventListener("mouseleave", (e) => hoverNode(null, e));
el.falls.addEventListener("mousemove", (e) => {
  const g = (e.target as Element).closest?.("[data-req]");
  const id = g?.getAttribute("data-req") ?? null;
  if (id !== [...focus.reqs][0] || focus.reqs.size !== 1) hoverReq(id, e);
  else if (id) showTip(el.tip.innerHTML, e);
});
el.falls.addEventListener("mouseleave", (e) => hoverReq(null, e));
el.chain.addEventListener("mousemove", (e) => {
  const li = (e.target as Element).closest?.("[data-reqs]");
  const ids = li?.getAttribute("data-reqs")?.split(" ").filter(Boolean) ?? [];
  const sig = ids.join(",");
  if (sig === [...focus.reqs].join(",")) return;
  clearFocus();
  if (scene === openScene && openScene) {
    for (const id of ids) {
      focus.reqs.add(id);
      const [l, round, idx] = id.split(":").map(Number);
      const r = openScene.lanes[l!]?.reqs.find((x) => x.round === round && (x.index ?? 0) === idx);
      for (const p of r?.pages ?? []) focus.pages.add(pageKey(p));
    }
  }
  dirtyAll();
});
el.chain.addEventListener("mouseleave", () => {
  clearFocus();
  dirtyAll();
});

// --- drawing -------------------------------------------------------------------------

let dirty = true;
function dirtyAll() {
  dirty = true;
}

let lastTrieSig = "";
let lastChainSig = "";
let lastFallSig = "";

function frame(now: number) {
  try {
    draw(now);
  } catch (e) {
    console.error(e);
  }
  requestAnimationFrame(frame);
}

function draw(now: number) {
  const { cur, checks, fixedEnd, caption } = cursorNow(now);
  const animating = mode.kind !== "idle";
  const fSig = [...focus.pages, "|", ...focus.reqs, "|", ...focus.nodes].join(",");
  if (fSig !== focusSig) {
    focusSig = fSig;
    dirty = true;
  }
  if (animating || dirty) {
    const s = scene;
    // The trie path.
    const landed = s ? s.lanes.reduce((n, l) => n + l.reqs.filter((r) => l.offset + r.end <= cur.t).length, 0) : 0;
    // What the trie view shows changes with the checks shown, the open's
    // answer and the tamper flip being reached.
    const reached = s ? s.lanes.map((l) => `${l.done && cur.t >= l.offset + l.ms - 1e-6 ? 1 : 0}${l.tamper && cur.t >= l.tamper.t ? "t" : ""}`).join() : "";
    const tSig = `${s?.id}|${cur.checks}|${s?.lanes.map((l) => `${l.done}${l.reqs.length}`).join()}|${reached}|${fSig}|${el.trie.clientWidth}`;
    if (tSig !== lastTrieSig) {
      lastTrieSig = tSig;
      const out = renderTrie(s, checks, cur, focus, el.trie.clientWidth - 2, { stateRoot: s?.head?.state_root, tampered: true });
      el.trie.innerHTML = out.svg;
      if (animating && checks.length && cur.checks >= checks.length) {
        // Every check shown: bring the end of the walk(s) into view.
        const wrap = el.trie.getBoundingClientRect();
        const ends = [...el.trie.querySelectorAll(".end")].map((e) => e.getBoundingClientRect().bottom - wrap.top + el.trie.scrollTop);
        if (ends.length) el.trie.scrollTop = Math.max(...ends) - el.trie.clientHeight + 12;
      } else if (animating && out.latest) {
        const g = el.trie.querySelector(`[data-node="${out.latest}"]`) as SVGGElement | null;
        if (g) {
          const box = g.getBoundingClientRect();
          const wrap = el.trie.getBoundingClientRect();
          if (box.bottom > wrap.bottom - 20 || box.top < wrap.top) el.trie.scrollTop += box.bottom - wrap.bottom + 90;
        }
      }
      el.trieHead.innerHTML = trieHead(s, cur);
    }
    // The chain of trust: the opening drive, at its own cursor.
    const os = openScene;
    const oc = os && s === os ? cur : os ? { t: sceneEnd(os) + 1e6, checks: 0 } : cur;
    const cSig = `${os?.id}|${os === s ? landed : "end"}|${os?.lanes[0]?.sent.length}|${os?.lanes[0]?.steps.length}|${os === s ? Math.floor(cur.t) : 0}|${fSig}`;
    if (cSig !== lastChainSig) {
      lastChainSig = cSig;
      el.chain.innerHTML = renderChain(os, oc, s === os ? focus.reqs : new Set());
    }
    // The rounds.
    const wSig = `${s?.id}|${cur.t.toFixed(1)}|${fSig}|${el.falls.clientWidth}|${fixedEnd}`;
    if (wSig !== lastFallSig) {
      lastFallSig = wSig;
      el.falls.innerHTML = renderWaterfall(s, cur, focus, el.falls.clientWidth - 2, fixedEnd);
      el.readout.innerHTML = readout(s, cur);
    }
    const cap = caption || idleCaption();
    if (cap !== el.caption.innerHTML) {
      el.caption.innerHTML = cap;
      el.caption.title = el.caption.textContent ?? "";
    }
    dirty = false;
  }
  // The bucket redraws every frame: its flashes fade on the clock.
  bucket.draw(scene, mode.kind === "idle" && scene && scene.lanes.every((l) => l.done) ? { t: sceneEnd(scene) + 1e6, checks: cur.checks } : cur, focus, checkedPages(scene, cur, checks));
}

function idleCaption(): string {
  if (!client) return busy ? "" : openScene?.lanes[0]?.error ? "Not opened: change the settings and reopen." : "Open the bucket to begin.";
  if (!scene || scene.kind === "open") return "Pick a key and read it, or race the two ways of reading it. Hover anything: a node, a page or a request lights the others.";
  return "Done. Replay it slowed down, or step through it event by event.";
}

function trieHead(s: Scene | null, cur: Cursor): string {
  if (!s || s.kind === "open") return `<b>the path</b><span>from the state root down to the key</span>`;
  const l = s.lanes[0];
  const hashed = l?.result?.hashed ?? "";
  const what = s.what === "storage" ? `slot ${esc(s.slot)} of ${esc(short(s.key, 6))}` : s.what === "code" ? `code ${esc(short(s.key, 6))}` : esc(short(s.key, 8));
  // The flip is shown from when it happened.
  const tam = l?.tamper && cur.t >= l.tamper.t ? `<span class="pill bad">✗ tampered: byte ${l.tamper.byte.toLocaleString()} of ${esc(pageName({ table: l.tamper.table, kind: "data", index: l.tamper.page }))} (${l.tamper.trie === "account" ? "an account" : "a storage"} node at depth ${l.tamper.depth}) flipped before the client saw it</span>` : l?.tamper ? "" : l?.tamper === null && l.done ? `<span class="pill">tamper asked: no node in this read's responses to flip</span>` : "";
  const hs = l?.result?.hashed_slot;
  const paths = hashed ? ` · account path ${l?.result?.address ? "keccak(address)" : "(a hashed key, given)"} = <span class="mono">${esc(short(hashed, 5))}</span>${hs ? ` · slot path keccak(slot) = <span class="mono">${esc(short(hs, 5))}</span>` : ""}` : "";
  return `<b>${s.kind === "race" ? "race" : s.what}</b><span>${what}${paths}</span>${tam}`;
}

function readout(s: Scene | null, cur: Cursor): string {
  if (!s) return "";
  const stat = (l: Lane) => {
    const reqs = l.reqs.filter((r) => l.offset + r.end <= cur.t);
    const sent = l.reqs.filter((r) => l.offset + r.start <= cur.t).length + l.sent.filter((q) => l.offset + q.start <= cur.t).length;
    const rounds = new Set(l.reqs.filter((r) => l.offset + r.start <= cur.t).map((r) => r.round));
    for (const q of l.sent) if (l.offset + q.start <= cur.t) rounds.add(q.round);
    const bytes = reqs.reduce((n, r) => n + r.bytes, 0);
    const t = Math.min(Math.max(0, cur.t - l.offset), l.done ? l.ms : Infinity);
    return { rounds: rounds.size, reqs: sent, bytes, t };
  };
  if (s.kind === "race") {
    return `<div class="race">${s.lanes
      .map((l) => {
        const x = stat(l);
        return `<div class="lane"><span class="sw" style="background:${LANE[l.name]}"></span><div><div class="lbl">${l.name === "baseline" ? "by hash (baseline)" : "path-keyed"}</div><div class="big">${x.rounds}<small> ${x.rounds === 1 ? "round" : "rounds"}</small></div><div class="sm">${plural(x.reqs, "request")} · ${kb(x.bytes)} · ${ms(x.t)}</div></div></div>`;
      })
      .join("")}</div>`;
  }
  const l = s.lanes[0];
  if (!l) return "";
  const x = stat(l);
  return `<div class="nums"><div><div class="big">${x.rounds}</div><div class="lbl">${x.rounds === 1 ? "round" : "rounds"}</div></div><div><div class="big">${x.reqs}</div><div class="lbl">${x.reqs === 1 ? "request" : "requests"}</div></div><div><div class="big">${kb(x.bytes)}</div><div class="lbl">fetched</div></div><div><div class="big">${ms(x.t)}</div><div class="lbl">${s.kind === "open" ? "to prove the head" : "wall clock"}</div></div></div><div class="legend">${legend(s)}</div>`;
}

function legend(s: Scene): string {
  const rounds = [...new Set(s.lanes.flatMap((l) => l.reqs.map((r) => r.round)))].sort((a, b) => a - b);
  return rounds
    .slice(0, 6)
    .map((r) => `<span><i style="background:${roundColor(r)}"></i>round ${r}</span>`)
    .join("");
}

function status(msg: string, bad = false) {
  el.status.textContent = msg;
  el.status.title = msg;
  el.status.className = bad ? "t-bad" : "";
}

// --- inputs ----------------------------------------------------------------------------

interface Chip {
  label: string;
  kind: What;
  key: string;
  slot?: string;
}
const CHIPS: Chip[] = [
  { label: "an EOA", kind: "account", key: "0x00c290a6375b3c2a0a553ab65b82ad8847e3524d" },
  { label: "a contract", kind: "account", key: "0x20ea861b3acec90d3a15b4755d9a1cf1f161496e" },
  { label: "its slot 2", kind: "storage", key: "0x20ea861b3acec90d3a15b4755d9a1cf1f161496e", slot: "2" },
  { label: "its empty slot 1", kind: "storage", key: "0x20ea861b3acec90d3a15b4755d9a1cf1f161496e", slot: "1" },
  { label: "absent key", kind: "account", key: "0x1a7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" },
  { label: "vitalik.eth (outside the slice)", kind: "account", key: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045" },
];
let codeChip: Chip | null = null;

function setInputs(c: Chip) {
  el.kind.value = c.kind;
  syncKind();
  el.key.value = c.key;
  if (c.slot !== undefined) el.slot.value = c.slot;
}

function renderChips() {
  el.chips.innerHTML = "";
  for (const c of codeChip ? [...CHIPS, codeChip] : CHIPS) {
    const b = document.createElement("button");
    b.className = "chip";
    b.textContent = c.label;
    b.disabled = busy || !client;
    b.onclick = () => {
      setInputs(c);
      void read();
    };
    el.chips.appendChild(b);
  }
}

function updateCodeChip(s: Scene) {
  const r = s.lanes[0]?.result;
  if (s.kind === "read" && s.what === "account" && r?.status === "verified" && r.has_code && r.code_hash) {
    codeChip = { label: "its code", kind: "code", key: r.code_hash };
    renderChips();
  }
}

function syncKind() {
  el.slotWrap.hidden = el.kind.value !== "storage";
  el.key.placeholder = el.kind.value === "code" ? "code hash 0x…" : "address or hashed key 0x…";
}

el.kind.onchange = syncKind;
el.read.onclick = () => void read();
el.race.onclick = () => void race();
el.reopen.onclick = () => void open();
el.key.onkeydown = el.slot.onkeydown = (e) => {
  if (e.key === "Enter") void read();
};
for (const b of el.replay.querySelectorAll<HTMLButtonElement>("button[data-slow]")) b.onclick = () => replay(Number(b.dataset.slow));
el.stepPrev.onclick = () => stepBy(-1);
el.stepNext.onclick = () => stepBy(1);
window.addEventListener("keydown", (e: KeyboardEvent) => {
  if ((e.target as HTMLElement).tagName === "INPUT") return;
  if (e.key === "ArrowRight") stepBy(1);
  if (e.key === "ArrowLeft") stepBy(-1);
});
new ResizeObserver(() => {
  bucket.resize();
  dirtyAll();
}).observe(el.bucketWrap);
window.addEventListener("resize", dirtyAll);

// Expose the recorded scenes for the browser test (read only; nothing here
// drives the client).
(globalThis as unknown as { __viz: unknown }).__viz = {
  scene: () => scene,
  open: () => openScene,
  mode: () => mode.kind,
  busy: () => busy,
};

el.bucketNote.innerHTML = `<span><i style="background:${C.page0}"></i>page 0</span><span><i style="background:${C.model}"></i>model pages</span><span><i style="background:${C.heat}"></i>delivered earlier</span><span><i class="ring" style="border-color:${C.ok}"></i>holds a checked node</span><span><i class="ring" style="border-color:${C.bad}"></i>asked for, not delivered</span>`;

syncKind();
renderChips();
setBusy(false);
requestAnimationFrame(frame);
(async () => {
  try {
    wasm = await loadWasm();
    $<HTMLSpanElement>("version").textContent = `csl-eth-wasm ${wasm.version()}`;
    await open();
  } catch (e) {
    status(`could not load the wasm module: ${e instanceof Error ? e.message : e}`, true);
  }
})();
