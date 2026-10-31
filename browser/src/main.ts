// The page: drives the wasm client's rounds and renders what it answers.
// Nothing here verifies anything; the client (wasm, in this tab) does, and
// the page shows the head it proved, each answer's status, and what every
// read cost in rounds, requests, bytes, and milliseconds.

import { drive, loadWasm, type ClientLike, type WasmModule } from "./client.ts";
import type { Head, ReadResult, RequestLog, Trip } from "./protocol.ts";

const DEFAULT_BASE = "https://pub-a977a488180546bfb335de69b6f2e207.r2.dev";
const DEFAULT_CHECKPOINT = "0xe59d78041964322427cc209a44edcad243487378b78895a6cc0bfa7a7577cf0b";

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const base = $<HTMLInputElement>("base");
const checkpoint = $<HTMLInputElement>("checkpoint");
const prefetch = $<HTMLInputElement>("prefetch");
const toplevels = $<HTMLInputElement>("toplevels");
const openBtn = $<HTMLButtonElement>("open");
const openStatus = $<HTMLParagraphElement>("openstatus");
const headEl = $<HTMLDivElement>("head");
const kind = $<HTMLSelectElement>("kind");
const keyLabel = $<HTMLLabelElement>("keylabel");
const key = $<HTMLInputElement>("key");
const slotLabel = $<HTMLLabelElement>("slotlabel");
const slot = $<HTMLInputElement>("slot");
const readBtn = $<HTMLButtonElement>("read");
const chips = $<HTMLDivElement>("chips");
const resultEl = $<HTMLDivElement>("result");
const versionEl = $<HTMLSpanElement>("version");

const params = new URLSearchParams(location.search);
base.value = params.get("bucket") ?? DEFAULT_BASE;
checkpoint.value = params.get("checkpoint") ?? DEFAULT_CHECKPOINT;

let wasm: WasmModule | null = null;
let client: ClientLike | null = null;
let bucket = "";

// --- rendering --------------------------------------------------------------

const esc = (s: unknown) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c] ?? c);
const kb = (b: number) => (b < 1024 ? `${b} B` : `${(b / 1024).toFixed(1)} KB`);
const ago = (secs: number) => (secs < 120 ? `${secs} s` : secs < 7200 ? `${Math.round(secs / 60)} min` : `${(secs / 3600).toFixed(1)} h`);
const utc = (ts: number) => new Date(ts * 1000).toISOString().replace("T", " ").slice(0, 19) + " UTC";
const plural = (n: number, w: string) => `${n} ${w}${n === 1 ? "" : "s"}`;

function logTable(log: RequestLog[]): string {
  if (!log.length) return "";
  const rows = log
    .map(
      (r) =>
        `<tr><td class="num">${r.round}</td><td>${esc(r.file)}</td><td class="num">${r.offset === null ? "whole" : `${r.offset}+${r.length}`}</td><td class="num">${r.status}</td><td class="num">${kb(r.bytes)}</td><td class="num">${r.ms.toFixed(0)}</td></tr>`,
    )
    .join("");
  const rounds = log.reduce((m, r) => Math.max(m, r.round), 0);
  return `<details><summary>${plural(log.length, "request")} in ${plural(rounds, "round")}</summary><table><tr><th class="num">round</th><th>file</th><th class="num">range</th><th class="num">status</th><th class="num">bytes</th><th class="num">ms</th></tr>${rows}</table></details>`;
}

function renderHead(h: Head, trip: Trip) {
  const stale = h.finality_lag_secs > 3600;
  headEl.innerHTML = `
    <span class="badge ${stale ? "warn" : "ok"}">${stale ? "verified, but stale" : "verified"}</span>
    <span class="status"> finalized block <b>${h.block_number.toLocaleString()}</b>, finalized ${ago(h.finality_lag_secs)} ago (${utc(h.timestamp)})</span>
    <dl>
      <dt>block hash</dt><dd>${esc(h.block_hash)}</dd>
      <dt>state root</dt><dd>${esc(h.state_root)}</dd>
      <dt>beacon root</dt><dd>${esc(h.beacon_root)} <span class="status">slot ${h.slot}, period ${h.period}</span></dd>
      <dt>signed by</dt><dd class="plain">${h.participants} of 512 sync-committee members; ${plural(h.updates_applied, "period update")} applied from the checkpoint</dd>
      <dt>snapshot</dt><dd class="plain">block ${h.snapshot.block_number.toLocaleString()}, keys under prefix <code>${esc(h.snapshot.prefix)}</code> (${(100 / 16 ** h.snapshot.prefix.length).toFixed(3)}% of the state)</dd>
    </dl>
    <p class="cost">opening cost <b>${plural(h.open.requests, "request")}</b> in <b>${plural(trip.rounds, "round")}</b>, <b>${kb(h.open.bytes)}</b>, <b>${trip.ms.toFixed(0)} ms</b>: the head proof file by file (each depends on the last), then the manifest, then every table's model at once.</p>
    ${logTable(trip.log)}`;
}

function renderResult(r: ReadResult, what: string, trip: Trip) {
  const badge =
    r.status === "verified"
      ? `<span class="badge ok">verified</span>`
      : r.status === "absent"
        ? `<span class="badge ok">verified absent</span> <span class="status">${esc(r.why)}: the trie proves there is nothing here</span>`
        : `<span class="badge warn">insufficient</span> <span class="status">${esc(r.why)}</span>`;
  const rows: [string, string, boolean?][] = [];
  if (r.address) rows.push(["address", r.address]);
  if (r.hashed) rows.push(["hashed key", r.hashed]);
  if (r.hashed_slot) rows.push(["hashed slot", r.hashed_slot]);
  if (r.status === "verified") {
    if (what === "account") {
      rows.push(["nonce", String(r.nonce), true]);
      rows.push(["balance", `${r.balance} wei (${(Number(r.balance) / 1e18).toFixed(6)} ETH)`, true]);
      rows.push(["code hash", `${r.code_hash}${r.has_code ? "" : " (no code)"}`]);
      rows.push(["storage root", `${r.storage_root}${r.has_storage ? "" : " (empty)"}`]);
    } else if (what === "storage") {
      rows.push(["value", `${r.value}`]);
      rows.push(["decimal", `${r.value_dec}`, true]);
    } else {
      rows.push(["size", `${r.size} bytes`, true]);
      rows.push(["starts with", `${r.prefix}…`]);
    }
  }
  const dl = rows.map(([k, v, plain]) => `<dt>${esc(k)}</dt><dd${plain ? ' class="plain"' : ""}>${esc(v)}</dd>`).join("");
  const c = r.cost;
  const cost = `<p class="cost"><b>${plural(c.requests, "request")}</b> in <b>${plural(c.rounds, "round")}</b>, <b>${kb(c.bytes)}</b>, <b>${trip.ms.toFixed(0)} ms</b> · ${plural(c.repairs, "repair")}, ${c.nodes} trie nodes checked${c.model_pages ? `, ${plural(c.model_pages, "model page")} fetched` : ""}</p>`;
  const more = what === "account" && r.status === "verified" && r.has_code ? `<div class="chips"><button class="ghost" id="readcode">read its code</button></div>` : "";
  resultEl.innerHTML = `${badge}<dl>${dl}</dl>${cost}${more}${logTable(trip.log)}`;
  const rc = document.getElementById("readcode");
  if (rc && r.code_hash) {
    const hash = r.code_hash;
    rc.onclick = () => {
      kind.value = "code";
      kind.dispatchEvent(new Event("change"));
      key.value = hash;
      void read();
    };
  }
}

function setChips(items: { label: string; kind: string; key: string; slot?: string }[]) {
  chips.innerHTML = "";
  for (const it of items) {
    const b = document.createElement("button");
    b.className = "ghost";
    b.textContent = it.label;
    b.onclick = () => {
      kind.value = it.kind;
      kind.dispatchEvent(new Event("change"));
      key.value = it.key;
      if (it.slot !== undefined) slot.value = it.slot;
      void read();
    };
    chips.appendChild(b);
  }
}

// --- actions ----------------------------------------------------------------

let busy = false;
let opened = false;
function setBusy(b: boolean) {
  busy = b;
  openBtn.disabled = b;
  readBtn.disabled = b || !opened;
}

async function open() {
  if (busy || !wasm) return;
  setBusy(true);
  opened = false;
  headEl.innerHTML = `<span class="badge idle">verifying…</span> <span class="status">reading head/bootstrap, head/updates, head/finality and checking sync-committee signatures</span>`;
  openStatus.textContent = "";
  try {
    client?.free();
    client = null;
    bucket = base.value.trim().replace(/\/+$/, "");
    const c = new wasm.Client(checkpoint.value.trim(), Date.now(), Number(prefetch.value), Number(toplevels.value));
    client = c;
    const { result, trip } = await drive<Head>(c, bucket, () => c.open());
    renderHead(result, trip);
    opened = true;
  } catch (e) {
    headEl.innerHTML = `<span class="badge bad">not verified</span> <span class="err">${esc(e instanceof Error ? e.message : e)}</span>`;
  } finally {
    setBusy(false);
  }
}

async function read() {
  if (busy || !opened || !client) return;
  setBusy(true);
  const c = client;
  const what = kind.value;
  resultEl.innerHTML = `<span class="badge idle">reading…</span>`;
  try {
    const start =
      what === "account"
        ? () => c.account(key.value)
        : what === "storage"
          ? () => c.storage(key.value, slot.value || "0")
          : () => c.code(key.value);
    const { result, trip } = await drive<ReadResult>(c, bucket, start);
    renderResult(result, what, trip);
  } catch (e) {
    resultEl.innerHTML = `<span class="badge bad">error</span> <span class="err">${esc(e instanceof Error ? e.message : e)}</span>`;
  } finally {
    setBusy(false);
  }
}

kind.onchange = () => {
  slotLabel.hidden = kind.value !== "storage";
  keyLabel.firstChild!.textContent = kind.value === "code" ? "code hash" : "address or hashed key";
};
openBtn.onclick = () => void open();
readBtn.onclick = () => void read();
key.onkeydown = slot.onkeydown = (e) => {
  if (e.key === "Enter") void read();
};

// Example keys: mainnet addresses whose hashed key falls inside the demo
// slice (found by hashing recent blocks' senders and log emitters), one
// outside it (the honest answer there is "insufficient", not "absent"), and
// a hashed key that can only be absent.
setChips([
  { label: "an EOA in the slice", kind: "account", key: "0x00c290a6375b3c2a0a553ab65b82ad8847e3524d" },
  { label: "a contract in the slice", kind: "account", key: "0x20ea861b3acec90d3a15b4755d9a1cf1f161496e" },
  { label: "an account created after the snapshot", kind: "account", key: "0xa0ec455414c8ef8750e3efe831fbc98dfddd1123" },
  { label: "its storage slot 2", kind: "storage", key: "0x20ea861b3acec90d3a15b4755d9a1cf1f161496e", slot: "2" },
  { label: "its empty slot 1", kind: "storage", key: "0x20ea861b3acec90d3a15b4755d9a1cf1f161496e", slot: "1" },
  { label: "vitalik.eth (outside the slice)", kind: "account", key: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045" },
  { label: "absent key in the slice", kind: "account", key: "0x1a7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" },
]);

(async () => {
  try {
    const t0 = performance.now();
    wasm = await loadWasm();
    versionEl.textContent = `csl-eth-wasm ${wasm.version()} (module loaded in ${(performance.now() - t0).toFixed(0)} ms)`;
    openStatus.textContent = "module loaded; Open verifies the head and opens the snapshot it names.";
    if (params.has("open")) void open();
  } catch (e) {
    openStatus.innerHTML = `<span class="err">could not load the wasm module: ${esc(e instanceof Error ? e.message : e)}</span>`;
  }
})();
