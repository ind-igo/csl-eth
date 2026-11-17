// mini.html's script: the form, the tamper toggle, and the result.
import { run, type Outcome } from "./driver.ts";
import { hex, Session, tamperSpot, unhex, type Want } from "./verify.ts";

declare const __VERIFY_LINES__: number;
const SOURCE = "https://github.com/ind-igo/csl-eth/blob/main/browser/mini/verify.ts";

// From the bucket, the state under `full/` beside this page; anywhere else, the demo bucket.
const BASE =
  location.hostname === "storage.googleapis.com"
    ? new URL("full", location.href).href.replace(/\/+$/, "")
    : "https://storage.googleapis.com/csl-eth-demo/full";

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const form = $<HTMLFormElement>("form");
const [address, slot, code, tamper, button] = [$<HTMLInputElement>("address"), $<HTMLInputElement>("slot"), $<HTMLInputElement>("code"), $<HTMLInputElement>("tamper"), $<HTMLButtonElement>("read")];
const status = $("status");

const lines = $("lines");
lines.innerHTML = `The whole verifier is <a href="${SOURCE}">${__VERIFY_LINES__} lines</a> of TypeScript.`;

const EXAMPLES: [string, string, string?, boolean?][] = [
  ["vitalik.eth", "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"],
  ["absent account", "0x5a17e00000000000000000000000000000c0ffee"],
  ["USDT slot 1", "0xdAC17F958D2ee523a2206206994597C13D831ec7", "1"],
  ["WETH slot 0", "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "0"],
  ["The DAO slot 0", "0xBB9bc244D798123fDe783fCc1C72d3Bb8C189413", "0"],
  ["CryptoPunks slot 0", "0xb47e3cd837dDF8e4c57F05d70Ab865de6e193BBB", "0"],
  ["WETH code", "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "", true],
];
for (const [label, a, s, c] of EXAMPLES) {
  const b = document.createElement("button");
  b.type = "button";
  b.className = "chip";
  b.textContent = label;
  b.onclick = () => {
    [address.value, slot.value, code.checked] = [a, s ?? "", !!c];
    form.requestSubmit();
  };
  $("examples").append(b);
}

/** The tamper demo: invert one byte of the account trie's root node in the newest run's page, before the verifier sees it. */
const ROOT_KEY = new Uint8Array(32);
function flipRoot(w: Want, body: Uint8Array): string | null {
  const r = w.run;
  if (!r || r.table !== 0 || r.index !== r.of - 1 || w.off === undefined) return null;
  const at = tamperSpot(body, ROOT_KEY, w.off / 4096 === r.pages);
  if (at === null) return null;
  const before = body[at]!;
  body[at] = before ^ 0xff;
  const x = (n: number) => "0x" + n.toString(16).padStart(2, "0");
  return `Tampered: byte ${(w.off + at).toLocaleString()} of ${w.path} flipped (${x(before)} → ${x(body[at]!)}) before the verifier saw it. That page holds the account trie's root node in the newest layer.`;
}

// What earlier reads checked: index pages, the account trie's top levels, the committees.
const session = new Session();

const esc = (s: string) => s.replace(/[&<>"]/g, (c) => `&#${c.charCodeAt(0)};`);
const short = (b: Uint8Array) => hex(b);
function eth(wei: bigint): string {
  const s = wei.toString().padStart(19, "0");
  const [i, f] = [s.slice(0, -18), s.slice(-18).replace(/0+$/, "")];
  return `${BigInt(i).toLocaleString("en-US")}${f ? "." + f : ""} ETH`;
}
const kb = (n: number) => (n >= 1 << 20 ? `${(n / (1 << 20)).toFixed(1)} MB` : `${Math.round(n / 1024)} KB`);

function show(o: Outcome, what: { slot?: bigint; code: boolean }, reused: number) {
  const a = o.answer;
  status.className = a ? "ok" : "bad";
  status.textContent = a ? "Verified" : `Refused: ${o.refused}`;
  $("tampered").hidden = !o.tampered;
  $("tampered").textContent = o.tampered ?? "";
  $("stats").hidden = false;
  $("s-block").textContent = a ? a.head.block.toLocaleString("en-US") : "–";
  $("s-rounds").textContent = String(o.stats.rounds);
  $("s-requests").textContent = String(o.stats.requests);
  $("s-bytes").textContent = kb(o.stats.bytes);
  $("s-ms").textContent = `${(o.stats.ms / 1000).toFixed(1)} s`;

  const rows: [string, string][] = [];
  if (a?.account) {
    const acc = a.account;
    rows.push(["balance", esc(eth(acc.balance))], ["nonce", acc.nonce.toString()], ["storage root", short(acc.storageRoot)], ["code hash", short(acc.codeHash)]);
  } else if (a) rows.push(["account", `absent <span class="note">(${esc(a.absent ?? "")})</span>`]);
  if (a && what.slot !== undefined) {
    const s = a.storage!;
    rows.push([`slot ${what.slot}`, s.absent ? `0 <span class="note">(absent: ${esc(s.absent)})</span>` : "0x" + s.value.toString(16).padStart(64, "0")]);
  }
  if (a?.code) rows.push(["code", a.code.length ? `${a.code.length.toLocaleString()} bytes, ${short(a.code.slice(0, 12))}…` : "none"]);
  $("answer").innerHTML = rows.length ? rows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("") : `<dd class="empty">Nothing: the read was refused.</dd>`;

  const chain = $("chain");
  if (!a) {
    chain.innerHTML = `<li class="empty">Nothing is shown when a check fails.</li>`;
    return;
  }
  const h = a.head;
  const steps = [
    `Started from the checkpoint at slot ${h.checkpointSlot.toLocaleString("en-US")}, built into the page.`,
    `Followed ${h.updates} sync committee ${h.updates === 1 ? "handover" : "handovers"}, each signed by two thirds of the outgoing committee.`,
    `Slot ${h.slot.toLocaleString("en-US")} was signed by ${h.participants} of 512 committee members (two thirds needed), BLS aggregate verified.`,
    `Its execution header is in the signed block by a Merkle branch: block ${h.block.toLocaleString("en-US")}, state root <span class="mono">${short(h.stateRoot)}</span>.`,
    a.account || a.absent ? `Walked the account trie from that root, every node keccak-checked${a.account ? "" : "; the trie's shape proves the account absent"}.` : "",
    what.slot !== undefined && a.account ? `Walked the account's storage trie from its storage root${a.storage?.absent ? "; its shape proves the slot empty" : ""}.` : "",
    a.code?.length ? `The code's keccak equals the account's code hash.` : "",
    reused ? `Reused ${reused.toLocaleString("en-US")} index pages and trie nodes that earlier reads on this page checked.` : "",
  ].filter(Boolean);
  chain.innerHTML = steps.map((s) => `<li>${s}</li>`).join("");
}

form.onsubmit = async (ev) => {
  ev.preventDefault();
  let q: { address: Uint8Array; slot?: bigint; code: boolean; now: number };
  try {
    const s = slot.value.trim();
    const v = s === "" ? undefined : BigInt(s);
    if (v !== undefined && (v < 0n || v >= 2n ** 256n)) throw new Error("slot out of range");
    q = { address: unhex(address.value.trim(), 20), slot: v, code: code.checked, now: Date.now() };
  } catch {
    status.className = "bad";
    status.textContent = "Enter a 20-byte hex address and, optionally, a slot number (decimal or 0x hex).";
    return;
  }
  const tamp = tamper.checked;
  button.disabled = true;
  status.className = "";
  status.textContent = tamp ? "Reading; one byte of one fetched page will be flipped…" : "Reading…";
  try {
    // A tampered read starts from nothing, so the targeted page is fetched rather than answered from what earlier reads kept.
    const s = tamp ? new Session() : session;
    const reused = s.keep.size + s.nodes.size;
    const o = await run(BASE, q, tamp ? flipRoot : undefined, s);
    if (tamp && !o.tampered) o.tampered = "Tamper: no fetched page held the targeted node, so nothing was changed.";
    show(o, q, reused);
  } finally {
    button.disabled = false;
    tamper.checked = false;
  }
};
// For the browser tests.
(globalThis as unknown as { __mini: unknown }).__mini = { busy: () => button.disabled };
