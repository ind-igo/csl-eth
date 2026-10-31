// `globalThis.cslFetch`: the synchronous byte source the wasm client calls
// (its `JsBucket`/`JsRun`). Runs only inside a Web Worker, where synchronous
// XMLHttpRequest is allowed and may set `responseType`.
//
// Contract: (url, offset, len) -> {status, body} or {status: 0, error}. It
// never throws; 404 and 416 are ordinary outcomes the Rust side interprets.
// All response validation (206 for a range, exact length) is the Rust
// side's: this only transports.

export type FetchResult = { status: number; body: Uint8Array } | { status: 0; error: string };
export type CslFetch = (url: string, offset: number | null, len: number | null) => FetchResult;

/// Per-request timeout. Sync XHR in a worker honours `timeout`.
const timeoutMs = 15_000;

export const cslFetch: CslFetch = (url, offset, len) => {
  try {
    const xhr = new XMLHttpRequest();
    xhr.open("GET", url, false);
    xhr.responseType = "arraybuffer";
    xhr.timeout = timeoutMs;
    if (offset !== null && len !== null) {
      if (len <= 0) return { status: 0, error: "zero-length range" };
      xhr.setRequestHeader("Range", `bytes=${offset}-${offset + len - 1}`);
    }
    xhr.send();
    if (xhr.status === 0) return { status: 0, error: "network error (status 0): CORS, offline, or timeout" };
    const body = xhr.response instanceof ArrayBuffer ? new Uint8Array(xhr.response) : new Uint8Array(0);
    return { status: xhr.status, body };
  } catch (e) {
    return { status: 0, error: e instanceof Error ? `${e.name}: ${e.message}` : String(e) };
  }
};

export function install() {
  (globalThis as unknown as { cslFetch: CslFetch }).cslFetch = cslFetch;
}
