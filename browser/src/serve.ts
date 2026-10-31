// The dev server: bundles `src/main.ts` into `dist/` with Bun, then serves `index.html`, `dist/*` and the wasm-bindgen output
// in `pkg/*` (`.wasm` as `application/wasm`, so the module compiles while
// streaming). With `--site <dir>` it instead assembles a static site there
// (index.html, dist/, pkg/) for hosting, and exits.
//
//   bun src/serve.ts [--port 8791]
//   bun src/serve.ts --site site

import { cpSync, existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { join, normalize, resolve } from "node:path";

const ROOT = resolve(import.meta.dir, "..");

const TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".map": "application/json",
  ".wasm": "application/wasm",
  ".json": "application/json",
  ".txt": "text/plain; charset=utf-8",
};

export async function build(): Promise<void> {
  const out = await Bun.build({
    entrypoints: [join(ROOT, "src/main.ts")],
    outdir: join(ROOT, "dist"),
    target: "browser",
    format: "esm",
    sourcemap: "linked",
  });
  if (!out.success) {
    for (const l of out.logs) console.error(l);
    throw new Error("bun build failed");
  }
}

function site(dir: string) {
  const out = resolve(ROOT, dir);
  rmSync(out, { recursive: true, force: true });
  mkdirSync(out, { recursive: true });
  cpSync(join(ROOT, "index.html"), join(out, "index.html"));
  cpSync(join(ROOT, "dist"), join(out, "dist"), { recursive: true });
  cpSync(join(ROOT, "pkg"), join(out, "pkg"), { recursive: true });
  // Static-assets Worker: cache the hashed-by-nothing assets for a short while.
  Bun.write(join(out, "_headers"), "/pkg/*\n  Cache-Control: public, max-age=300\n/dist/*\n  Cache-Control: public, max-age=300\n");
  console.log(`site assembled in ${out}`);
}

function serve(port: number) {
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port,
    fetch(req) {
      const url = new URL(req.url);
      let path = decodeURIComponent(url.pathname);
      if (path === "/") path = "/index.html";
      const file = normalize(join(ROOT, path));
      if (!file.startsWith(ROOT) || !existsSync(file)) return new Response("not found", { status: 404 });
      const ext = file.slice(file.lastIndexOf("."));
      const headers: Record<string, string> = { "Content-Type": TYPES[ext] ?? "application/octet-stream", "Cache-Control": "no-store" };
      return new Response(readFileSync(file), { headers });
    },
  });
  console.log(`csl-eth browser client at http://127.0.0.1:${server.port}/`);
}

const args = process.argv.slice(2);
const flag = (name: string) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};

await build();
const siteDir = flag("--site");
if (siteDir !== undefined) site(siteDir ?? "site");
else serve(Number(flag("--port") ?? 8791));
