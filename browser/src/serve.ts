// The dev server: bundles `src/viz.ts` and the TypeScript light client's
// `light/light.ts` into `dist/` with Bun, then serves `index.html`,
// `light.html`, `dist/*` and the wasm-bindgen output
// in `pkg/*` (`.wasm` as `application/wasm`, so the module compiles while
// streaming). With `--site <dir>` it instead assembles a static site there
// (index.html, viz.html as a copy for old links, light.html and a redirect
// to it under its first name; dist/, pkg/) for hosting, and exits.
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
  // The light client's page states its verifier's length, counted here.
  const lines = readFileSync(join(ROOT, "light/verify.ts"), "utf8").trimEnd().split("\n").length;
  for (const [entry, define] of [
    ["src/viz.ts", {}],
    ["light/light.ts", { __VERIFY_LINES__: String(lines) }],
  ] as const) {
    const out = await Bun.build({
      entrypoints: [join(ROOT, entry)],
      outdir: join(ROOT, "dist"),
      target: "browser",
      format: "esm",
      sourcemap: "linked",
      define,
    });
    if (!out.success) {
      for (const l of out.logs) console.error(l);
      throw new Error(`bun build of ${entry} failed`);
    }
  }
}

const OLD_LIGHT = "mini.html";

function site(dir: string) {
  const out = resolve(ROOT, dir);
  rmSync(out, { recursive: true, force: true });
  mkdirSync(out, { recursive: true });
  cpSync(join(ROOT, "index.html"), join(out, "index.html"));
  cpSync(join(ROOT, "index.html"), join(out, "viz.html"));
  cpSync(join(ROOT, "light.html"), join(out, "light.html"));
  // The light client's page went by another name for a day; old links land on it.
  Bun.write(join(out, OLD_LIGHT), `<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0; url=light.html"><title>csl-eth</title><p><a href="light.html">The TypeScript light client is now at light.html.</a></p>\n`);
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
