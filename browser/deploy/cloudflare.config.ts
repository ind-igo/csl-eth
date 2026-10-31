// Hosting for the browser client: a static-assets Worker (Pages on Workers)
// named `csl-eth`, serving `../site` as assembled by `bun run site`. Deploy
// from this directory with `cf deploy` (the `cf` CLI; see ../README.md).
import { defineConfig } from "cf/config";

export default defineConfig({
  worker: {
    name: "csl-eth",
    compatibilityDate: "2026-10-23",
    observability: { enabled: true },
    assets: { htmlHandling: "auto-trailing-slash", notFoundHandling: "404-page" },
  },
});
