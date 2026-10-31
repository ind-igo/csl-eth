// Build settings `cf` keeps for a static-assets project (generated shape
// from `cf init`; the file may change during the cf beta).
import { defineWranglerConfig } from "wrangler/experimental-config";

export default defineWranglerConfig({
  assetsDirectory: "../site",
});
