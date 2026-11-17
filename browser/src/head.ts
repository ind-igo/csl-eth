// How the page and the visualizer word a verified head. One place, so both
// say the same thing.

import type { Head } from "./protocol.ts";

export const ago = (secs: number) =>
  secs < 120 ? `${secs} s` : secs < 7200 ? `${Math.round(secs / 60)} min` : `${(secs / 3600).toFixed(1)} h`;

/// "attested by 509 of 512, not final, 5 min old" or "finalized, 17 min old".
export function tierLine(h: Head): string {
  return h.tier === "attested"
    ? `attested by ${h.participants} of 512, not final, ${ago(h.lag_secs)} old`
    : `finalized, ${ago(h.lag_secs)} old`;
}

export type TierChoice = "best" | "finalized" | "attested";

/// `?tier=finalized` or `?tier=attested` forces that head (the open is
/// refused when it cannot be opened); anything else is the default.
export function tierParam(params: URLSearchParams): TierChoice {
  return tierChoice(params.get("tier"));
}

/// A select's or a query's value as a tier choice, "best" when it is neither forced tier.
export function tierChoice(v: string | null): TierChoice {
  return v === "finalized" || v === "attested" ? v : "best";
}
