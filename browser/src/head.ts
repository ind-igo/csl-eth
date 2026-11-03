// How the page and the visualizer word a verified head and the producer's
// unverified FCR note. One place, so both say the same thing.

import type { Fcr, Head } from "./protocol.ts";

export const ago = (secs: number) =>
  secs < 120 ? `${secs} s` : secs < 7200 ? `${Math.round(secs / 60)} min` : `${(secs / 3600).toFixed(1)} h`;

/// "attested by 509 of 512, not final, 5 min old" or "finalized, 17 min old".
export function tierLine(h: Head): string {
  return h.tier === "attested"
    ? `attested by ${h.participants} of 512, not final, ${ago(h.lag_secs)} old`
    : `finalized, ${ago(h.lag_secs)} old`;
}

/// The producer's FCR note as a sentence, or null when there is none (the
/// client keeps it only when it names the head it verified).
export function fcrLine(f: Fcr | null | undefined): string | null {
  if (!f) return null;
  return f.classification === "fcr_like"
    ? `fast-confirmed per ${f.source} after ${f.confirmed_after_secs} s (not verified by this client)`
    : `safe per ${f.source} (justified, not fast confirmation; not verified by this client)`;
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
