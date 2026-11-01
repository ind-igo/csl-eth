// One small palette for every view. Rounds take the first four slots of a
// categorical order validated for colour-vision deficiency on the dark
// surface (blue, magenta, violet, teal); rounds past the fourth (only the
// serial baseline gets there) share one slate and are told apart by their
// numbers, which every view prints. Status colours are reserved and always
// come with an icon and a word: green verified, amber insufficient, red
// tampered.

export const C = {
  bg: "#0d1016",
  panel: "#131821",
  panel2: "#171d28",
  line: "#252d3b",
  grid: "#1c2330",
  ink: "#e8ecf3",
  ink2: "#aab3c2",
  muted: "#737d8f",
  faint: "#4a5365",
  ok: "#4ade80",
  okDim: "#1f5b3a",
  warn: "#fbbf24",
  warnDim: "#5c4610",
  bad: "#f87171",
  badDim: "#5f2626",
  page0: "#d7dde8",
  model: "#7c8aa5",
  cell: "#1f2633",
  heat: "#35577f",
};

const ROUNDS = ["#3987e5", "#d55181", "#9085e9", "#1fa3b3"];
const LATER = "#8a94a8";

export const roundColor = (round: number) => ROUNDS[round - 1] ?? LATER;

/// Race lanes: the first two categorical slots.
export const LANE = { path: "#3987e5", baseline: "#d55181", open: "#9085e9" } as const;

export function rgba(hex: string, a: number): string {
  const n = parseInt(hex.slice(1), 16);
  return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${a})`;
}

export function mix(a: string, b: string, f: number): string {
  const x = parseInt(a.slice(1), 16);
  const y = parseInt(b.slice(1), 16);
  const ch = (s: number) => Math.round(((x >> s) & 255) * (1 - f) + ((y >> s) & 255) * f);
  return `#${((ch(16) << 16) | (ch(8) << 8) | ch(0)).toString(16).padStart(6, "0")}`;
}
