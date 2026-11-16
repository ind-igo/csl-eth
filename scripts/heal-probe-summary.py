#!/usr/bin/env python3
"""Reduce `csl-eth heal-probe` JSON lines to a summary (JSON on stdout).

    python3 scripts/heal-probe-summary.py heal-probe.jsonl [more.jsonl ...]
"""
import json
import sys
from collections import defaultdict


def family(client):
    c = (client or "").lower()
    for name in ("geth", "nethermind", "besu", "erigon", "reth", "ethereumjs", "nimbus"):
        if name in c:
            return name
    return c.split("/")[0] or "?"


def pct(xs, p):
    if not xs:
        return None
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(p / 100 * len(xs)))]


def stats(xs):
    return {"n": len(xs), "p50": pct(xs, 50), "p90": pct(xs, 90), "max": max(xs) if xs else None}


def main(paths):
    evs = []
    for p in paths:
        with open(p) as f:
            for line in f:
                line = line.strip()
                if line:
                    evs.append(json.loads(line))
    t0 = min(e["t"] for e in evs)
    t1 = max(e["t"] for e in evs)
    out = {"hours": round((t1 - t0) / 3600, 2)}

    dials = [e for e in evs if e["ev"] == "dials"]
    if dials:
        d = dials[-1]
        out["dials"] = {k: d[k] for k in ("dialed", "snap1", "no_snap1")}
        out["dials"]["errors_top"] = sorted(d["errors"].items(), key=lambda kv: -kv[1])[:6]

    ups = [e for e in evs if e["ev"] == "peer_up"]
    downs = [e for e in evs if e["ev"] == "peer_down"]
    by_fam = defaultdict(lambda: {"up": 0, "served_any": 0, "down_reasons": defaultdict(int)})
    for e in ups:
        by_fam[family(e["client"])]["up"] += 1
    for e in downs:
        f = by_fam[family(e["client"])]
        f["served_any"] += 1 if e["served"] > 0 else 0
        f["down_reasons"][e["reason"]] += 1

    reqs = [e for e in evs if e["ev"] == "req"]
    per = defaultdict(lambda: defaultdict(list))
    for e in reqs:
        f = family(e["client"])
        k = e["kind"]
        per[f][k + ":ok"].append(1 if e.get("matched", 0) > 0 else 0)
        if "error" in e:
            per[f][k + ":error"].append(1)
            continue
        if e.get("matched", 0) > 0:
            per[f][k + ":ms"].append(e["ms"])
            per[f][k + ":matched"].append(e["matched"])
            per[f][k + ":frac"].append(e["matched"] / e["asked"])
            per[f][k + ":bytes"].append(e["bytes"])
    peers = {}
    for f, v in by_fam.items():
        row = {"connected": v["up"], "disconnected_after_serving": v["served_any"], "down_reasons": dict(v["down_reasons"])}
        for kind in ("new", "old"):
            oks = per[f].get(kind + ":ok", [])
            if not oks:
                continue
            row[kind] = {
                "requests": len(oks),
                "served": round(sum(oks) / len(oks), 3),
                "errors": len(per[f].get(kind + ":error", [])),
                "ms": stats(per[f].get(kind + ":ms", [])),
                "nodes": stats(per[f].get(kind + ":matched", [])),
                "share_of_asked": stats([round(x, 3) for x in per[f].get(kind + ":frac", [])]),
                "kib": stats([round(b / 1024, 1) for b in per[f].get(kind + ":bytes", [])]),
            }
        peers[f] = row
    out["peers"] = peers

    ages = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    for e in evs:
        if e["ev"] == "age":
            a = ages[family(e["client"])][e["age"]]
            a[0] += 1
            a[1] += 1 if e["served"] else 0
    out["root_age_served"] = {
        f: {str(age): f"{s}/{n}" for age, (n, s) in sorted(v.items())} for f, v in ages.items()
    }

    cycles = [e for e in evs if e["ev"] == "cycle"]
    full = [e for e in cycles if e["count"]["complete"]]
    out["cycles"] = {"run": len(cycles), "complete": len(full)}
    if full:
        c = [e["count"] for e in full]
        blocks = [e["blocks"] for e in full]
        an = [x["account"]["nodes"] for x in c]
        sn = [x["storage"]["nodes"] for x in c]
        mib = [(x["account"]["bytes"] + x["storage"]["bytes"]) / 2**20 for x in c]
        per_block = [(a + s) / b for a, s, b in zip(an, sn, blocks) if b]
        out["cycles"].update({
            "blocks": stats(blocks),
            "account_nodes": stats(an),
            "storage_nodes": stats(sn),
            "new_mib": stats([round(m, 1) for m in mib]),
            "nodes_per_block": stats([round(x) for x in per_block]),
            "accounts_changed": stats([x["accounts_changed"] for x in c]),
            "accounts_created": stats([x["accounts_created"] for x in c]),
            "storage_tries_changed": stats([x["storage_tries_changed"] for x in c]),
            "secs": stats([round(e["secs"], 1) for e in full]),
            "lag_s": stats([round(e["lag_s"], 1) for e in full]),
            "requests": stats([x["requests"] for x in c]),
            "old_side_mib": stats([round(x["old_bytes"] / 2**20, 1) for x in c]),
            "levels": stats([x["levels"] for x in c]),
        })
        span_s = sum(b * 12 for b in blocks)
        nodes = sum(an) + sum(sn)
        out["rates"] = {
            "new_nodes_per_hour": round(nodes / span_s * 3600),
            "new_mib_per_hour": round(sum(mib) / span_s * 3600, 1),
            "new_nodes_per_sec": round(nodes / span_s, 1),
            "note": "summed over consecutive cycles; a node rewritten in two cycles counts twice",
        }
        top = defaultdict(int)
        for x in c:
            for owner, n in x["top_storage"]:
                top[owner] += n
        out["top_storage_owners"] = sorted(top.items(), key=lambda kv: -kv[1])[:8]
    incomplete = [e for e in cycles if not e["count"]["complete"]]
    if incomplete:
        out["incomplete"] = [
            {"to": e["to"], "unservable_new": e["count"]["unservable_new"], "unservable_old": e["count"]["unservable_old"], "secs": round(e["secs"])}
            for e in incomplete
        ][:20]
    notes = defaultdict(int)
    for e in evs:
        if e["ev"] == "note":
            notes[e["what"]] += 1
    out["notes"] = dict(notes)
    json.dump(out, sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main(sys.argv[1:])
