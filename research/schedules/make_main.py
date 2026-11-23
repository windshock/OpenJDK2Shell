#!/usr/bin/env python3
"""Main schedule: 10 blocks x 4 arms, permuted per block (seed 20261123) — PREREG §3."""
import json, random
ARMS = {"A1": ("17.0.21", "", "malicious"), "A2": ("17.0.21.1", "", "malicious"),
        "A3": ("17.0.21", "-XX:-UseBASE64Intrinsics", "malicious"), "A4": ("17.0.21", "", "control")}
rng = random.Random(20261123); eps = []
for b in range(1, 11):
    order = list(ARMS); rng.shuffle(order)
    for arm in order:
        jdk, flags, inp = ARMS[arm]
        eps.append({"epid": "main-b%02d-%s" % (b, arm), "arm": arm, "jdk": jdk, "flags": flags,
                    "input": inp, "episode_class": "main", "K": 12, "block": b})
d = json.load(open("research/schedules/pilot2-2026-11-23.json"))["digests"]
json.dump({"run_id": "main-2026-11-23", "digests": d, "episodes": eps}, open("research/schedules/main-2026-11-23.json", "w"), indent=1)
print(" ".join(e["arm"] for e in eps))
