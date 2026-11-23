#!/usr/bin/env python3
"""Cross-check analyze.py (pure Python, pre-registered) against scipy / scikit-learn.
usage: research/.venv/bin/python crosscheck.py <attempts.jsonl> [--class main] [--a1 A1]
Exit 1 if any discrepancy exceeds tolerance."""
import argparse, os, sys
import numpy as np
from scipy.stats import fisher_exact
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import LeaveOneGroupOut

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import analyze as A

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("jsonl"); ap.add_argument("--class", dest="cls", default="main")
    ap.add_argument("--a1", default="A1"); a = ap.parse_args()
    rows = A.load(a.jsonl, a.cls); eps = A.episodes(rows); bad = 0
    stats = {}
    for e in eps.values():
        if e["invalid"]: continue
        c, n = stats.get(e["arm"], (0, 0)); stats[e["arm"]] = (c + e["crashed"], n + 1)
    for x in ("A2", "A3", "A4"):
        if x in stats and a.a1 in stats:
            (c1, n1), (c2, n2) = stats[a.a1], stats[x]
            mine = A.fisher_greater(c1, n1, c2, n2)
            ref = fisher_exact([[c1, n1 - c1], [c2, n2 - c2]], alternative="greater")[1]
            ok = abs(mine - ref) < 1e-9; bad += not ok
            print("Fisher %s>%s  mine=%.6g scipy=%.6g %s" % (a.a1, x, mine, ref, "OK" if ok else "MISMATCH"))
    br = A.b_rows(rows, a.a1)
    if br and len(set(r["_y"] for r in br)) == 2:
        y = np.array([r["_y"] for r in br]); g = np.array([r["episode_id"] for r in br])
        for name, feats in (("H0", A.FEATS_H0), ("H1", A.FEATS_H1)):
            X = np.array([A.featurize(r, feats) for r in br], dtype=float)
            se = 0.0
            for tr, te in LeaveOneGroupOut().split(X, y, g):
                Xtr, Xte = X[tr].copy(), X[te].copy()
                mu = np.nanmean(Xtr, axis=0)
                for M in (Xtr, Xte):
                    idx = np.where(np.isnan(M)); M[idx] = np.take(mu, idx[1])
                if len(set(y[tr])) < 2:
                    p = np.full(len(te), y[tr].mean())
                else:
                    sc = StandardScaler().fit(Xtr)
                    # analyze.py uses sample sd (ddof=1); align
                    sc.scale_ = np.where(Xtr.std(axis=0, ddof=1) > 1e-12, Xtr.std(axis=0, ddof=1), 1.0)
                    m = LogisticRegression(C=1.0, max_iter=1000).fit(sc.transform(Xtr), y[tr])
                    p = m.predict_proba(sc.transform(Xte))[:, 1]
                se += ((p - y[te]) ** 2).sum()
            ref = se / len(y); mine, _ = A.loeo_brier(br, feats, lambda r: r["_y"])
            ok = abs(mine - ref) < 1e-3; bad += not ok
            print("Brier %s  mine=%.5f sklearn=%.5f %s" % (name, mine, ref, "OK" if ok else "MISMATCH"))
    print("CROSSCHECK", "PASS" if bad == 0 else "FAIL (%d)" % bad)
    sys.exit(1 if bad else 0)

if __name__ == "__main__":
    main()
