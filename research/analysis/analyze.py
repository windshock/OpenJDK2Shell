#!/usr/bin/env python3
"""Pre-registered analysis (research/PREREG-2026-11-23.md §5–6). Pure Python, no deps.

usage: analyze.py <attempts.jsonl> [--class main] [--out report.md]
"""
import json, math, sys, argparse, random
from collections import defaultdict

# ------------------------------------------------------------------ load
def load(path, ep_class):
    rows = [json.loads(l) for l in open(path) if l.strip()]
    return [r for r in rows if r.get("episode_class") == ep_class]

def episodes(rows):
    eps = defaultdict(list)
    for r in rows: eps[r["episode_id"]].append(r)
    out = {}
    for epid, rs in eps.items():
        att = [r for r in rs if r.get("attempt_id", 0) > 0]
        end = [r for r in rs if r.get("record") == "episode_end"]
        inv0 = [r for r in rs if r.get("attempt_id") == 0 and r.get("validity") == "INVALID"]
        arm = rs[0]["arm"]
        valid_trig = [r for r in att if r.get("validity") == "VALID"]
        crashed = any(r.get("process_crash") == 1 for r in att)
        corr = any(r.get("live_object_corruption") == "OBSERVED" for r in att)
        # episode INVALID: startup/fill failure, or no valid trigger at all
        invalid = bool(inv0) or not valid_trig
        out[epid] = dict(arm=arm, crashed=crashed, corruption=corr, invalid=invalid,
                         n_valid=len(valid_trig), exit=(end[0].get("exit_code") if end else None),
                         survived_with_corruption=(not crashed and corr))
    return out

# ------------------------------------------------------------------ Fisher exact (one-sided, a > b)
def _lc(n, k): return math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)
def fisher_greater(a_hit, a_n, b_hit, b_n):
    """P(X >= a_hit) for hypergeometric: rows=arm A/B, cols=crash/no."""
    K = a_hit + b_hit; N = a_n + b_n
    lo, hi = max(0, K - b_n), min(K, a_n)
    denom = _lc(N, K)
    return min(1.0, sum(math.exp(_lc(a_n, x) + _lc(b_n, K - x) - denom) for x in range(a_hit, hi + 1)))

def holm(ps):
    order = sorted(range(len(ps)), key=lambda i: ps[i])
    adj, prev = [0] * len(ps), 0
    for rank, i in enumerate(order):
        v = min(1.0, (len(ps) - rank) * ps[i]); prev = max(prev, v); adj[i] = prev
    return adj

# ------------------------------------------------------------------ logistic regression (L2, Newton)
def fit_logit(X, y, C=1.0, iters=50):
    d = len(X[0]); w = [0.0] * (d + 1); lam = 1.0 / C
    for _ in range(iters):
        g = [0.0] * (d + 1); Hm = [[0.0] * (d + 1) for _ in range(d + 1)]
        for xi, yi in zip(X, y):
            z = w[0] + sum(wj * xj for wj, xj in zip(w[1:], xi))
            p = 1 / (1 + math.exp(-max(-35, min(35, z))))
            xa = [1.0] + xi; s = p * (1 - p)
            for a in range(d + 1):
                g[a] += (p - yi) * xa[a]
                for b in range(d + 1): Hm[a][b] += s * xa[a] * xa[b]
        for a in range(1, d + 1): g[a] += lam * w[a]; Hm[a][a] += lam
        Hm[0][0] += 1e-6
        step = solve(Hm, g)
        w = [wi - si for wi, si in zip(w, step)]
        if max(abs(s) for s in step) < 1e-8: break
    return w

def solve(A, b):
    n = len(b); M = [row[:] + [b[i]] for i, row in enumerate(A)]
    for c in range(n):
        p = max(range(c, n), key=lambda r: abs(M[r][c])); M[c], M[p] = M[p], M[c]
        if abs(M[c][c]) < 1e-12: M[c][c] = 1e-12
        for r in range(n):
            if r != c:
                f = M[r][c] / M[c][c]
                for k in range(c, n + 1): M[r][k] -= f * M[c][k]
    return [M[i][n] / M[i][i] for i in range(n)]

def predict(w, x):
    z = w[0] + sum(a * b for a, b in zip(w[1:], x))
    return 1 / (1 + math.exp(-max(-35, min(35, z))))

FEATS_H1 = ["f_cycles_total", "f_secs_since_last_cycle_end", "f_humongous_alloc_gcs",
            "f_heap_occupancy_after_last_pause", "f_secs_since_drop", "f_cycle_rate_60s",
            "attempt_id", "shape_pad2"]
FEATS_H0 = ["f_heap_occupancy_after_last_pause"]

def featurize(r, names):
    v = []
    for n in names:
        if n == "shape_pad2": v.append(1.0 if r.get("shape") == "pad2" else 0.0)
        else:
            x = r.get(n); v.append(float(x) if x is not None else float("nan"))
    return v

def standardize(train, test):
    d = len(train[0]); mu, sd = [], []
    for j in range(d):
        col = [r[j] for r in train if not math.isnan(r[j])]
        m = sum(col) / len(col) if col else 0.0
        s = math.sqrt(sum((c - m) ** 2 for c in col) / max(1, len(col) - 1)) if len(col) > 1 else 1.0
        mu.append(m); sd.append(s if s > 1e-12 else 1.0)
    f = lambda rows: [[((r[j] if not math.isnan(r[j]) else mu[j]) - mu[j]) / sd[j] for j in range(d)] for r in rows]
    return f(train), f(test)

def loeo_brier(rows, names, label):
    eps = sorted(set(r["episode_id"] for r in rows)); se, n = 0.0, 0; preds = []
    for held in eps:
        tr = [r for r in rows if r["episode_id"] != held]; te = [r for r in rows if r["episode_id"] == held]
        ytr = [label(r) for r in tr]
        if len(set(ytr)) < 2:
            p0 = sum(ytr) / len(ytr); ps = [p0] * len(te)
        else:
            Xtr, Xte = standardize([featurize(r, names) for r in tr], [featurize(r, names) for r in te])
            w = fit_logit(Xtr, ytr); ps = [predict(w, x) for x in Xte]
        for r, p in zip(te, ps):
            y = label(r); se += (p - y) ** 2; n += 1; preds.append((p, y))
    return se / n if n else float("nan"), preds

def b_rows(rows, a1_arm):
    """A1 VALID attempts; label = crash before next trigger (incl. delayed crash attributed back)."""
    att = [r for r in rows if r["arm"] == a1_arm and r.get("attempt_id", 0) > 0]
    delayed = {(r["episode_id"], r.get("attributed_to_attempt")) for r in att
               if r.get("crash_phase") in ("pre-trigger", "during-rewarm") and r.get("attributed_to_attempt")}
    out = []
    for r in att:
        if r.get("validity") != "VALID": continue
        r = dict(r); r["_y"] = 1 if (r.get("process_crash") == 1 or (r["episode_id"], r["attempt_id"]) in delayed) else 0
        out.append(r)
    return out

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("jsonl"); ap.add_argument("--class", dest="cls", default="main")
    ap.add_argument("--a1", default="A1"); ap.add_argument("--out")
    a = ap.parse_args()
    rows = load(a.jsonl, a.cls); eps = episodes(rows)
    L = []; P = lambda *s: L.append(" ".join(str(x) for x in s))
    P("# 분석 결과 (사전등록 §5–6)\n"); P("입력:", a.jsonl, "· episode_class =", a.cls, "· 행", len(rows), "\n")
    P("## 실험 A — episode 단위\n"); P("| arm | episode(유효) | INVALID | 크래시 | 크래시율 | 헤더 손상 OBSERVED | 생존+손상 |"); P("|---|---|---|---|---|---|---|")
    by = defaultdict(list)
    for e in eps.values(): by[e["arm"]].append(e)
    stats = {}
    for arm in sorted(by):
        v = [e for e in by[arm] if not e["invalid"]]; inv = len(by[arm]) - len(v)
        c = sum(e["crashed"] for e in v); co = sum(e["corruption"] for e in v); sc = sum(e["survived_with_corruption"] for e in v)
        stats[arm] = (c, len(v))
        P("| %s | %d | %d | %d | %.2f | %d | %d |" % (arm, len(v), inv, c, c / len(v) if v else float("nan"), co, sc))
    P("")
    comps = [x for x in ("A2", "A3", "A4") if x in stats and a.a1 in stats]
    if comps:
        raw = [fisher_greater(stats[a.a1][0], stats[a.a1][1], stats[x][0], stats[x][1]) for x in comps]
        adj = holm(raw)
        P("| 비교 | Fisher 단측 p | Holm 보정 p |"); P("|---|---|---|")
        for x, p, q in zip(comps, raw, adj): P("| %s > %s | %.4g | %.4g |" % (a.a1, x, p, q))
        a1r = stats[a.a1][0] / max(1, stats[a.a1][1])
        others_low = all(stats[x][0] / max(1, stats[x][1]) <= 0.10 for x in comps)
        sig = all(q < 0.05 for q in adj) and len(comps) == 3
        a4ns = "A4" in comps and adj[comps.index("A4")] >= 0.05
        verdict = "causal supported" if (sig and others_low) else ("not supported" if a4ns and stats[a.a1][0] > 0 and stats["A4"][0] > 0 else "inconclusive")
        if stats[a.a1][0] == 0: verdict = "HOLD (A1 크래시 0 — 계획 §8)"
        P("\n**판정 (사전등록 §5): %s** (A1 크래시율 %.2f)\n" % (verdict, a1r))
    P("## 실험 B — attempt 단위 예측 (A1 VALID attempt)\n")
    br = b_rows(rows, a.a1); pos = sum(r["_y"] for r in br)
    P("attempt %d, 양성(크래시) %d, episode %d\n" % (len(br), pos, len(set(r["episode_id"] for r in br))))
    if br:
        b0, _ = loeo_brier(br, FEATS_H0, lambda r: r["_y"]); b1, _ = loeo_brier(br, FEATS_H1, lambda r: r["_y"])
        base = pos / len(br); bconst = sum((base - r["_y"]) ** 2 for r in br) / len(br)
        P("| 모델 | Brier (LOEO) |"); P("|---|---|")
        P("| 상수(양성 비율, 참고) | %.4f |" % bconst); P("| H0 점유율 단일 | %.4f |" % b0); P("| H1 GC 상태 전체 | %.4f |" % b1)
        if pos < 8: vb = "INCONCLUSIVE (양성 %d < 8)" % pos
        elif b0 - b1 >= 0.05: vb = "H1 채택 근거 (개선 %.4f ≥ 0.05)" % (b0 - b1)
        else: vb = "H1 개선 없음 (개선 %.4f < 0.05) → H0/H2 검토" % (b0 - b1)
        P("\n**판정 (사전등록 §6): %s**\n" % vb)
        # exploratory
        ex = [r for r in br if r.get("live_object_corruption") in ("OBSERVED", "NOT_OBSERVED")]
        if ex:
            lab = lambda r: 1 if r["live_object_corruption"] == "OBSERVED" else 0
            e0, _ = loeo_brier(ex, FEATS_H0, lab); e1, _ = loeo_brier(ex, FEATS_H1, lab)
            P("탐색적 (라벨 = 헤더 손상 OBSERVED; UNKNOWN 제외 %d/%d): H0 %.4f / H1 %.4f, 양성 %d\n"
              % (len(br) - len(ex), len(br), e0, e1, sum(lab(r) for r in ex)))
    txt = "\n".join(L); print(txt)
    if a.out: open(a.out, "w").write(txt + "\n")

if __name__ == "__main__":
    main()
