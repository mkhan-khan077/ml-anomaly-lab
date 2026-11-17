"""Isolation Forest anomaly detection on per-client, per-minute features from the lab's nginx log,
compared with fixed thresholds like the ones in api-abuse-detections.
Usage:
  python3 anomaly.py logs/synthetic.log logs/synthetic_labels.csv   # labeled evaluation
  python3 anomaly.py logs/access.log                                # real lab log: no labels, lists top anomalies
Baseline = the first BASELINE_HOURS hours of the log (assumed clean). The model is fit on the baseline only."""
import re, sys
from datetime import datetime
import pandas as pd
from sklearn.ensemble import IsolationForest

BASELINE_HOURS = 3
LINE = re.compile(r'^(?P<client>\S+) \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+)" (?P<status>\d{3}) (?P<bytes>\d+) tok=(?P<tok>\S+)$')
FEATURES = ["n_req", "n_paths", "n_small_login", "err_rate", "mean_bytes", "debug_hit", "tok_clients"]

def load(path):
    rows = []
    for raw in open(path):
        m = LINE.match(raw.strip())
        if m:
            d = m.groupdict(); d["ts"] = datetime.fromisoformat(d["ts"]); d["status"] = int(d["status"]); d["bytes"] = int(d["bytes"]); rows.append(d)
    return pd.DataFrame(rows).sort_values("ts").reset_index(drop=True)

def featurize(df):
    df["minute"] = df["ts"].dt.floor("min")
    df["small_login"] = (df["path"].str.contains("login")) & (df["bytes"] < 150)
    df["err"] = df["status"] >= 400
    df["debug"] = df["path"].str.contains("_debug")
    # distinct clients that used each token in the same hour (token reuse signal)
    df["hour"] = df["ts"].dt.floor("h")
    df["tok_clients"] = df.groupby(["tok", "hour"])["client"].transform("nunique")
    g = df.groupby(["client", "minute"])
    f = pd.DataFrame({
        "n_req": g.size(), "n_paths": g["path"].nunique(), "n_small_login": g["small_login"].sum(),
        "err_rate": g["err"].mean(), "mean_bytes": g["bytes"].mean(), "debug_hit": g["debug"].max().astype(int),
        "tok_clients": g["tok_clients"].max(),
    }).reset_index()
    return f

def rules(f):
    """Fixed thresholds, one-minute windows (the lab rules use 5 min / 1 hour sliding windows; this is a simplification)."""
    return ((f.n_paths >= 21) | (f.n_small_login >= 11) | (f.n_req >= 101) | (f.debug_hit == 1) | (f.tok_clients >= 3))

def main():
    log = sys.argv[1]; labels = sys.argv[2] if len(sys.argv) > 2 else None
    f = featurize(load(log))
    cut = f.minute.min() + pd.Timedelta(hours=BASELINE_HOURS)
    base, test = f[f.minute < cut], f[f.minute >= cut].copy()
    model = IsolationForest(n_estimators=300, contamination="auto", random_state=0).fit(base[FEATURES])
    test["score"] = -model.score_samples(test[FEATURES])           # higher = more anomalous
    # alert threshold: above the 99.5th percentile of baseline scores (about 1 in 200 normal windows)
    thr = pd.Series(-model.score_samples(base[FEATURES])).quantile(0.995)
    test["ml"] = test.score > thr
    # Second model: z-score against the baseline. For each feature, how many standard deviations above the baseline mean
    # (std floored at 0.5 so a constant feature cannot divide by zero); a window's score is its largest z.
    mu, sd = base[FEATURES].mean(), base[FEATURES].std().clip(lower=0.5)
    zb = ((base[FEATURES] - mu) / sd).max(axis=1)
    test["z"] = ((test[FEATURES] - mu) / sd).max(axis=1)
    test["zs"] = test.z > zb.quantile(0.995)
    test["rule"] = rules(test)
    print(f"baseline windows: {len(base)}  test windows: {len(test)}  ML threshold: {thr:.3f}")
    if not labels:
        print("\nTop 15 anomalous client-minutes (no labels for this log):")
        print(test.sort_values("score", ascending=False).head(15)[["client", "minute", "score"] + FEATURES].to_string(index=False))
        print("\nRule hits:", int(test.rule.sum()), " ML hits:", int(test.ml.sum()), " Both:", int((test.rule & test.ml).sum()))
        return
    lab = pd.read_csv(labels); lab["ts"] = pd.to_datetime(lab["ts"], format="ISO8601"); lab["minute"] = lab.ts.dt.floor("min")
    lab = lab.groupby(["client", "minute"])["label"].agg(lambda s: s.mode()[0]).reset_index()
    test = test.merge(lab, on=["client", "minute"], how="left"); test["attack"] = test.label.notna()
    print("\nPer-scenario detection (attack windows caught / total):")
    rows = []
    for name, grp in test[test.attack].groupby("label"):
        rows.append((name, len(grp), int(grp.rule.sum()), int(grp.ml.sum()), int(grp.zs.sum())))
    print(pd.DataFrame(rows, columns=["scenario", "windows", "rule_caught", "iforest_caught", "zscore_caught"]).to_string(index=False))
    norm = test[~test.attack]
    print(f"\nFalse positives on {len(norm)} normal windows: rule={int(norm.rule.sum())}  iforest={int(norm.ml.sum())}  zscore={int(norm.zs.sum())}")
    label_names = {"ml": "iforest", "zs": "zscore"}
    for name in ("rule", "ml", "zs"):
        tp = int((test[name] & test.attack).sum()); fp = int((test[name] & ~test.attack).sum()); fn = int((~test[name] & test.attack).sum())
        p = tp / (tp + fp) if tp + fp else 0; r = tp / (tp + fn) if tp + fn else 0
        print(f"{label_names.get(name, name):8s} precision={p:.2f} recall={r:.2f} (tp={tp} fp={fp} fn={fn})")

main()
