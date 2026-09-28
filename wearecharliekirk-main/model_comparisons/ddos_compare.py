"""
Fair DDoS model comparison on CIC-DDoS2019 — the same 431,371-row dataset the
shipped NetSentinel DDoS model was trained on (dhoogla cleaned parquet release).

Binary task: attack vs benign, using the shipped model's 59 features.
Two protocols, every model on identical rows:
  A. random stratified 80/20 split  (the protocol behind the shipped 99.97% F1)
  B. train on the CIC "training day" files, test on the "testing day" files
     (a different day with a different attack mix — harder, closer to real use)
"""
import json, time, glob
import numpy as np, pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
from sklearn.metrics import f1_score, accuracy_score, precision_score, recall_score
import xgboost as xgb, lightgbm as lgb

SEED = 42
FEATS = json.load(open("ddos_feature_names.json"))
fs = sorted(glob.glob("/mnt/user-data/uploads/1_sih26/dataset/ddos/archive/*.parquet"))
df = pd.concat([pd.read_parquet(f).assign(_day="train" if "training" in f else "test") for f in fs], ignore_index=True)
X = df[FEATS].astype(np.float64).replace([np.inf, -np.inf], np.nan).fillna(0.0).to_numpy(np.float32)
y = (df["Label"] != "Benign").astype(np.int64).to_numpy()

def models():
    return {
        "xgboost (ours)": xgb.XGBClassifier(n_estimators=300, max_depth=8, learning_rate=0.1, tree_method="hist",
                                            n_jobs=2, random_state=SEED),
        "lightgbm": lgb.LGBMClassifier(n_estimators=300, num_leaves=63, learning_rate=0.1, n_jobs=2,
                                       random_state=SEED, verbose=-1),
        "random_forest": RandomForestClassifier(n_estimators=200, n_jobs=2, random_state=SEED),
        "logistic_regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=3000)),
        "mlp": make_pipeline(StandardScaler(), MLPClassifier(hidden_layer_sizes=(64, 32), early_stopping=True,
                                                             max_iter=60, random_state=SEED)),
    }

def latency_ms(m, Xs):
    one = Xs[:1]; m.predict(one); t = time.perf_counter()
    for i in range(300): m.predict(Xs[i:i+1])
    return (time.perf_counter() - t) / 300 * 1000

def run(name, Xtr, ytr, Xte, yte):
    out = {}
    for mname, m in models().items():
        t0 = time.time(); m.fit(Xtr, ytr); tt = time.time() - t0
        p = m.predict(Xte)
        out[mname] = dict(f1=f1_score(yte, p), acc=accuracy_score(yte, p), precision=precision_score(yte, p),
                          recall=recall_score(yte, p), false_alarm_rate=float(((p == 1) & (yte == 0)).sum() / max((yte == 0).sum(), 1)),
                          train_s=tt, latency_ms_single_flow=latency_ms(m, Xte))
        print(f"[{name}] {mname:20s} F1 {out[mname]['f1']:.5f} acc {out[mname]['acc']:.5f} "
              f"FAR {out[mname]['false_alarm_rate']:.4f} train {tt:.0f}s lat {out[mname]['latency_ms_single_flow']:.3f}ms", flush=True)
    return out

res = {}
Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, stratify=y, random_state=SEED)
print("A: train", len(ytr), "test", len(yte), flush=True)
res["A_random_80_20"] = run("A", Xtr, ytr, Xte, yte)
tr, te = (df._day == "train").to_numpy(), (df._day == "test").to_numpy()
print("B: train", tr.sum(), "test", te.sum(), flush=True)
res["B_train_day_to_test_day"] = run("B", X[tr], y[tr], X[te], y[te])
json.dump({"results": res, "config": dict(seed=SEED, rows=len(y), features=len(FEATS),
          dataset="CIC-DDoS2019 (dhoogla parquet, 431,371 rows) — same data as the shipped model")},
          open("ddos_compare_results.json", "w"), indent=1)
