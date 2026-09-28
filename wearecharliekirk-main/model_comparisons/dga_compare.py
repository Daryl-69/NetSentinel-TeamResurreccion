"""
Fair DGA model comparison on a public dataset, family-wise split.

Data: Cucchiarelli et al. (2021) DGA_domains_dataset — 25 DGA families from
360 Netlab (13,500 domains each) + Alexa benign domains.

Every model sees the SAME training rows and is tested on the SAME held-out rows.
Test DGA families are never seen in training (5-fold family-wise CV:
5 families held out per fold). Benign test domains are also held out.

Models:
  cnn_bilstm   replica of the shipped NetSentinel DGA architecture
               (emb 64 -> 3 parallel convs k=3,4,5 x128 + BN -> BiLSTM 2x64 -> MLP)
  lstm         plain character LSTM (emb 64 -> LSTM 128 -> linear)
  ngram_lr     character 1-3-gram TF-IDF + logistic regression
  rf_stats     random forest on the 7 simple name features the shipped wrapper computes
  xgb_stats    XGBoost on the same 7 features
  shipped      the shipped ONNX model (trained on DGArchive), NOT retrained
"""
import json, math, sys, time, collections
import numpy as np, pandas as pd, torch, torch.nn as nn
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, accuracy_score, recall_score
import xgboost as xgb
import onnxruntime as ort

SEED = 7
torch.manual_seed(SEED); np.random.seed(SEED); torch.set_num_threads(2)
N_TRAIN_PER_CLASS = 60000     # same subsample for every model (CPU budget)
MAXLEN = 64                   # shipped model pads to 128; 64 covers these domains
EPOCHS = 2
N_TEST_PER_FAMILY = 4000      # test subsample: 5 held-out families x 4,000 + 20,000 benign
ONNX = "/mnt/user-data/uploads/1_sih26#2/wearecharliekirk-main/models/dga_dna_tunneling_detection/dga_cnn_bilstm.onnx"

VOCAB = {c: i + 2 for i, c in enumerate("abcdefghijklmnopqrstuvwxyz0123456789-.")}
BIGRAM = {"th":.0356,"he":.0307,"in":.0243,"er":.0205,"an":.0199,"on":.0176,"en":.0145,"at":.014,"es":.0132,
          "ed":.0131,"or":.0128,"ti":.0127,"is":.0113,"it":.0112,"al":.0109,"ar":.0107,"st":.0105,"to":.0104,
          "nt":.0104,"ng":.0095,"se":.0093,"ha":.0093,"ou":.0087,"io":.0083,"le":.0083,"nd":.0082,"re":.0081,
          "ea":.0069,"de":.0069,"co":.0068,"te":.0067,"of":.0067,"ra":.0062,"ri":.0062,"ne":.0058,"me":.0057,
          "sa":.0056,"li":.0054,"la":.0054,"el":.0053,"ve":.0052,"ta":.0051,"ce":.0049,"si":.0048,"ic":.0045,
          "no":.0044,"ma":.0044,"di":.0043,"ro":.0043,"as":.0042}

def encode(domains, maxlen):
    out = np.zeros((len(domains), maxlen), dtype=np.int64)
    for i, d in enumerate(domains):
        ids = [VOCAB.get(c, 1) for c in d.lower().strip()[:maxlen]]
        out[i, :len(ids)] = ids
    return out

def stats7(d):
    d = d.lower().strip(); labels = d.split("."); name = labels[0] if labels else d
    s = "".join(labels[:-1]) if len(labels) > 1 else d
    cnt = collections.Counter(s); n = max(len(s), 1)
    ent = -sum(c / n * math.log2(c / n) for c in cnt.values()) if s else 0.0
    big = [s[i:i+2] for i in range(len(s) - 1)]
    bscore = sum(BIGRAM.get(b, 0.0) for b in big) / max(len(big), 1)
    alpha = [c for c in s if c.isalpha()]
    cons = sum(1 for c in alpha if c not in "aeiou") / len(alpha) if alpha else 0.0
    digit = sum(c.isdigit() for c in s) / n
    return [ent, bscore, max(len(labels) - 2, 0), cons, digit, max(len(l) for l in labels), len(d)]

class CnnBiLstm(nn.Module):           # mirrors dga_best_model.pt parameter shapes
    def __init__(self):
        super().__init__()
        self.embedding = nn.Embedding(40, 64, padding_idx=0)
        self.convs = nn.ModuleList([nn.Sequential(nn.Conv1d(64, 128, k, padding="same"), nn.BatchNorm1d(128), nn.ReLU())
                                    for k in (3, 4, 5)])
        self.lstm = nn.LSTM(384, 64, num_layers=2, batch_first=True, bidirectional=True, dropout=0.2)
        self.classifier = nn.Sequential(nn.Linear(128, 128), nn.ReLU(), nn.Dropout(0.3),
                                        nn.Linear(128, 64), nn.ReLU(), nn.Dropout(0.3), nn.Linear(64, 2))
    def forward(self, x):
        lengths = (x != 0).sum(1).clamp(min=1).cpu()
        e = self.embedding(x).transpose(1, 2)
        c = torch.cat([conv(e) for conv in self.convs], dim=1).transpose(1, 2)
        packed = nn.utils.rnn.pack_padded_sequence(c, lengths, batch_first=True, enforce_sorted=False)
        _, (h, _) = self.lstm(packed)          # final states at each domain's real last character
        return self.classifier(torch.cat([h[-2], h[-1]], dim=1))

class PlainLstm(nn.Module):
    def __init__(self):
        super().__init__()
        self.embedding = nn.Embedding(40, 64, padding_idx=0)
        self.lstm = nn.LSTM(64, 128, batch_first=True)
        self.out = nn.Linear(128, 2)
    def forward(self, x):
        lengths = (x != 0).sum(1).clamp(min=1).cpu()
        packed = nn.utils.rnn.pack_padded_sequence(self.embedding(x), lengths, batch_first=True, enforce_sorted=False)
        _, (h, _) = self.lstm(packed); return self.out(h[-1])

def train_torch(model, Xtr, ytr, Xte):
    opt = torch.optim.Adam(model.parameters(), lr=1e-3); lossf = nn.CrossEntropyLoss()
    Xtr_t, ytr_t = torch.from_numpy(Xtr), torch.from_numpy(ytr)
    for ep in range(EPOCHS):
        model.train(); perm = torch.randperm(len(Xtr_t))
        for b in range(0, len(perm), 256):
            idx = perm[b:b+256]; opt.zero_grad()
            loss = lossf(model(Xtr_t[idx]), ytr_t[idx]); loss.backward(); opt.step()
    model.eval(); preds = []
    with torch.no_grad():
        for b in range(0, len(Xte), 1024):
            preds.append(model(torch.from_numpy(Xte[b:b+1024])).argmax(1).numpy())
    return np.concatenate(preds)

def shipped_predict(sess, domains):
    X = encode(domains, 128); preds = []
    for b in range(0, len(X), 512):
        logits = sess.run(None, {"domain_chars": X[b:b+512]})[0]
        preds.append((logits.argmax(1) != 0).astype(np.int64))   # dga or dns_tunnel -> malicious
    return np.concatenate(preds)

def main():
    df = pd.read_csv("dga_domains_full.csv", header=None, names=["cls", "family", "domain"]).dropna()
    df["y"] = (df.cls == "dga").astype(np.int64)
    fams = sorted(df[df.y == 1].family.unique()); rng = np.random.RandomState(SEED); rng.shuffle(fams)
    fam_folds = [fams[i::5] for i in range(5)]
    benign_idx = df.index[df.y == 0].to_numpy().copy(); rng.shuffle(benign_idx)
    benign_folds = np.array_split(benign_idx, 5)
    sess = ort.InferenceSession(ONNX, providers=["CPUExecutionProvider"])
    results = collections.defaultdict(list); log = []
    for k in range(5):
        t0 = time.time()
        test_idx = np.concatenate([df.index[df.family.isin(fam_folds[k])].to_numpy(), benign_folds[k]])
        train_pool = df.drop(index=test_idx)
        tr = pd.concat([train_pool[train_pool.y == 1].sample(N_TRAIN_PER_CLASS, random_state=SEED + k),
                        train_pool[train_pool.y == 0].sample(N_TRAIN_PER_CLASS, random_state=SEED + k)])
        te = df.loc[test_idx]
        te = pd.concat([te[te.y == 1].groupby("family", group_keys=False).apply(lambda g: g.sample(min(len(g), N_TEST_PER_FAMILY), random_state=SEED + k)),
                        te[te.y == 0].sample(min((te.y == 0).sum(), 5 * N_TEST_PER_FAMILY), random_state=SEED + k)])
        ytr, yte = tr.y.to_numpy(), te.y.to_numpy()
        preds = {}
        Xtr_c, Xte_c = encode(tr.domain.tolist(), MAXLEN), encode(te.domain.tolist(), MAXLEN)
        preds["cnn_bilstm"] = train_torch(CnnBiLstm(), Xtr_c, ytr, Xte_c)
        preds["lstm"] = train_torch(PlainLstm(), Xtr_c, ytr, Xte_c)
        vec = TfidfVectorizer(analyzer="char", ngram_range=(1, 3), min_df=2, sublinear_tf=True)
        lr = LogisticRegression(max_iter=2000, C=4.0)
        lr.fit(vec.fit_transform(tr.domain), ytr); preds["ngram_lr"] = lr.predict(vec.transform(te.domain))
        Str, Ste = np.array([stats7(d) for d in tr.domain]), np.array([stats7(d) for d in te.domain])
        rf = RandomForestClassifier(n_estimators=200, n_jobs=2, random_state=SEED).fit(Str, ytr)
        preds["rf_stats"] = rf.predict(Ste)
        xg = xgb.XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.1, n_jobs=2, random_state=SEED).fit(Str, ytr)
        preds["xgb_stats"] = xg.predict(Ste)
        preds["shipped"] = shipped_predict(sess, te.domain.tolist())
        for name, p in preds.items():
            results[name].append(dict(f1=f1_score(yte, p), acc=accuracy_score(yte, p),
                                      recall_unseen=recall_score(yte, p), fpr=float(((p == 1) & (yte == 0)).sum() / (yte == 0).sum()),
                                      macro_f1=f1_score(yte, p, average="macro")))
        msg = f"fold {k}: held-out families {fam_folds[k]} | {time.time()-t0:.0f}s | " + \
              ", ".join(f"{n}={results[n][-1]['f1']:.4f}" for n in preds)
        print(msg, flush=True); log.append(msg)
    summary = {n: {m: [float(np.mean([r[m] for r in rs])), float(np.std([r[m] for r in rs]))] for m in rs[0]}
               for n, rs in results.items()}
    json.dump({"summary": summary, "folds": {n: rs for n, rs in results.items()}, "log": log,
               "config": dict(seed=SEED, n_train_per_class=N_TRAIN_PER_CLASS, maxlen=MAXLEN, epochs=EPOCHS,
                              dataset="chrmor/DGA_domains_dataset (Cucchiarelli et al., ESWA 2021)",
                              split="5-fold family-wise CV, 5 DGA families + 20% benign held out per fold; test subsample 4,000 per held-out family + 20,000 held-out benign")},
              open("dga_compare_results.json", "w"), indent=1)
    print("\nSUMMARY (mean ± std over 5 family-wise folds)")
    for n, s in sorted(summary.items(), key=lambda kv: -kv[1]["f1"][0]):
        print(f"  {n:11s} F1 {s['f1'][0]:.4f}±{s['f1'][1]:.4f}  acc {s['acc'][0]:.4f}  "
              f"unseen-family recall {s['recall_unseen'][0]:.4f}  benign FPR {s['fpr'][0]:.4f}")

if __name__ == "__main__":
    main()
