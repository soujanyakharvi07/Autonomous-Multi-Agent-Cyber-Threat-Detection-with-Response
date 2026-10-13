import io, time, pathlib, joblib, pandas as pd
from .data import synthetic, add_identifiers, load_csv, FEATURES, map_label
from .detector import Detector
from .agents import risk_level

STATE = pathlib.Path(__file__).resolve().parent.parent / "data" / "state.joblib"

class Store:
    def __init__(self):
        self.det = Detector(); self.events = pd.DataFrame(); self.dataset = {}; self.actions = {}
        self.reports = {}; self.timings = {}

    def boot(self):
        if STATE.exists():  # a model trained on uploaded real data survives restarts
            try:
                self.det, self.events, self.dataset = joblib.load(STATE); return
            except Exception: pass
        self.det.train(synthetic(), True)
        self.analyse(synthetic(150, seed=99), "CICIDS2017-style synthetic demo batch", True)

    def save(self):
        STATE.parent.mkdir(exist_ok=True); joblib.dump((self.det, self.events, self.dataset), STATE)

    def reset(self):
        STATE.unlink(missing_ok=True); self.det = Detector(); self.boot()

    def train_on(self, df):
        self.det.train(df, False)

    def analyse(self, df, name, synthetic_flag):
        df = add_identifiers(df); df = df.dropna(subset=FEATURES).reset_index(drop=True)
        t = time.perf_counter(); preds = self.det.predict(df); self.timings["detection_s"] = round(time.perf_counter() - t, 3)
        df["prediction"] = [p for p, _ in preds]; df["confidence"] = [c for _, c in preds]
        df["event_id"] = [f"EVT-{70000 + i}" for i in range(len(df))]
        df["timestamp"] = pd.date_range("2026-10-03 00:00", periods=len(df), freq="37s").strftime("%Y-%m-%d %H:%M:%S")
        rs = [risk_level(p, c) for p, c in preds]; df["risk"] = [r[1] for r in rs]; df["risk_score"] = [r[0] for r in rs]
        df["status"] = ["New" if p != "Normal" else "Reviewed" for p in df["prediction"]]
        self.events = df
        truth = df["Label"].map(map_label) if "Label" in df else None
        mal = int((df["prediction"] != "Normal").sum())
        self.dataset = dict(name=name, rows=len(df), columns=int(df.shape[1]), normal=len(df) - mal, malicious=mal,
                            missing=int(df[FEATURES].isna().sum().sum()), duplicates=int(df[FEATURES].duplicated().sum()),
                            synthetic=synthetic_flag, status="Analysed",
                            batch_accuracy=round(float((truth == df["prediction"]).mean() * 100), 2) if truth is not None else None)
        return self.dataset

    def analyse_csv(self, raw: bytes, name: str):
        df = load_csv(io.BytesIO(raw))
        missing = [c for c in FEATURES if c not in df.columns]
        if missing: raise ValueError(f"CSV is missing CICIDS2017 columns: {missing[:5]}")
        if "Label" in df.columns:  # labelled real data -> train on it, then analyse UNSEEN held-out rows
            self.det.train(df, False, max_per_class=6000)
            test = df.loc[self.det.test_index]; test = test.sample(min(3000, len(test)), random_state=3)
            ds = self.analyse(test, f"{name} (held-out test rows)", False); self.save(); return ds
        return self.analyse(df.head(5000), name, False)  # unlabelled -> use current model

    def event_view(self, r):
        proto = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(r["Protocol"], r["Protocol"]) if not isinstance(r["Protocol"], str) else r["Protocol"]
        return dict(id=r["event_id"], timestamp=r["timestamp"], sourceIp=r["Source IP"], destinationIp=r["Destination IP"],
                    protocol=str(proto), sourcePort=int(r["Source Port"]), destinationPort=int(r["Destination Port"]),
                    prediction=r["prediction"], confidence=round(float(r["confidence"]) * 100, 1), risk=r["risk"], status=r["status"])
