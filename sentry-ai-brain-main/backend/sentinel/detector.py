"""Real ML detector: Random Forest trained on CICIDS2017-format data."""
import time, numpy as np, pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix
from .data import FEATURES, map_label, synthetic

class Detector:
    def __init__(self):
        self.model = None; self.metrics = {}; self.baseline = {}; self.importance = {}
        self.trained_on = None; self.synthetic = True

    def train(self, df: pd.DataFrame, synthetic_data: bool, max_per_class=None):
        df = df.copy()
        if "Label" not in df: raise ValueError("Training data needs a 'Label' column")
        df["y"] = df["Label"].map(map_label)
        df = df.dropna(subset=FEATURES)
        keep = df["y"].value_counts(); df = df[df["y"].isin(keep[keep >= 10].index)]  # drop tiny classes
        if max_per_class:
            df = pd.concat([g.sample(min(len(g), max_per_class), random_state=1) for _, g in df.groupby("y")])
        X, y = df[FEATURES].astype(float), df["y"]
        Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=.25, stratify=y, random_state=1)
        t = time.perf_counter()
        self.model = RandomForestClassifier(n_estimators=150, n_jobs=-1, random_state=1, class_weight="balanced").fit(Xtr, ytr)
        train_s = time.perf_counter() - t
        t = time.perf_counter(); pred = self.model.predict(Xte); inf_s = time.perf_counter() - t
        p, r, f, _ = precision_recall_fscore_support(yte, pred, average="weighted", zero_division=0)
        self.test_index = Xte.index; labels = list(self.model.classes_)
        self.metrics = dict(accuracy=round(accuracy_score(yte, pred) * 100, 2), precision=round(p * 100, 2),
                            recall=round(r * 100, 2), f1=round(f * 100, 2), train_seconds=round(train_s, 2),
                            ms_per_event=round(inf_s / len(Xte) * 1000, 4), test_rows=len(Xte), labels=labels,
                            confusion=confusion_matrix(yte, pred, labels=labels).tolist())
        normal = Xtr[ytr == "Normal"]
        self.baseline = {c: dict(median=float(normal[c].median()), scale=float(normal[c].quantile(.75) - normal[c].quantile(.25)) or 1.0)
                         for c in FEATURES}
        self.importance = dict(zip(FEATURES, map(float, self.model.feature_importances_)))
        self.trained_on = f"{len(df)} rows ({', '.join(f'{k}:{v}' for k, v in df['y'].value_counts().items())})"; self.synthetic = synthetic_data
        return self

    def ensure(self):
        if self.model is None: self.train(synthetic(), True)
        return self

    def predict(self, df: pd.DataFrame):
        self.ensure()
        X = df[FEATURES].astype(float).fillna(0)
        proba = self.model.predict_proba(X); idx = proba.argmax(1)
        return [(self.model.classes_[i], float(proba[k, i])) for k, i in enumerate(idx)]

    def deviations(self, row: pd.Series, top=4):
        """Evidence: which features of THIS flow deviate most from the learned normal baseline,
        weighted by the model's real feature importance."""
        out = []
        for c in FEATURES:
            b = self.baseline[c]; v = float(row[c]); z = (v - b["median"]) / b["scale"]
            out.append((abs(z) * self.importance[c], c, v, b["median"], z))
        out.sort(reverse=True)
        return [dict(feature=c, value=v, normal_median=m, z=round(z, 1),
                     strength="High" if abs(z) >= 3 else "Medium" if abs(z) >= 1.5 else "Low",
                     direction="above" if z > 0 else "below", importance=round(self.importance[c], 3))
                for _, c, v, m, z in out[:top]]
