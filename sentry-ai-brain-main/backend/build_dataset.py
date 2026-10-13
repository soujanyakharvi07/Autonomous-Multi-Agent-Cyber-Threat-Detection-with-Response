"""Combine the real CICIDS2017 CSV files into ONE small, balanced file you can upload.
Memory-safe: reads each big file in chunks and only the 13 columns we need.
Usage:  python build_dataset.py "C:\\path\\to\\csv\\folder" [max_rows_per_class]
Output: data/cicids_sample.csv"""
import sys, glob, os, numpy as np, pandas as pd
from sentinel.data import map_label, FEATURES

def cap_classes(df, cap):
    return pd.concat([g.sample(min(len(g), cap), random_state=1) for _, g in df.groupby("Label")])

folder = sys.argv[1]; cap = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
files = sorted(glob.glob(os.path.join(folder, "**", "*.csv"), recursive=True))
if not files: sys.exit(f"No .csv files found in {folder}")
keep = set(FEATURES + ["Label"]); parts = []
for f in files:
    got = []
    try:
        for ch in pd.read_csv(f, usecols=lambda c: c.strip() in keep, chunksize=100_000, encoding="latin-1"):
            ch.columns = [c.strip() for c in ch.columns]
            if "Label" not in ch.columns: break
            ch = ch.replace([np.inf, -np.inf], np.nan).dropna()
            ch["Label"] = ch["Label"].map(map_label)
            got.append(cap_classes(ch, cap))
    except Exception as e:
        print("skipped", os.path.basename(f), "->", str(e)[:80]); continue
    if got:
        df = cap_classes(pd.concat(got), cap); parts.append(df)
        print(os.path.basename(f), df["Label"].value_counts().to_dict())
if not parts: sys.exit("No usable files (need a 'Label' column).")
out = cap_classes(pd.concat(parts), cap).sample(frac=1, random_state=1)
os.makedirs("data", exist_ok=True); out.to_csv("data/cicids_sample.csv", index=False)
print("\nWrote data/cicids_sample.csv", len(out), "rows"); print(out["Label"].value_counts())
