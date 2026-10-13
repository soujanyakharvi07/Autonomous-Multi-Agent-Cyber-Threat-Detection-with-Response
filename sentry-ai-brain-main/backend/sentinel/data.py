"""Dataset loading. Real CICIDS2017 CSVs are supported; if none is supplied a
CICIDS-style *synthetic* generator is used so the system runs end to end.
Synthetic data is always flagged as such (dataset['synthetic'] = True)."""
import numpy as np, pandas as pd

FEATURES = ["Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
            "Flow Bytes/s", "Flow Packets/s", "SYN Flag Count", "ACK Flag Count",
            "Packet Length Mean", "Flow IAT Mean", "Idle Mean", "Fwd Packets/s"]
CLASSES = ["Normal", "DoS", "DDoS", "Brute Force", "Port Scan", "Botnet", "Web Attack"]

def map_label(raw: str) -> str:
    s = str(raw).strip().lower()
    if s in ("benign", "normal"): return "Normal"
    if "web attack" in s or "sql" in s or "xss" in s: return "Web Attack"
    if "ddos" in s: return "DDoS"
    if "dos" in s: return "DoS"
    if "patator" in s or "brute" in s: return "Brute Force"
    if "portscan" in s or "port scan" in s: return "Port Scan"
    if s == "bot" or "botnet" in s: return "Botnet"
    return "Other"

def load_csv(path_or_buf) -> pd.DataFrame:
    try:
        df = pd.read_csv(path_or_buf, low_memory=False)
    except UnicodeDecodeError:  # real CICIDS2017 files are not UTF-8 (the "Web Attack – ..." dash)
        if hasattr(path_or_buf, "seek"): path_or_buf.seek(0)
        df = pd.read_csv(path_or_buf, encoding="latin-1", low_memory=False)
    df.columns = [c.strip() for c in df.columns]
    df = df.replace([np.inf, -np.inf], np.nan)
    return df

def _profile(rng, n, cls):
    r = rng.lognormal
    if cls == "Normal":
        port = rng.choice([80, 443, 53, 8080, 22, 25, 3389], n, p=[.25, .4, .15, .08, .04, .04, .04])
        return dict(port=port, dur=r(13, 1.5, n), fwd=r(1.8, .8, n), bwd=r(1.8, .8, n), bps=r(8, 1.5, n),
                    pps=r(3, 1.2, n), syn=rng.binomial(1, .3, n), ack=rng.binomial(3, .4, n),
                    plen=r(4.2, .6, n), iat=r(11, 1.5, n), idle=r(12, 1.8, n))
    if cls == "DoS":
        return dict(port=rng.choice([80, 443, 8080], n), dur=r(14, 1.2, n), fwd=r(2.4, .8, n), bwd=r(.5, .7, n),
                    bps=r(8.8, 1.3, n), pps=r(4.2, 1.1, n), syn=rng.binomial(3, .5, n), ack=rng.binomial(2, .3, n),
                    plen=r(4.0, .6, n), iat=r(10.5, 1.3, n), idle=r(14.5, 1.2, n))
    if cls == "DDoS":
        return dict(port=rng.choice([80, 443], n), dur=r(10, 1.4, n), fwd=r(3.2, .6, n), bwd=r(.3, .5, n),
                    bps=r(11, 1.2, n), pps=r(7.5, .8, n), syn=rng.binomial(8, .6, n), ack=rng.binomial(1, .2, n),
                    plen=r(3.8, .5, n), iat=r(6.5, 1.0, n), idle=r(8, 1.5, n))
    if cls == "Brute Force":
        return dict(port=rng.choice([22, 21, 3389], n, p=[.6, .25, .15]), dur=r(11.2, .6, n), fwd=r(2.7, .4, n),
                    bwd=r(2.6, .4, n), bps=r(8.6, .6, n), pps=r(5.1, .6, n), syn=rng.binomial(1, .95, n),
                    ack=rng.binomial(6, .6, n), plen=r(4.4, .4, n), iat=r(8.5, .7, n), idle=r(9, 1.0, n))
    if cls == "Port Scan":
        return dict(port=rng.integers(1, 65535, n), dur=r(5.5, 1.0, n), fwd=r(.8, .3, n), bwd=r(.2, .3, n),
                    bps=r(5.5, 1.0, n), pps=r(6.5, .8, n), syn=rng.binomial(2, .9, n), ack=rng.binomial(1, .1, n),
                    plen=r(2.5, .5, n), iat=r(5, 1.0, n), idle=r(5, 1.0, n))
    if cls == "Botnet":
        return dict(port=rng.choice([8080, 443, 6667, 21], n), dur=r(12.5, .7, n), fwd=r(1.6, .4, n),
                    bwd=r(1.5, .4, n), bps=r(6.8, .7, n), pps=r(2.2, .5, n), syn=rng.binomial(1, .4, n),
                    ack=rng.binomial(3, .5, n), plen=r(4.6, .4, n), iat=r(12.8, .5, n), idle=r(13.5, .6, n))
    return dict(port=rng.choice([80, 443, 8080], n), dur=r(12, .9, n), fwd=r(2.3, .6, n), bwd=r(2.0, .6, n),
                bps=r(9.2, .8, n), pps=r(3.9, .7, n), syn=rng.binomial(1, .5, n), ack=rng.binomial(4, .5, n),
                plen=r(5.0, .5, n), iat=r(10, 1.0, n), idle=r(11, 1.2, n))  # Web Attack

def synthetic(n_per_class=700, seed=7) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    parts = []
    for cls in CLASSES:
        n = n_per_class * (4 if cls == "Normal" else 1)
        p = _profile(rng, n, cls)
        parts.append(pd.DataFrame({
            "Destination Port": p["port"], "Flow Duration": p["dur"], "Total Fwd Packets": np.ceil(p["fwd"]),
            "Total Backward Packets": np.ceil(p["bwd"]), "Flow Bytes/s": p["bps"], "Flow Packets/s": p["pps"],
            "SYN Flag Count": p["syn"], "ACK Flag Count": p["ack"], "Packet Length Mean": p["plen"],
            "Flow IAT Mean": p["iat"], "Idle Mean": p["idle"], "Fwd Packets/s": p["pps"] * rng.uniform(.5, .9, n),
            "Label": cls}))
    return pd.concat(parts, ignore_index=True).sample(frac=1, random_state=seed).reset_index(drop=True)

def add_identifiers(df: pd.DataFrame, seed=11) -> pd.DataFrame:
    """CICIDS 'MachineLearningCVE' CSVs have no IPs. Fill private-range identifiers
    (marked synthetic) so events can be tracked; real columns are kept if present."""
    rng = np.random.default_rng(seed); n = len(df); df = df.copy()
    if "Source IP" not in df:
        df["Source IP"] = [f"192.168.{rng.integers(10, 30)}.{rng.integers(2, 250)}" for _ in range(n)]
        df["Source IP synthetic"] = True
    if "Destination IP" not in df:
        df["Destination IP"] = [f"10.0.0.{rng.integers(2, 60)}" for _ in range(n)]
    if "Source Port" not in df: df["Source Port"] = rng.integers(32768, 65000, n)
    if "Protocol" not in df: df["Protocol"] = np.where(df["Destination Port"] == 53, "UDP", "TCP")
    return df
