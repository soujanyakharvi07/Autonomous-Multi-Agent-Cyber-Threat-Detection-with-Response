"""Adaptive part: analyst decisions are remembered and change future scoring.
Rejecting a response for an IP lowers the confidence of future detections for that IP."""
import json, pathlib, threading
F = pathlib.Path(__file__).resolve().parent.parent / "data" / "feedback.json"
_lock = threading.Lock()

def _load():
    try: return json.loads(F.read_text())
    except Exception: return {}

def rejections(ip): return int(_load().get("rejected", {}).get(ip, 0))

def record(ip, decision):
    if not ip: return
    with _lock:
        d = _load(); bucket = d.setdefault("rejected" if decision == "reject" else "approved", {})
        bucket[ip] = bucket.get(ip, 0) + 1
        F.parent.mkdir(exist_ok=True); F.write_text(json.dumps(d, indent=1))

def reset():
    F.unlink(missing_ok=True)
