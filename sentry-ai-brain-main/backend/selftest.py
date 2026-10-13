"""Core test without FastAPI: python selftest.py"""
from sentinel.store import Store
from sentinel.agents import Orchestrator
from sentinel import actions
import os; os.environ["SENTINEL_BLOCKLIST"] = "/tmp/blocklist_test.txt"
S = Store(); S.boot()
print("metrics:", {k: v for k, v in S.det.metrics.items() if k not in ("confusion",)})
print("dataset:", S.dataset)
top = S.events[S.events.prediction == "Brute Force"].sort_values("risk_score", ascending=False).iloc[0]["event_id"]
r = Orchestrator(S.det, S.events).run(top)
print(r["prediction"], r["confidence"], r["risk"], r["mitre"]["id"] if r["mitre"] else None)
print("evidence:", [(e["feature"], e["strength"]) for e in r["evidence"]])
print("agents:", [(a["agent"], a["duration"]) for a in r["agents"]])
print("explanation:", r["explanation"]["source"], r["explanation"]["text"][:200])
blk = next(a for a in r["actions"] if a["kind"] == "block_ip")
assert blk["status"] == "pending_approval"; actions.execute(blk); print("after approve:", blk["status"], open("/tmp/blocklist_test.txt").read().strip())
