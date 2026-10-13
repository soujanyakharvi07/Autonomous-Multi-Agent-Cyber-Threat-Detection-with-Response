"""Multi-agent pipeline. The Orchestrator runs each agent over a shared state,
timing every step for real. Agents: Detection -> Investigation -> Threat Intel -> RAG ->
Risk -> Response -> Explanation (LLM)."""
import time, uuid
import pandas as pd
from .knowledge import MITRE, mitre_url, QUERY_BOOST, Retriever
from . import llm

SEVERITY = {"Normal": 0.0, "Other": .5, "Port Scan": .45, "Brute Force": .75, "Web Attack": .8, "DoS": .8, "Botnet": .9, "DDoS": .9}
RESPONSES = {
 "Brute Force": [("Rate-limit or temporarily block source", "block_ip"), ("Enforce MFA / key-only SSH on target", "advisory"), ("Review auth logs for successful logins", "advisory"), ("Rotate exposed credentials", "advisory")],
 "DoS": [("Apply per-client connection limits on target", "advisory"), ("Block offending source", "block_ip"), ("Enable WAF / reverse-proxy rate limits", "advisory")],
 "DDoS": [("Engage upstream scrubbing / CDN", "advisory"), ("Enable SYN cookies and rate limits", "advisory"), ("Notify ISP and incident commander", "advisory")],
 "Port Scan": [("Block or tarpit scanning source", "block_ip"), ("Verify only intended ports are exposed", "advisory"), ("Watch for follow-on exploitation from same source", "advisory")],
 "Botnet": [("Isolate suspected host from network", "block_ip"), ("Inspect DNS/proxy logs for C2 domains", "advisory"), ("Reimage host if compromise is confirmed", "advisory")],
 "Web Attack": [("Add WAF rule for offending source/pattern", "block_ip"), ("Review web server logs and patch application", "advisory")],
}
RET = Retriever()

def risk_level(prediction, confidence):
    score = round(100 * SEVERITY.get(prediction, .5) * (0.5 + 0.5 * confidence))
    return score, ("high" if score >= 60 else "medium" if score >= 30 else "low")

class Orchestrator:
    def __init__(self, detector, event_log): self.det, self.log = detector, event_log  # event_log: DataFrame of analysed events

    def run(self, event_id: str):
        row = self.log.loc[self.log["event_id"] == event_id].iloc[0]
        st = dict(event=row, trace=[])
        for name, fn in [("Detection Agent", self.detect), ("Investigation Agent", self.investigate),
                         ("Threat Intelligence Agent", self.intel), ("RAG Agent", self.rag),
                         ("Response Agent", self.respond), ("Explanation Agent", self.explain)]:
            t = time.perf_counter(); out = fn(st); st["trace"].append(dict(agent=name, status="completed",
                duration=round(time.perf_counter() - t, 3), output=out))
        e = row
        return dict(event_id=event_id, prediction=st["pred"], confidence=round(st["conf"] * 100, 1), risk=st["risk"], risk_score=st["score"],
                    event={k: (v.item() if hasattr(v, "item") else v) for k, v in e.items() if k in
                           ("Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol")},
                    evidence=st["evidence"], related_events=st["related"], mitre=st.get("mitre"), retrieved=st["retrieved"],
                    actions=st["actions"], explanation=st["explanation"], agents=st["trace"], mode="connected",
                    synthetic_ips=bool(e.get("Source IP synthetic", False)))

    def detect(self, st):
        st["pred"], st["conf"] = st["event"]["prediction"], float(st["event"]["confidence"])
        return f"{st['pred']} ({st['conf']*100:.1f}%) via RandomForest"

    def investigate(self, st):
        e = st["event"]; st["evidence"] = self.det.deviations(e) if st["pred"] != "Normal" else []
        same = self.log[(self.log["Source IP"] == e["Source IP"]) & (self.log["event_id"] != e["event_id"])]
        st["related"] = dict(same_source_events=int(len(same)),
                             same_source_threats=int((same["prediction"] != "Normal").sum()),
                             distinct_dest_ports=int(same["Destination Port"].nunique()))
        return f"{len(st['evidence'])} deviating features; {st['related']['same_source_events']} related events"

    def intel(self, st):
        m = MITRE.get(st["pred"]); st["mitre"] = None
        if m: st["mitre"] = dict(id=m[0], name=m[1], tactic=m[2], url=mitre_url(m[0]), source="MITRE ATT&CK (technique ID mapping)")
        return st["mitre"]["id"] if m else "no technique mapping"

    def rag(self, st):
        q = QUERY_BOOST.get(st["pred"], "incident response") + " " + " ".join(x["feature"] for x in st["evidence"])
        st["retrieved"] = RET.search(q, 3); return f"{len(st['retrieved'])} passages"

    def respond(self, st):
        st["score"], st["risk"] = risk_level(st["pred"], st["conf"])
        e = st["event"]; acts = []
        for text, kind in RESPONSES.get(st["pred"], []):
            acts.append(dict(id=uuid.uuid4().hex[:8], text=text, kind=kind, status="pending_approval",
                             target=e["Source IP"] if kind == "block_ip" else None))
        st["actions"] = acts; return f"{len(acts)} actions, all pending analyst approval"

    def explain(self, st):
        ev = "; ".join(f"{x['feature']}={x['value']:.3g} ({x['direction']} normal median {x['normal_median']:.3g}, {x['strength']})" for x in st["evidence"])
        rel = st["related"]; m = st.get("mitre")
        facts = (f"Prediction: {st['pred']} at {st['conf']*100:.1f}% confidence. Risk {st['risk']} ({st['score']}/100). "
                 f"Evidence: {ev or 'none'}. Related: {rel}. MITRE: {m['id'] + ' ' + m['name'] if m else 'n/a'}. "
                 f"Knowledge: {' | '.join(r['passage'] for r in st['retrieved'])}")
        fallback = (f"This flow was classified as {st['pred']} with {st['conf']*100:.1f}% confidence (risk {st['risk']}). "
                    f"Why it matters: {ev or 'no strong deviations from normal traffic'}. The same source produced "
                    f"{rel['same_source_threats']} other flagged events. " + (f"It maps to MITRE ATT&CK {m['id']} ({m['name']}). " if m else "")
                    + "Recommended actions below require analyst approval.")
        st["explanation"] = llm.reason(facts + "\n\nExplain the threat, why it is dangerous, and what to do.", fallback)
        return f"explanation via {st['explanation']['source']}"
