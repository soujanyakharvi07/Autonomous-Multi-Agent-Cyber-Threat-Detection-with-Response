"""SENTINEL-X backend. Run: uvicorn main:app --port 8000   (set VITE_SENTINEL_API_URL=http://localhost:8000)"""
import os, pathlib
_env = pathlib.Path(__file__).parent / ".env"   # simple .env loader (no extra package needed)
if _env.exists():
    for _l in _env.read_text().splitlines():
        if "=" in _l and not _l.strip().startswith("#"):
            _k, _v = _l.split("=", 1)
            if _v.strip(): os.environ.setdefault(_k.strip(), _v.strip())
from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.responses import PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from sentinel.store import Store
from sentinel.agents import Orchestrator
from sentinel import llm, feedback, actions as act
from sentinel.log_agents import analyze_log

app = FastAPI(title="SENTINEL-X API"); S = Store(); S.log_report = None
SAMPLE = pathlib.Path(__file__).parent / "sample_logs" / "attack.log"
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.on_event("startup")
def boot(): S.boot()

def _events(n=500): return [S.event_view(r) for _, r in S.events.head(n).iterrows()]

@app.get("/api/events")
def events(): return _events()

@app.get("/api/detection")
def detection(): return dict(events=_events(), dataset=S.dataset)

@app.get("/api/datasets")
def datasets(): return S.dataset

@app.post("/api/upload")
async def upload(file: UploadFile = File(...)):
    try: return S.analyse_csv(await file.read(), file.filename)
    except ValueError as e: raise HTTPException(422, str(e))

@app.post("/api/analyze/{event_id}")
def analyze(event_id: str):
    if event_id not in set(S.events["event_id"]): raise HTTPException(404, "unknown event")
    rep = Orchestrator(S.det, S.events).run(event_id)
    for a in rep["actions"]: S.actions[a["id"]] = a
    S.reports[event_id] = rep; return rep

@app.get("/api/investigation")
def investigation():
    top = S.events[S.events["prediction"] != "Normal"].sort_values("risk_score", ascending=False)
    if top.empty: raise HTTPException(404, "no threats detected")
    return analyze(top.iloc[0]["event_id"])

@app.get("/api/agents")
def agents(): return investigation()["agents"]

@app.get("/api/threat-intelligence")
def intel(): return investigation()["mitre"]

@app.get("/api/rag/search")
def rag(q: str = "brute force authentication"):
    from sentinel.agents import RET; return dict(results=RET.search(q, 5))

@app.get("/api/risk")
def risk():
    r = investigation(); return dict(score=r["risk_score"], level=r["risk"])

@app.get("/api/reports")
def reports(): return list(S.reports.values())

@app.get("/api/evaluation")
def evaluation():
    m = S.det.metrics; return dict(random_forest=m, trained_on=S.det.trained_on, synthetic_training_data=S.det.synthetic,
        detection_batch_seconds=S.timings.get("detection_s"), feature_importance=S.det.importance)

@app.post("/api/actions/{action_id}/approve")
def approve(action_id: str, approver: str = "analyst"):
    a = S.actions.get(action_id)
    if not a: raise HTTPException(404, "unknown action")
    return act.execute(a, approver)

@app.get("/api/system/status")
def status():
    return [dict(name="ML Model", status="Live", detail=f"RandomForest, trained on {S.det.trained_on}" + (" (synthetic)" if S.det.synthetic else " (uploaded data)")),
            dict(name="RAG", status="Live", detail="TF-IDF retrieval over local knowledge base"),
            dict(name="LLM", status="Live" if llm.available() else "Template", detail=f"Provider: {llm.provider()}" if llm.available() else "No API key set; templated explanations"),
            dict(name="Response actions", status="Approval-gated", detail="Nothing executes without analyst approval")]

@app.post("/api/reset")
def reset(): S.reset(); return S.dataset


# ---------------- Security-log analysis mode ----------------
@app.get("/api/logs/sample", response_class=PlainTextResponse)
def log_sample(): return SAMPLE.read_text()

@app.post("/api/logs/analyze")
async def logs_analyze(file: UploadFile | None = File(None), sample: bool = Query(False)):
    if sample: text, name = SAMPLE.read_text(), "attack.log (sample)"
    elif file is not None:
        raw = await file.read()
        if len(raw) > 25_000_000: raise HTTPException(413, "Log file too large (max 25 MB)")
        text, name = raw.decode("utf-8", errors="replace"), file.filename
    else: raise HTTPException(422, "Upload a log file or use the sample")
    rep = analyze_log(text, name)
    if rep["events_parsed"] == 0: raise HTTPException(422, "No readable events. Expected lines like: 2026-10-05 20:01:01 LOGIN FAILED user=admin ip=10.0.0.45")
    S.log_report = rep
    for inc in rep["incidents"]:
        for a in inc["response"]["actions"]: S.actions[a["id"]] = a
    return rep

@app.post("/api/logs/{incident_id}/decision")
def log_decision(incident_id: str, decision: str = Query(...), approver: str = "analyst"):
    inc = next((i for i in (S.log_report or {}).get("incidents", []) if i["id"] == incident_id), None)
    if not inc: raise HTTPException(404, "unknown incident")
    if decision not in ("approve", "reject"): raise HTTPException(422, "decision must be approve or reject")
    for a in inc["response"]["actions"]:
        if a["status"] != "pending_approval": continue
        if decision == "reject": a["status"] = "rejected"; a["approved_by"] = approver; continue
        try: act.execute(a, approver)
        except Exception as e: a["status"] = "failed"; a["error"] = str(e)[:100]
    feedback.record(inc["source_ip"], decision)
    inc["decision"] = decision + "d"; return inc

@app.post("/api/logs/feedback/reset")
def feedback_reset(): feedback.reset(); return dict(ok=True)
