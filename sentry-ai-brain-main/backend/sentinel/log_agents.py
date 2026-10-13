"""Security-log pipeline: Data Collection -> Detection -> Investigation -> RAG -> Explainability -> Response,
run by an Orchestrator. Rules decide what is suspicious (deterministic); the LLM adds cross-checks, explanation
and response rationale. Agents pass structured dicts to each other. Nothing is executed without approval."""
import os, re, time, uuid, datetime as dt
from collections import Counter, defaultdict
from . import llm, feedback
from .knowledge import mitre_url
from .agents import RET

MAX_LLM = int(os.getenv("SENTINEL_MAX_LLM_INCIDENTS", "2"))   # incidents that get LLM calls (free-tier friendly)
KV = re.compile(r'(\w+)=("[^"]*"|\S+)')
LINE = re.compile(r'^(?P<ts>(?:\d{4}-\d{2}-\d{2}[ T])?\d{2}:\d{2}:\d{2})\s+(?P<kind>[A-Z]+(?:[ _][A-Z]+)?)\s+(?P<rest>.*)$')
KINDS = {"LOGIN FAILED": "login_failed", "LOGIN SUCCESS": "login_success", "PROCESS START": "process_start",
         "FILE ACCESS": "file_access", "FW DENY": "fw_deny"}
MITRE = {"Brute Force": ("T1110", "Brute Force"), "Password Spraying": ("T1110.003", "Password Spraying"),
         "Port Scan": ("T1046", "Network Service Discovery"), "valid": ("T1078", "Valid Accounts"),
         "ps": ("T1059.001", "PowerShell"), "data": ("T1005", "Data from Local System")}
SUSP_PROC = ("powershell", "mimikatz", "certutil", "wmic", "psexec", "nc.exe")
SENSITIVE = ("secure", "finance", "payroll", "password", "shadow", "confidential", "credential")
BASE = {"Brute Force": 50, "Password Spraying": 60, "Port Scan": 55}
M = dt.timedelta

def _time(ts):
    for f in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%H:%M:%S"):
        try: return dt.datetime.strptime(ts, f)
        except ValueError: pass

# ---------------- Agent 1: Data Collection ----------------
def collect(text, max_lines=200_000):
    ev, bad = [], 0
    for i, line in enumerate(text.splitlines()[:max_lines]):
        line = line.strip()
        if not line or line.startswith("#"): continue
        m = LINE.match(line)
        kind = KINDS.get(m["kind"].replace("_", " ")) if m else None
        t = _time(m["ts"]) if m else None
        if not (m and kind and t): bad += 1; continue
        kv = {k: v.strip('"') for k, v in KV.findall(m["rest"])}
        port = kv.get("port", "")
        ev.append(dict(n=i + 1, time=t, ts=m["ts"], type=kind, user=kv.get("user"), ip=kv.get("ip"),
                       proc=kv.get("proc"), path=kv.get("path"), port=int(port) if port.isdigit() else None))
    ev.sort(key=lambda e: e["time"]); return ev, bad

# ---------------- Agent 2: Detection (rules + scoring + LLM cross-check) ----------------
def _windows(evs, win, key=None):
    """Sliding window: returns (max count or distinct count, first idx, last idx)."""
    best, j, c = (0, 0, 0), 0, Counter()
    for i, e in enumerate(evs):
        c[key(e) if key else 1] += 1
        while e["time"] - evs[j]["time"] > win:
            k = key(evs[j]) if key else 1; c[k] -= 1
            if c[k] == 0: del c[k]
            j += 1
        size = len(c) if key else i - j + 1
        if size > best[0]: best = (size, j, i)
    return best

def detect(events):
    inc, flagged = [], set()
    fails = defaultdict(list); by_ip_fail = defaultdict(list); deny = defaultdict(list)
    for e in events:
        if e["type"] == "login_failed" and e["ip"]: fails[(e["ip"], e["user"])].append(e); by_ip_fail[e["ip"]].append(e)
        if e["type"] == "fw_deny" and e["ip"] and e["port"]: deny[e["ip"]].append(e)
    for (ip, user), evs in fails.items():
        n, a, b = _windows(evs, M(minutes=5))
        if n < 10: continue
        s, e_ = evs[a]["time"], evs[b]["time"]; flagged.add(ip)
        inc.append(dict(type="Brute Force", ip=ip, user=user, start=s, end=e_, n=n, evidence=[
            f"{n} failed login attempts against account '{user}'", f"Attempts originated from the same IP ({ip})",
            f"Activity occurred within {round((e_ - s).total_seconds() / 60, 1)} minutes"]))
    for ip, evs in by_ip_fail.items():
        if ip in flagged: continue
        users, a, b = _windows(evs, M(minutes=10), key=lambda x: x["user"])
        total = b - a + 1
        if users >= 6 and total >= 10:
            s, e_ = evs[a]["time"], evs[b]["time"]
            inc.append(dict(type="Password Spraying", ip=ip, user=None, start=s, end=e_, n=users, evidence=[
                f"{total} failed logins across {users} different accounts", f"All from the same IP ({ip})",
                f"Activity occurred within {round((e_ - s).total_seconds() / 60, 1)} minutes"]))
    for ip, evs in deny.items():
        ports, a, b = _windows(evs, M(minutes=2), key=lambda x: x["port"])
        if ports >= 15:
            s, e_ = evs[a]["time"], evs[b]["time"]
            inc.append(dict(type="Port Scan", ip=ip, user=None, start=s, end=e_, n=ports, evidence=[
                f"{ports} different destination ports probed and denied by the firewall", f"All from the same IP ({ip})",
                f"Activity occurred within {round((e_ - s).total_seconds())} seconds"]))
    for x in inc:  # deterministic confidence score (rule-based, NOT a calibrated probability)
        success = [e for e in events if e["type"] == "login_success" and e["ip"] == x["ip"] and x["end"] <= e["time"] <= x["end"] + M(minutes=10)
                   and (x["user"] is None or e["user"] == x["user"])]
        x["success"] = success
        c = {"Brute Force": .55 + min(x["n"], 60) / 60 * .30, "Password Spraying": .55 + min(x["n"], 30) / 30 * .25,
             "Port Scan": .50 + min(x["n"], 60) / 60 * .35}[x["type"]] + (.08 if success else 0)
        if success: x["evidence"].append(f"Successful login occurred immediately afterward (user '{success[0]['user']}' at {success[0]['ts']})")
        fb = feedback.rejections(x["ip"]); c = min(.98, c) * (.7 ** fb)
        if fb: x["evidence"].append(f"Analyst previously rejected a response for this IP ({fb}x): confidence reduced")
        x["conf"] = round(c, 2)
    inc.sort(key=lambda x: -x["conf"])
    for i, x in enumerate(inc): x["id"] = f"INC-{i + 1:03d}"
    return inc

def llm_check(x):
    fb = dict(suspicious=True, attack_type=x["type"], confidence=x["conf"], evidence=x["evidence"])
    r = llm.reason_json("You are a cybersecurity detection agent. Analyse this event summary and decide if it is suspicious.\n"
        f"Event: {x['type']} candidate. Evidence: {'; '.join(x['evidence'])}.\n"
        'Return JSON: {"suspicious": bool, "attack_type": str, "confidence": number 0-1, "evidence": [str]}. Never invent evidence.', fb)
    d = r["data"]; agrees = bool(d.get("suspicious", True))
    return dict(agrees=agrees, llm_type=str(d.get("attack_type", x["type"])), llm_confidence=d.get("confidence"), source=r["source"], error=r.get("error"))

# ---------------- Agent 3: Investigation ----------------
def investigate(x, events):
    ip = x["ip"]; ipev = [e for e in events if e["ip"] == ip]
    users = sorted({e["user"] for e in ipev if e["type"] == "login_failed" and e["user"]})
    s = x["success"][0] if x["success"] else None
    post = [e for e in events if s and e["user"] == s["user"] and s["time"] <= e["time"] <= s["time"] + M(minutes=15)
            and e["type"] in ("process_start", "file_access")]
    proc = [e for e in post if e["type"] == "process_start" and any(k in (e["proc"] or "").lower() for k in SUSP_PROC)]
    sens = [e for e in post if e["type"] == "file_access" and any(k in (e["path"] or "").lower() for k in SENSITIVE)]
    related = []
    if s: related.append(f"Successful login for '{s['user']}' at {s['ts']}")
    related += [f"Process '{e['proc']}' started at {e['ts']}" for e in proc] + [f"Sensitive file accessed ('{e['path']}') at {e['ts']}" for e in sens]
    if len(users) > 1: related.append(f"{len(users)} different accounts targeted from this IP")
    first = min(e["time"] for e in ipev).strftime("%H:%M:%S")
    related.append(f"First activity from this IP in the log: {first}")
    pattern = ("Credential attack followed by successful login and suspicious post-authentication activity" if s and (proc or sens)
              else "Credential attack followed by a successful login" if s
              else "Repeated failed authentication with no successful login observed" if x["type"] == "Brute Force"
              else f"Password spraying across {x['n']} accounts" if x["type"] == "Password Spraying"
              else f"Reconnaissance: {x['n']} ports probed")
    tl = [dict(time=x["start"].strftime("%H:%M:%S"), text=f"{x['evidence'][0]} (until {x['end'].strftime('%H:%M:%S')})", flag="attack")]
    if s: tl.append(dict(time=s["ts"][-8:], text=f"Successful login: {s['user']}", flag="compromise"))
    tl += [dict(time=e["ts"][-8:], text=f"Process started: {e['proc']}", flag="suspicious") for e in proc]
    tl += [dict(time=e["ts"][-8:], text=f"File accessed: {e['path']}", flag="suspicious") for e in sens]
    score = BASE[x["type"]] * x["conf"] + 25 * bool(s) + 12 * bool(proc) + 12 * bool(sens)
    score = int(min(100, round(score)))
    mitre = [MITRE[x["type"]]] + ([MITRE["valid"]] if s else []) + ([MITRE["ps"]] if any("powershell" in (e["proc"] or "").lower() for e in proc) else []) + ([MITRE["data"]] if sens else [])
    return dict(attack_pattern=pattern, compromise_possible=bool(s), related_events=related, timeline=tl, risk_score=score,
                severity="high" if score >= 70 else "medium" if score >= 40 else "low",
                mitre=[dict(id=i, name=n, url=mitre_url(i)) for i, n in mitre], suspicious_process=bool(proc), sensitive_file=bool(sens))

# ---------------- Agent 4: RAG ----------------
def rag(x, inv):
    q = " ".join([x["type"], inv["attack_pattern"]] + [m["id"] + " " + m["name"] for m in inv["mitre"]] + ["incident response policy authentication guidelines"])
    return RET.search(q, 4)

# ---------------- Agent 5: Explainability ----------------
def explain(x, inv, know, use_llm):
    obs = x["evidence"] + inv["related_events"]
    fb = dict(summary=(f"The event was classified as {x['type']} (confidence {x['conf']:.0%}) because " + "; ".join(x["evidence"][:3]).lower() + "."
                       + (" A successful login followed the failures, which may mean valid credentials were obtained." if inv["compromise_possible"] else "")),
              inference=f"The pattern is consistent with {', '.join(m['id'] + ' ' + m['name'] for m in inv['mitre'])}.",
              uncertainty="The confidence is a rule-based score, not a calibrated probability. Shared addresses (NAT/VPN) can cause false positives; verify the login with the account owner.")
    if not use_llm: return dict(**fb, observed=obs, source="template")
    r = llm.reason_json("You are a cybersecurity explainability agent. Use ONLY the evidence and knowledge below; do not invent facts.\n"
        f"Observed evidence: {'; '.join(obs)}\nAttack pattern: {inv['attack_pattern']}\nSeverity: {inv['severity']}\n"
        f"Retrieved knowledge: {' | '.join(k['passage'][:400] for k in know)}\n"
        'Return JSON with string keys "summary" (why it was flagged, 2-3 sentences), "inference" (what it likely is, 1-2 sentences), "uncertainty" (limits and what to verify, 1-2 sentences).', fb)
    d = r["data"]; ok = r["source"] == "llm" and all(isinstance(d.get(k), str) and d[k].strip() for k in fb)
    return dict(**({k: d[k] for k in fb} if ok else fb), observed=obs, source="llm" if ok else "template", model=r.get("model"), error=r.get("error"))

# ---------------- Agent 6: Response (recommendations only) ----------------
def respond(x, inv, use_llm):
    ip, user, acts = x["ip"], x["user"], []
    def add(text, reason, prio, kind="advisory", target=None):
        acts.append(dict(id=uuid.uuid4().hex[:8], text=text, reason=reason, priority=prio, kind=kind, target=target, status="pending_approval", requires_approval=True))
    s = inv["compromise_possible"]
    if x["type"] in ("Brute Force", "Password Spraying", "Port Scan"):
        add(f"Temporarily block source IP {ip}", "Stops further attempts from this source.", "HIGH" if s else "MEDIUM", "block_ip", ip)
    if s:
        who = x["success"][0]["user"]
        add(f"Lock or challenge account '{who}'", "A login succeeded after the attack burst; credentials may be compromised.", "HIGH")
        add(f"Force a password reset for '{who}'", "Invalidates credentials the attacker may hold.", "HIGH")
    if inv["suspicious_process"]: add("Review PowerShell/process activity after the login", "Post-login command execution can mean the attacker is active.", "HIGH")
    if inv["sensitive_file"]: add("Investigate the sensitive files that were accessed", "Possible data theft.", "HIGH")
    if x["type"] == "Port Scan": add("Verify that only intended ports are exposed", "Reconnaissance usually precedes an attack.", "MEDIUM")
    add(f"Monitor {ip} for further activity", "Detect follow-up attempts.", "LOW")
    prio = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW"}[inv["severity"]]
    fb = f"Priority {prio}: contain the source first, then protect the affected account and review what happened after any login. Every action needs analyst approval."
    rationale, src = fb, "template"
    if use_llm:
        r = llm.reason("You are a cybersecurity incident response agent. In 2-3 sentences explain the priority and order of these recommended actions. Do NOT claim any action was executed.\n"
                       f"Pattern: {inv['attack_pattern']}. Severity {prio}. Actions: " + "; ".join(a["text"] for a in acts), fb, 600)
        rationale, src = r["text"], r["source"]
    return dict(priority=prio, rationale=rationale, source=src, actions=acts)

# ---------------- Orchestrator ----------------
def analyze_log(text, filename="log", use_llm=True):
    trace = {}
    def run(name, fn, fallback=None):
        t = time.perf_counter(); rec = trace.setdefault(name, dict(agent=name, status="completed", duration=0.0, output=""))
        try: out = fn()
        except Exception as e: out = fallback; rec["status"] = "failed"; rec["output"] = f"error: {str(e)[:100]}"
        rec["duration"] = round(rec["duration"] + time.perf_counter() - t, 3); return out
    events, bad = run("Data Collection Agent", lambda: collect(text), ([], 0))
    trace["Data Collection Agent"]["output"] = trace["Data Collection Agent"]["output"] or f"{len(events)} events normalised, {bad} unreadable lines"
    incidents = run("Detection Agent", lambda: detect(events), [])
    out = []
    for k, x in enumerate(incidents):
        llm_on = use_llm and llm.available() and k < MAX_LLM
        chk = run("Detection Agent", lambda: llm_check(x), None) if llm_on else None
        inv = run("Investigation Agent", lambda: investigate(x, events),
                  dict(attack_pattern=x["type"], compromise_possible=False, related_events=[], timeline=[], risk_score=int(BASE[x["type"]] * x["conf"]), severity="medium", mitre=[dict(id=MITRE[x["type"]][0], name=MITRE[x["type"]][1], url=mitre_url(MITRE[x["type"]][0]))], suspicious_process=False, sensitive_file=False))
        know = run("RAG Agent", lambda: rag(x, inv), [])
        exp = run("Explainability Agent", lambda: explain(x, inv, know, llm_on), dict(summary="Explanation unavailable.", inference="", uncertainty="", observed=x["evidence"], source="template"))
        res = run("Response Agent", lambda: respond(x, inv, llm_on), dict(priority="MEDIUM", rationale="Response unavailable.", source="template", actions=[]))
        out.append(dict(id=x["id"], threat_type=x["type"], severity=inv["severity"], confidence=round(x["conf"] * 100), risk_score=inv["risk_score"],
                        source_ip=x["ip"], target_user=x["user"] or (f"{x['n']} accounts" if x["type"] == "Password Spraying" else "n/a"),
                        window=dict(start=x["start"].strftime("%H:%M:%S"), end=x["end"].strftime("%H:%M:%S")), evidence=x["evidence"],
                        investigation=inv, mitre=inv["mitre"], knowledge=know, explanation=exp, response=res, llm_check=chk, decision="pending"))
    n = len(out)
    notes = {"Detection Agent": f"{n} threat(s) found by rules" + (" (LLM cross-check on top incidents)" if any(o["llm_check"] for o in out) else ""),
             "Investigation Agent": f"{n} incident(s) correlated", "RAG Agent": f"{sum(len(o['knowledge']) for o in out)} passages retrieved",
             "Explainability Agent": f"{n} explanation(s): " + ", ".join(sorted({o['explanation']['source'] for o in out})) if n else "nothing to explain",
             "Response Agent": f"{sum(len(o['response']['actions']) for o in out)} actions proposed, all pending approval"}
    for name, msg in notes.items():
        rec = trace.setdefault(name, dict(agent=name, status="completed", duration=0.0, output=""))
        if not rec["output"]: rec["output"] = msg
    order = ["Data Collection Agent", "Detection Agent", "Investigation Agent", "RAG Agent", "Explainability Agent", "Response Agent"]
    sev = Counter(o["severity"] for o in out)
    return dict(mode="logs", filename=filename, events_parsed=len(events), unreadable_lines=bad, incidents=out, agents=[trace[k] for k in order if k in trace],
                summary=dict(threats=n, high=sev["high"], medium=sev["medium"], low=sev["low"]), llm=dict(provider=llm.provider(), used=bool(use_llm and llm.available())),
                status="THREAT DETECTED" if n else "NO THREAT DETECTED")
