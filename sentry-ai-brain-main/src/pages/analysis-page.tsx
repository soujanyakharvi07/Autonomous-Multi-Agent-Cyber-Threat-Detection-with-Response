import { useRef, useState } from "react";
import { Check, FileText, Play, ShieldAlert, Upload, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { MetricCard, PageHeader, Panel, RiskBadge, SectionLabel } from "@/components/sentinel/primitives";
import type { RiskLevel } from "@/types/security";

const API = ((import.meta.env["VITE_SENTINEL_API_URL"] as string | undefined) ?? "http://127.0.0.1:8000").replace(/\/$/, "");

type Action = { id: string; text: string; reason: string; priority: string; kind: string; target: string | null; status: string; error?: string };
type Incident = {
  id: string; threat_type: string; severity: RiskLevel; confidence: number; risk_score: number; source_ip: string; target_user: string;
  window: { start: string; end: string }; evidence: string[]; decision: string;
  investigation: { attack_pattern: string; compromise_possible: boolean; related_events: string[]; timeline: { time: string; text: string; flag: string }[] };
  mitre: { id: string; name: string; url: string }[];
  knowledge: { document: string; score: number; passage: string }[];
  explanation: { summary: string; inference: string; uncertainty: string; source: string; model?: string | null; error?: string | null };
  response: { priority: string; rationale: string; source: string; actions: Action[] };
  llm_check: { agrees: boolean; llm_type: string; source: string } | null;
};
type Report = {
  filename: string; events_parsed: number; unreadable_lines: number; status: string; incidents: Incident[];
  agents: { agent: string; status: string; duration: number; output: string }[];
  summary: { threats: number; high: number; medium: number; low: number }; llm: { provider: string | null; used: boolean };
};

const sevColor = (s: string) => (s === "high" ? "text-risk-high border-risk-high/40 bg-risk-high/10" : s === "medium" ? "text-risk-medium border-risk-medium/40 bg-risk-medium/10" : "text-risk-low border-risk-low/40 bg-risk-low/10");

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(`${API}${path}`, init);
  if (!r.ok) {
    let detail = `Request failed (${r.status})`;
    try { detail = (await r.json()).detail ?? detail; } catch { /* keep default */ }
    throw new Error(detail);
  }
  return r.json() as Promise<T>;
}

export function AnalysisPage() {
  const input = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [useSample, setUseSample] = useState(false);
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState<Record<string, boolean>>({});

  const start = async () => {
    setBusy(true); setError(""); setReport(null);
    try {
      let r: Report;
      if (useSample) r = await call<Report>("/api/logs/analyze?sample=true", { method: "POST" });
      else { const f = new FormData(); f.append("file", file as File); r = await call<Report>("/api/logs/analyze", { method: "POST", body: f }); }
      setReport(r);
    } catch (e) {
      setError(e instanceof TypeError ? "Cannot reach the backend. Start it with: uvicorn main:app --port 8000 (in the backend folder)." : (e as Error).message);
    }
    setBusy(false);
  };
  const decide = async (id: string, decision: "approve" | "reject") => {
    try {
      const inc = await call<Incident>(`/api/logs/${id}/decision?decision=${decision}`, { method: "POST" });
      setReport(prev => (prev ? { ...prev, incidents: prev.incidents.map(i => (i.id === id ? inc : i)) } : prev));
    } catch (e) { setError((e as Error).message); }
  };

  const ready = useSample || file !== null;
  return <>
    <PageHeader title="Log Analysis" description="Upload security logs, run the multi-agent analysis, and review explained findings. Responses run only after analyst approval." />
    <input ref={input} type="file" accept=".log,.txt,.csv" className="hidden" onChange={e => { const f = e.target.files?.[0]; if (f) { setFile(f); setUseSample(false); setReport(null); } e.target.value = ""; }} />

    <Panel title="1. Upload security data" subtitle="Lines like: 2026-10-05 20:01:01 LOGIN FAILED user=admin ip=10.0.0.45  (also LOGIN SUCCESS, PROCESS START, FILE ACCESS, FW DENY)">
      <div className="flex flex-wrap items-center gap-3">
        <Button variant="outline" onClick={() => input.current?.click()}><Upload />Upload security log</Button>
        <Button variant="outline" onClick={() => { setUseSample(true); setFile(null); setReport(null); }}><FileText />Use sample attack.log</Button>
        <span className="font-mono text-xs text-muted-foreground">{useSample ? "attack.log (sample, fictional data)" : file ? file.name : "No file selected"}</span>
        <Button className="ml-auto" disabled={!ready || busy} onClick={() => void start()}><Play />{busy ? "Analysing…" : "2. Start analysis"}</Button>
      </div>
    </Panel>

    {error && <div className="mt-4 border border-risk-high/30 bg-risk-high/10 px-3 py-2 text-xs text-risk-high">{error}</div>}
    {busy && <div className="mt-4 border border-primary/30 bg-primary/10 px-3 py-2 text-xs text-primary">Agents are working (the LLM steps can take up to a minute)…</div>}

    {report && <>
      <div className="mt-4 grid gap-4 xl:grid-cols-[1fr_2fr]">
        <Panel title="Agent pipeline" subtitle="Measured execution of each agent">
          <div className="space-y-2">{report.agents.map(a => <div key={a.agent} className="text-xs">
            <div className="flex items-center justify-between"><span className="flex items-center gap-2">{a.status === "completed" ? <Check className="size-3 text-risk-low" /> : <X className="size-3 text-risk-high" />}{a.agent}</span><span className="font-mono text-muted-foreground">{a.duration}s</span></div>
            <div className="ml-5 text-muted-foreground">{a.output}</div></div>)}</div>
        </Panel>
        <div className="grid grid-cols-2 content-start gap-3 md:grid-cols-4">
          <MetricCard label="Status" value={report.status === "THREAT DETECTED" ? "Threat" : "Clear"} detail={report.filename} tone={report.summary.threats ? "danger" : "success"} />
          <MetricCard label="Events parsed" value={report.events_parsed.toLocaleString()} detail={`${report.unreadable_lines} unreadable lines`} />
          <MetricCard label="Threats" value={String(report.summary.threats)} detail={`${report.summary.high} high · ${report.summary.medium} medium · ${report.summary.low} low`} tone="danger" />
          <MetricCard label="LLM" value={report.llm.used ? "Live" : "Template"} detail={report.llm.used ? String(report.llm.provider) : "No API key set"} />
        </div>
      </div>

      {report.incidents.map(i => <div key={i.id} className="mt-5 border border-border bg-card">
        <div className={`flex flex-wrap items-center gap-x-6 gap-y-2 border-b px-5 py-3 ${sevColor(i.severity)}`}>
          <span className="flex items-center gap-2 font-mono text-sm font-semibold tracking-wider"><ShieldAlert className="size-4" />THREAT DETECTED · {i.id}</span>
          <span className="text-xs">Severity <b className="uppercase">{i.severity}</b></span><span className="text-xs">Confidence <b>{i.confidence}%</b></span><span className="text-xs">Risk score <b>{i.risk_score}/100</b></span>
        </div>
        <div className="space-y-5 p-5">
          <div className="grid gap-4 md:grid-cols-4">
            <div><SectionLabel>Threat type</SectionLabel><div className="text-sm font-medium">{i.threat_type}</div><div className="text-xs text-muted-foreground">{i.investigation.attack_pattern}</div></div>
            <div><SectionLabel>Severity</SectionLabel><RiskBadge risk={i.severity} /></div>
            <div><SectionLabel>Source</SectionLabel><div className="font-mono text-sm">{i.source_ip}</div></div>
            <div><SectionLabel>Target</SectionLabel><div className="font-mono text-sm">{i.target_user}</div><div className="font-mono text-xs text-muted-foreground">{i.window.start}–{i.window.end}</div></div>
          </div>

          <div><SectionLabel>Evidence</SectionLabel><ul className="mt-1 space-y-1 text-sm">{i.evidence.map(e => <li key={e} className="flex gap-2"><Check className="mt-1 size-3 shrink-0 text-risk-low" />{e}</li>)}</ul></div>

          <div><SectionLabel>Threat intelligence (MITRE ATT&CK)</SectionLabel><div className="mt-1 flex flex-wrap gap-2">{i.mitre.map(m => <a key={m.id} href={m.url} target="_blank" rel="noreferrer" className="border border-border px-2 py-1 font-mono text-xs text-primary underline">{m.id} · {m.name}</a>)}</div></div>

          <div><SectionLabel>Explanation · {i.explanation.source === "llm" ? `written by LLM (${i.explanation.model ?? ""})` : "template"}{i.explanation.error ? ` — LLM unavailable: ${i.explanation.error}` : ""}</SectionLabel>
            <div className="mt-1 space-y-2 text-sm leading-6">
              <p><b>Why it was flagged: </b>{i.explanation.summary}</p>
              <p><b>Inference: </b>{i.explanation.inference}</p>
              <p><b>Uncertainty: </b>{i.explanation.uncertainty}</p>
              {i.llm_check && <p className="text-xs text-muted-foreground">LLM cross-check ({i.llm_check.source}): {i.llm_check.agrees ? "agrees this is suspicious" : "does not agree — review manually"} · {i.llm_check.llm_type}</p>}
            </div>
            <div className="mt-2 space-y-1">{i.knowledge.slice(0, 3).map(k => <div key={k.document} className="border-l-2 border-primary pl-3 text-xs text-muted-foreground"><span className="font-mono text-primary">{k.document}</span> · {k.passage.slice(0, 160)}…</div>)}</div>
          </div>

          <div><SectionLabel>Recommended response · priority {i.response.priority}</SectionLabel>
            <p className="mt-1 text-sm">{i.response.rationale}</p>
            <div className="mt-2 space-y-2">{i.response.actions.map(a => <div key={a.id} className="flex items-center justify-between gap-3 border border-border p-3 text-xs">
              <div><div className="font-medium">{a.text}</div><div className="text-muted-foreground">{a.reason}</div></div>
              <div className="text-right font-mono"><div>{a.priority}</div><div className={a.status === "executed" || a.status === "acknowledged" ? "text-risk-low" : a.status === "rejected" || a.status === "failed" ? "text-risk-high" : "text-muted-foreground"}>{a.status}{a.error ? `: ${a.error}` : ""}</div></div>
            </div>)}</div>
            <div className="mt-1 text-[11px] text-muted-foreground">Human approval required. Approving a block adds the IP to backend/data/blocklist.txt; nothing else is executed automatically.</div>
          </div>

          {open[i.id] && <div className="border border-border p-4"><SectionLabel>Investigation timeline</SectionLabel>
            <div className="mt-2 space-y-1 font-mono text-xs">{i.investigation.timeline.map((t, k) => <div key={k}><span className="text-muted-foreground">{t.time}</span> · <span className={t.flag === "attack" ? "text-risk-medium" : "text-risk-high"}>{t.text}</span></div>)}</div>
            <ul className="mt-3 list-disc space-y-1 pl-5 text-xs text-muted-foreground">{i.investigation.related_events.map(r => <li key={r}>{r}</li>)}</ul></div>}

          <div className="flex flex-wrap items-center gap-3 border-t border-border pt-4">
            <Button disabled={i.decision !== "pending"} onClick={() => void decide(i.id, "approve")}>Approve response</Button>
            <Button variant="outline" disabled={i.decision !== "pending"} onClick={() => void decide(i.id, "reject")}>Reject</Button>
            <Button variant="outline" onClick={() => setOpen(o => ({ ...o, [i.id]: !o[i.id] }))}>{open[i.id] ? "Hide investigation" : "Investigate"}</Button>
            {i.decision !== "pending" && <span className="font-mono text-xs text-muted-foreground">Decision recorded: {i.decision}{i.decision === "rejected" ? " (future detections for this IP are scored lower)" : ""}</span>}
          </div>
        </div>
      </div>)}
      {report.incidents.length === 0 && <div className="mt-4 border border-border p-6 text-center text-sm text-muted-foreground">No threats detected in {report.events_parsed} events.</div>}
    </>}
  </>;
}
