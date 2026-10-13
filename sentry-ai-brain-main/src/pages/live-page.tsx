import { useCallback, useEffect, useRef, useState } from "react";
import { Check, Play, ShieldCheck, Upload } from "lucide-react";
import { Button } from "@/components/ui/button";
import { MetricCard, PageHeader, Panel, RiskBadge, ScoreBar, ScopeNote, SectionLabel, ThreatBadge } from "@/components/sentinel/primitives";
import type { RiskLevel } from "@/types/security";

const API = ((import.meta.env["VITE_SENTINEL_API_URL"] as string | undefined) ?? "http://127.0.0.1:8000").replace(/\/$/, "");

type Ev = { id: string; timestamp: string; sourceIp: string; destinationIp: string; protocol: string; sourcePort: number; destinationPort: number; prediction: string; confidence: number; risk: RiskLevel; status: string };
type Dataset = { name: string; rows: number; malicious: number; normal: number; missing: number; duplicates: number; synthetic: boolean; batch_accuracy: number | null };
type Metrics = { random_forest: { accuracy: number; precision: number; recall: number; f1: number; test_rows: number }; trained_on: string; synthetic_training_data: boolean };
type Action = { id: string; text: string; kind: string; status: string; target: string | null };
type Evidence = { feature: string; value: number; normal_median: number; strength: string; direction: string };
type Report = {
  event_id: string; prediction: string; confidence: number; risk: RiskLevel; risk_score: number;
  event: Record<string, string | number>; evidence: Evidence[];
  related_events: { same_source_events: number; same_source_threats: number };
  mitre: { id: string; name: string; tactic: string; url: string } | null;
  retrieved: { document: string; score: number; passage: string }[];
  actions: Action[]; explanation: { text: string; source: string; model: string | null; error?: string };
  agents: { agent: string; status: string; duration: number; output: string }[];
};

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(`${API}${path}`, init);
  if (!r.ok) {
    let detail = `Request failed (${r.status})`;
    try { detail = (await r.json()).detail ?? detail; } catch { /* keep default */ }
    throw new Error(detail);
  }
  return r.json() as Promise<T>;
}
const num = (v: number) => Number(v).toPrecision(3);

export function LivePage() {
  const input = useRef<HTMLInputElement>(null);
  const [events, setEvents] = useState<Ev[]>([]);
  const [dataset, setDataset] = useState<Dataset | null>(null);
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [report, setReport] = useState<Report | null>(null);
  const [actions, setActions] = useState<Action[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");
  const [onlyThreats, setOnlyThreats] = useState(true);

  const load = useCallback(async () => {
    try {
      const [d, m] = await Promise.all([call<{ events: Ev[]; dataset: Dataset }>("/api/detection"), call<Metrics>("/api/evaluation")]);
      setEvents(d.events); setDataset(d.dataset); setMetrics(m); setReport(null); setActions([]); setError("");
    } catch (e) {
      setError(e instanceof TypeError ? "Cannot reach the backend. Start it with: uvicorn main:app --port 8000 (in the backend folder)." : (e as Error).message);
    }
  }, []);
  useEffect(() => { void load(); }, [load]);

  const upload = async (file: File) => {
    setBusy("Training on your file and analysing unseen rows… this can take a minute.");
    try {
      const f = new FormData(); f.append("file", file);
      await call("/api/upload", { method: "POST", body: f });
      await load();
    } catch (e) { setError((e as Error).message); }
    setBusy("");
  };
  const analyze = async (id: string) => {
    setBusy(`Agents investigating ${id}…`);
    try {
      const r = await call<Report>(`/api/analyze/${id}`, { method: "POST" });
      setReport(r); setActions(r.actions); setError("");
    } catch (e) { setError((e as Error).message); }
    setBusy("");
  };
  const approve = async (id: string) => {
    try {
      const a = await call<Action>(`/api/actions/${id}/approve`, { method: "POST" });
      setActions(prev => prev.map(x => (x.id === id ? { ...x, ...a } : x)));
    } catch (e) { setError((e as Error).message); }
  };

  const rows = events.filter(e => !onlyThreats || e.prediction !== "Normal").slice(0, 40);

  return <>
    <PageHeader title="Live Analysis" description="Real detection, agent investigation, explanation and approval-gated response, served by the Python backend."
      actions={<Button variant="outline" onClick={() => input.current?.click()}><Upload />Upload labelled CICIDS2017 CSV</Button>} />
    <input ref={input} type="file" accept=".csv" className="hidden" onChange={e => { const f = e.target.files?.[0]; if (f) void upload(f); e.target.value = ""; }} />

    {error && <div className="mb-4 border border-risk-high/30 bg-risk-high/10 px-3 py-2 text-xs text-risk-high">{error}</div>}
    {busy && <div className="mb-4 border border-primary/30 bg-primary/10 px-3 py-2 text-xs text-primary">{busy}</div>}
    {dataset?.synthetic && <div className="mb-4 border border-risk-medium/20 bg-risk-medium/5 px-3 py-2 text-xs text-risk-medium">This batch is CICIDS-style synthetic data, so the accuracy shown is not a real-world result. Upload a real CICIDS2017 CSV (with a Label column) to train and analyse real traffic.</div>}

    {dataset && <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
      <MetricCard label="Events analysed" value={dataset.rows.toLocaleString()} detail={dataset.name} />
      <MetricCard label="Threats detected" value={dataset.malicious.toLocaleString()} detail={`${dataset.normal.toLocaleString()} normal`} tone="danger" />
      <MetricCard label="Batch accuracy" value={dataset.batch_accuracy == null ? "n/a" : `${dataset.batch_accuracy}%`} detail="vs. labels in the file" tone="success" />
      <MetricCard label="Data quality" value={`${dataset.missing} / ${dataset.duplicates}`} detail="missing values / duplicates" />
    </div>}

    {metrics && <div className="mt-3">
      <div className="mb-2 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">Model quality · measured on {metrics.random_forest.test_rows.toLocaleString()} unseen test rows · trained on {metrics.trained_on}</div>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <MetricCard label="Accuracy" value={`${metrics.random_forest.accuracy}%`} detail="Random Forest" tone="success" />
        <MetricCard label="Precision" value={`${metrics.random_forest.precision}%`} detail="weighted" />
        <MetricCard label="Recall" value={`${metrics.random_forest.recall}%`} detail="weighted" />
        <MetricCard label="F1 score" value={`${metrics.random_forest.f1}%`} detail="weighted" />
      </div>
    </div>}

    <div className="mt-4 grid gap-4 xl:grid-cols-[1fr_1.2fr]">
      <Panel title="Detected events" subtitle="Click an event to run the multi-agent investigation"
        action={<label className="flex items-center gap-2 text-xs text-muted-foreground"><input type="checkbox" checked={onlyThreats} onChange={e => setOnlyThreats(e.target.checked)} />Threats only</label>}>
        <div className="max-h-[640px] overflow-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-muted/70 font-mono text-[10px] uppercase text-muted-foreground"><tr>{["Event", "Source → Dest", "Prediction", "Conf.", "Risk", ""].map(h => <th key={h} className="px-3 py-2 font-medium">{h}</th>)}</tr></thead>
            <tbody>{rows.map(e => <tr key={e.id} className={`cursor-pointer border-t border-border hover:bg-accent/50 ${report?.event_id === e.id ? "bg-accent/40" : ""}`} onClick={() => void analyze(e.id)}>
              <td className="px-3 py-2 font-mono text-primary">{e.id}</td>
              <td className="px-3 py-2 font-mono">{e.sourceIp}<div className="text-muted-foreground">→ {e.destinationIp}:{e.destinationPort}</div></td>
              <td className="px-3 py-2"><ThreatBadge threat={e.prediction} /></td>
              <td className="px-3 py-2 font-mono">{e.confidence}%</td>
              <td className="px-3 py-2"><RiskBadge risk={e.risk} /></td>
              <td className="px-3 py-2"><Play className="size-3 text-primary" /></td>
            </tr>)}</tbody>
          </table>
          {!rows.length && !error && <div className="p-6 text-center text-xs text-muted-foreground">No events to show.</div>}
        </div>
      </Panel>

      <div className="space-y-4">
        {!report && <Panel><div className="p-8 text-center text-sm text-muted-foreground">Select an event on the left. The Detection, Investigation, Threat Intelligence, RAG, Response and Explanation agents will run on it.</div></Panel>}
        {report && <>
          <div className="border border-border bg-card p-5">
            <div className="flex flex-wrap items-center gap-4">
              <div><SectionLabel>Threat</SectionLabel><ThreatBadge threat={report.prediction} /></div>
              <div><SectionLabel>Risk</SectionLabel><RiskBadge risk={report.risk} /></div>
              <div><SectionLabel>Confidence</SectionLabel><span className="font-mono text-xl font-semibold">{report.confidence}%</span></div>
              <div className="min-w-32 flex-1"><SectionLabel>Risk score {report.risk_score}/100</SectionLabel><ScoreBar value={report.risk_score} tone="risk" /></div>
            </div>
            <div className="mt-3 font-mono text-[11px] text-muted-foreground">{report.event_id} · {String(report.event["Source IP"])} → {String(report.event["Destination IP"])}:{String(report.event["Destination Port"])}</div>
          </div>

          <Panel title="Explanation" subtitle={report.explanation.source === "llm" ? `Written by LLM (${report.explanation.model})` : (report.explanation.error ? `LLM unavailable (${report.explanation.error}) — template shown` : "Template explanation — add an API key in backend/.env for LLM reasoning")}>
            <p className="text-sm leading-6">{report.explanation.text}</p>
            {report.mitre && <a className="mt-3 inline-flex items-center gap-2 text-xs text-primary underline" href={report.mitre.url} target="_blank" rel="noreferrer"><ShieldCheck className="size-4" />MITRE ATT&CK {report.mitre.id} · {report.mitre.name} ({report.mitre.tactic})</a>}
          </Panel>

          <Panel title="Why it is dangerous" subtitle="Features of this flow that deviate most from normal traffic (from the trained model)">
            <div className="space-y-2">{report.evidence.length === 0 && <div className="text-xs text-muted-foreground">No strong deviations (normal traffic).</div>}
              {report.evidence.map(e => <div key={e.feature} className="flex items-center justify-between border-b border-border pb-2 text-xs last:border-0">
                <div><div className="font-medium">{e.feature}</div><div className="font-mono text-muted-foreground">{num(e.value)} vs normal {num(e.normal_median)} ({e.direction})</div></div>
                <span className={e.strength === "High" ? "text-risk-high" : "text-risk-medium"}>{e.strength}</span></div>)}
            </div>
            <div className="mt-3 text-xs text-muted-foreground">Same source: {report.related_events.same_source_events} other events, {report.related_events.same_source_threats} flagged.</div>
          </Panel>

          <Panel title="Knowledge retrieved (RAG)">
            <div className="space-y-3">{report.retrieved.map(r => <div key={r.document} className="border-l-2 border-primary pl-3 text-xs"><div className="font-mono text-primary">{r.document} · {r.score}</div><p className="mt-1 text-muted-foreground">{r.passage}</p></div>)}</div>
          </Panel>

          <Panel title="Agent pipeline" subtitle="Measured execution of each agent">
            <div className="space-y-1.5">{report.agents.map(a => <div key={a.agent} className="flex items-center justify-between text-xs"><span className="flex items-center gap-2"><Check className="size-3 text-risk-low" />{a.agent}</span><span className="font-mono text-muted-foreground">{a.output} · {a.duration}s</span></div>)}</div>
          </Panel>

          <Panel title="Recommended actions" subtitle="Nothing runs until an analyst approves it">
            <div className="space-y-2">{actions.length === 0 && <div className="text-xs text-muted-foreground">No action needed for normal traffic.</div>}
              {actions.map(a => <div key={a.id} className="flex items-center justify-between gap-3 border border-border p-3 text-xs">
                <div><div className="font-medium">{a.text}</div><div className="font-mono text-muted-foreground">{a.kind === "block_ip" ? `Adds ${a.target} to blocklist` : "Advisory step"} · {a.status}</div></div>
                {a.status === "pending_approval" ? <Button size="sm" onClick={() => void approve(a.id)}>Approve</Button> : <span className="flex items-center gap-1 text-risk-low"><Check className="size-3" />{a.status}</span>}
              </div>)}
            </div>
          </Panel>
        </>}
      </div>
    </div>
    <div className="mt-4"><ScopeNote /></div>
  </>;
}
