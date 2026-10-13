import { agents, dataset, documents, evaluations, events, ragResults, services } from "@/data/mock-security";
import type { AnalysisMode } from "@/types/security";

const delay = (ms = 350) => new Promise((resolve) => setTimeout(resolve, ms));
const endpoint = import.meta.env.VITE_SENTINEL_API_URL as string | undefined;

async function request<T>(path: string, mode: AnalysisMode, demoValue: T): Promise<T> {
  if (mode === "demo") { await delay(); return structuredClone(demoValue); }
  if (!endpoint) throw new Error("Connected mode requires VITE_SENTINEL_API_URL.");
  const response = await fetch(`${endpoint}${path}`);
  if (!response.ok) throw new Error(`API request failed (${response.status}).`);
  return response.json() as Promise<T>;
}
export const securityApi = {
 events:(mode:AnalysisMode)=>request("/api/events",mode,events),
 detection:(mode:AnalysisMode)=>request("/api/detection",mode,{events,dataset}),
 investigation:(mode:AnalysisMode)=>request("/api/investigation",mode,{event:events[0],agents}),
 agents:(mode:AnalysisMode)=>request("/api/agents",mode,agents),
 intelligence:(mode:AnalysisMode)=>request("/api/threat-intelligence",mode,{technique:"T1110 · Brute Force",source:"MITRE ATT&CK mapping (demo)"}),
 rag:(mode:AnalysisMode)=>request("/api/rag/search",mode,{documents,results:ragResults}),
 risk:(mode:AnalysisMode)=>request("/api/risk",mode,{score:86,level:"high"}),
 reports:(mode:AnalysisMode)=>request("/api/reports",mode,{id:"RPT-2026-1042",event:events[0]}),
 datasets:(mode:AnalysisMode)=>request("/api/datasets",mode,dataset),
 evaluation:(mode:AnalysisMode)=>request("/api/evaluation",mode,evaluations),
 status:(mode:AnalysisMode)=>request("/api/system/status",mode,services),,
 analyze:(id:string)=>post<unknown>(`/api/analyze/${id}`),
 approveAction:(id:string)=>post<unknown>(`/api/actions/${id}/approve`),
 uploadCsv:async(file:File)=>{ if(!endpoint) throw new Error("Connected mode requires VITE_SENTINEL_API_URL."); const f=new FormData(); f.append("file",file); const r=await fetch(`${endpoint}/api/upload`,{method:"POST",body:f}); if(!r.ok) throw new Error((await r.json()).detail??`Upload failed (${r.status}).`); return r.json(); },
};
async function post<T>(path:string):Promise<T>{ if(!endpoint) throw new Error("Connected mode requires VITE_SENTINEL_API_URL."); const r=await fetch(`${endpoint}${path}`,{method:"POST"}); if(!r.ok) throw new Error(`API request failed (${r.status}).`); return r.json() as Promise<T>; }
