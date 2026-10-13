import { createContext, useContext, useMemo, useState, type ReactNode } from "react";
import { toast } from "sonner";
import { agents as initialAgents, dataset, events } from "@/data/mock-security";
import type { AgentRun, AnalysisMode, SecurityEvent } from "@/types/security";

type Stage = "idle" | "uploaded" | "validated" | "preprocessed" | "classified";
interface AppContextValue { signedIn:boolean; enterWorkspace:(mode:AnalysisMode)=>void; mode:AnalysisMode; setMode:(m:AnalysisMode)=>void; selectedEvent:SecurityEvent; selectEvent:(e:SecurityEvent)=>void; stage:Stage; setStage:(s:Stage)=>void; agents:AgentRun[]; running:boolean; runDetection:()=>void; runPipeline:()=>void; thresholds:{low:number;medium:number}; setThresholds:(v:{low:number;medium:number})=>void; }
const AppContext = createContext<AppContextValue | undefined>(undefined);
export function SentinelProvider({children}:{children:ReactNode}) {
 const [signedIn,setSignedIn]=useState(false);
 const [mode,setModeState]=useState<AnalysisMode>("demo"); const [selectedEvent,setSelectedEvent]=useState(events[0]);
 const [stage,setStage]=useState<Stage>("idle"); const [agents,setAgents]=useState(initialAgents); const [running,setRunning]=useState(false);
 const [thresholds,setThresholds]=useState({low:39,medium:69});
 const setMode=(next:AnalysisMode)=>{setModeState(next); toast(next==="demo"?"Demo mode enabled":"Connected mode selected — endpoint required");};
 const enterWorkspace=(next:AnalysisMode)=>{setModeState(next);setSignedIn(true);toast.success(next==="demo"?"Demo workspace ready":"Connected workspace opened")};
 const selectEvent=(event:SecurityEvent)=>{setSelectedEvent(event);};
 const runDetection=()=>{setStage("uploaded"); ["validated","preprocessed","classified"].forEach((s,i)=>setTimeout(()=>setStage(s as Stage),650*(i+1))); setTimeout(()=>toast.success("Demo detection complete · 1,284 threats identified"),2100);};
 const runPipeline=()=>{setRunning(true); setAgents(initialAgents.map((a,i)=>({...a,status:i===0?"running":"queued"}))); initialAgents.forEach((_,i)=>setTimeout(()=>setAgents(prev=>prev.map((a,j)=>({...a,status:j<i?"completed":j===i?"running":"queued"}))),i*620)); setTimeout(()=>{setAgents(initialAgents);setRunning(false);toast.success("Agent investigation completed in 5.85s");},initialAgents.length*620);};
 const value=useMemo(()=>({signedIn,enterWorkspace,mode,setMode,selectedEvent,selectEvent,stage,setStage,agents,running,runDetection,runPipeline,thresholds,setThresholds}),[signedIn,mode,selectedEvent,stage,agents,running,thresholds]);
 return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
}
export function useSentinel(){const value=useContext(AppContext); if(!value) throw new Error("useSentinel must be used within SentinelProvider"); return value;}
export { dataset };
