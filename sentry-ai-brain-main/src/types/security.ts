export type RiskLevel = "low" | "medium" | "high";
export type ThreatType = "Normal" | "DoS" | "DDoS" | "Brute Force" | "Port Scan" | "Botnet";
export type AnalysisMode = "demo" | "connected";
export type RunStatus = "queued" | "running" | "completed";

export interface SecurityEvent {
  id: string; timestamp: string; sourceIp: string; destinationIp: string; protocol: string;
  sourcePort: number; destinationPort: number; prediction: ThreatType; confidence: number;
  risk: RiskLevel; status: "New" | "Investigating" | "Reviewed"; alertId?: string;
}
export interface AgentRun { id: string; name: string; responsibility: string; duration: number; status: RunStatus; input: string; output: string; evidence: string[]; model?: string; }
export interface Evidence { label: string; strength: "High" | "Medium" | "Low"; detail: string; }
export interface RagDocument { name: string; category: string; chunks: number; indexed: boolean; lastIndexed: string; source: string; }
export interface RagResult { document: string; score: number; passage: string; source: string; }
export interface ServiceStatus { name: string; status: "Operational" | "Ready" | "Loaded" | "Connected" | "Demo" | "Unavailable"; detail: string; simulated?: boolean; }
export interface ModelEvaluation { name: string; accuracy: number; precision: number; recall: number; f1: number; processingTime: number; explanation: number | null; retrieval: number | null; response: number | null; placeholder: boolean; }
export interface Experiment { id: string; dataset: string; model: string; rag: boolean; agents: number; llm: string; date: string; version: string; status: string; }
export interface DatasetSummary { name: string; rows: number; columns: number; normal: number; malicious: number; missing: number; duplicates: number; status: string; }
