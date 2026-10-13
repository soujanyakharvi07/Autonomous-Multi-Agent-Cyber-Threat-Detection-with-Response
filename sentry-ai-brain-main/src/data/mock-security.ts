import type { AgentRun, DatasetSummary, Experiment, ModelEvaluation, RagDocument, RagResult, SecurityEvent, ServiceStatus } from "@/types/security";

export const events: SecurityEvent[] = [
 { id:"EVT-78124",alertId:"ALRT-1042",timestamp:"2026-10-03 07:31:18",sourceIp:"192.168.10.42",destinationIp:"10.0.0.18",protocol:"TCP",sourcePort:51844,destinationPort:22,prediction:"Brute Force",confidence:94.7,risk:"high",status:"Investigating" },
 { id:"EVT-78119",alertId:"ALRT-1041",timestamp:"2026-10-03 07:24:03",sourceIp:"10.10.4.71",destinationIp:"172.16.2.10",protocol:"TCP",sourcePort:49212,destinationPort:443,prediction:"Port Scan",confidence:86.2,risk:"medium",status:"New" },
 { id:"EVT-78102",alertId:"ALRT-1040",timestamp:"2026-10-03 07:09:47",sourceIp:"172.16.8.32",destinationIp:"10.0.0.24",protocol:"UDP",sourcePort:53120,destinationPort:80,prediction:"DDoS",confidence:91.3,risk:"high",status:"Investigating" },
 { id:"EVT-78088",alertId:"ALRT-1039",timestamp:"2026-10-03 06:52:11",sourceIp:"192.168.20.16",destinationIp:"10.0.0.31",protocol:"TCP",sourcePort:44107,destinationPort:8080,prediction:"Normal",confidence:63.4,risk:"low",status:"Reviewed" },
 { id:"EVT-78063",alertId:"ALRT-1038",timestamp:"2026-10-03 06:35:42",sourceIp:"10.20.5.23",destinationIp:"172.16.2.11",protocol:"TCP",sourcePort:57410,destinationPort:21,prediction:"Botnet",confidence:88.9,risk:"high",status:"New" },
 { id:"EVT-78042",timestamp:"2026-10-03 06:18:29",sourceIp:"192.168.11.82",destinationIp:"10.0.0.12",protocol:"TCP",sourcePort:60214,destinationPort:443,prediction:"Normal",confidence:98.1,risk:"low",status:"Reviewed" },
];
export const timeline = [
 {time:"00:00",events:2180,threats:91},{time:"04:00",events:1840,threats:76},{time:"08:00",events:3910,threats:218},{time:"12:00",events:4560,threats:262},{time:"16:00",events:5220,threats:319},{time:"20:00",events:4210,threats:231},{time:"24:00",events:2761,threats:87},
];
export const threatDistribution = [{name:"Normal",value:23397},{name:"DoS",value:381},{name:"DDoS",value:296},{name:"Brute Force",value:244},{name:"Port Scan",value:197},{name:"Botnet",value:101},{name:"Other",value:65}];
export const riskDistribution = [{name:"Low",value:781},{name:"Medium",value:360},{name:"High",value:143}];
export const evidence = [
 {label:"Failed connection attempts",strength:"High" as const,detail:"37 failed SSH sessions within 4 minutes"},
 {label:"Request frequency",strength:"High" as const,detail:"9.2× the host's recent baseline"},
 {label:"Repeated access attempts",strength:"High" as const,detail:"Single source targeted one authentication service"},
 {label:"Unusual timing",strength:"Medium" as const,detail:"Activity outside the destination host's normal window"},
];
export const agents: AgentRun[] = [
 {id:"orchestrator",name:"Orchestrator",status:"completed",duration:0,responsibility:"Coordinates evidence flow and agent handoffs.",input:"Selected security event",output:"Ordered investigation plan",evidence:["Event EVT-78124","Configured agent policy"]},
 {id:"detection",name:"Detection Agent",status:"completed",duration:1.24,responsibility:"Classifies the security event using the ML detector.",input:"Preprocessed network event",output:"Brute Force · 94.7% confidence",model:"Random Forest (demo)",evidence:["Flow duration","Failed sessions","Packet frequency"]},
 {id:"investigation",name:"Investigation Agent",status:"completed",duration:0.83,responsibility:"Examines source, destination, ports, timing and related events.",input:"Detection result + event neighborhood",output:"Repeated SSH authentication pattern",evidence:["37 attempts","Destination port 22","4-minute cluster"]},
 {id:"intelligence",name:"Threat Intelligence Agent",status:"completed",duration:1.12,responsibility:"Maps the event to relevant defensive techniques.",input:"Investigated behavior",output:"MITRE ATT&CK T1110 candidate mapping",evidence:["Technique mapping is demonstration content"]},
 {id:"rag",name:"RAG Agent",status:"completed",duration:0.67,responsibility:"Retrieves relevant defensive cybersecurity knowledge.",input:"Evidence-grounded search query",output:"3 passages retrieved",model:"Sentence Transformer + FAISS (simulated)",evidence:["brute_force.txt","incident_response.txt","authentication_controls.txt"]},
 {id:"response",name:"Response Agent",status:"completed",duration:0.91,responsibility:"Generates defensive response recommendations.",input:"Evidence + intelligence + risk",output:"Five advisory response steps",evidence:["No automated blocking","Analyst approval required"]},
 {id:"explanation",name:"Explanation Agent",status:"completed",duration:1.08,responsibility:"Produces human-readable evidence-based reasoning.",input:"Consolidated agent outputs",output:"Concise analyst explanation",model:"LLM (simulated)",evidence:["Detection evidence","Retrieved context","Risk score"]},
];
export const documents: RagDocument[] = [
 {name:"brute_force.txt",category:"Attack Techniques",chunks:18,indexed:true,lastIndexed:"2026-10-03 06:42",source:"Demo corpus"},
 {name:"ddos.txt",category:"Threat Detection",chunks:23,indexed:true,lastIndexed:"2026-10-03 06:42",source:"Demo corpus"},
 {name:"port_scan.txt",category:"Network Security",chunks:14,indexed:true,lastIndexed:"2026-10-03 06:42",source:"Demo corpus"},
 {name:"phishing.txt",category:"Attack Techniques",chunks:17,indexed:true,lastIndexed:"2026-10-02 18:20",source:"Demo corpus"},
 {name:"malware.txt",category:"Malware",chunks:31,indexed:true,lastIndexed:"2026-10-02 18:20",source:"Demo corpus"},
 {name:"incident_response.txt",category:"Incident Response",chunks:26,indexed:true,lastIndexed:"2026-10-03 06:42",source:"Demo corpus"},
 {name:"mitigation.txt",category:"Mitigation",chunks:20,indexed:true,lastIndexed:"2026-10-02 18:20",source:"Demo corpus"},
];
export const ragResults: RagResult[] = [
 {document:"brute_force.txt",score:.91,source:"Demo corpus",passage:"Repeated authentication failures from one source in a short interval may indicate password guessing. Confirm against identity and access logs before response."},
 {document:"incident_response.txt",score:.84,source:"Demo corpus",passage:"Preserve event evidence, validate scope, identify affected assets and escalate according to the organization's incident-response procedure."},
 {document:"authentication_controls.txt",score:.78,source:"Demo corpus",passage:"Review rate limits, multi-factor authentication coverage and account lockout policy with service owners."},
];
export const dataset: DatasetSummary = {name:"CICIDS2017",rows:24681,columns:79,normal:23397,malicious:1284,missing:12,duplicates:37,status:"Loaded · demo sample"};
export const evaluations: ModelEvaluation[] = [
 {name:"Traditional ML",accuracy:94.2,precision:92.8,recall:91.9,f1:92.3,processingTime:1.8,explanation:null,retrieval:null,response:null,placeholder:true},
 {name:"ML + LLM",accuracy:94.2,precision:92.8,recall:91.9,f1:92.3,processingTime:3.9,explanation:86,retrieval:null,response:82,placeholder:true},
 {name:"ML + LLM + RAG",accuracy:94.2,precision:92.8,recall:91.9,f1:92.3,processingTime:4.8,explanation:90,retrieval:88,response:88,placeholder:true},
 {name:"Multi-Agent + LLM + RAG",accuracy:96.8,precision:95.4,recall:94.9,f1:95.1,processingTime:5.85,explanation:93,retrieval:91,response:92,placeholder:true},
];
export const experiments: Experiment[] = [
 {id:"Experiment #0042",dataset:"CICIDS2017",model:"Random Forest",rag:true,agents:6,llm:"Demo adapter",date:"2026-10-03",version:"v0.8.2",status:"Completed"},
 {id:"Experiment #0041",dataset:"CICIDS2017",model:"Random Forest",rag:false,agents:4,llm:"Demo adapter",date:"2026-10-02",version:"v0.8.1",status:"Completed"},
 {id:"Experiment #0040",dataset:"CICIDS2017",model:"XGBoost",rag:true,agents:6,llm:"Demo adapter",date:"2026-10-01",version:"v0.8.0",status:"Completed"},
];
export const services: ServiceStatus[] = [
 {name:"Frontend",status:"Operational",detail:"Local application"},{name:"FastAPI Backend",status:"Demo",detail:"API adapter is using local fixtures",simulated:true},{name:"ML Model",status:"Demo",detail:"Random Forest output is simulated",simulated:true},{name:"RAG",status:"Demo",detail:"Retrieval results are simulated",simulated:true},{name:"FAISS",status:"Demo",detail:"Architecture prepared; no live index",simulated:true},{name:"LLM",status:"Demo",detail:"No external model is connected",simulated:true},{name:"Database",status:"Unavailable",detail:"No persistent store configured",simulated:true},
];
export const featureImportance = [{name:"Failed login rate",value:.91},{name:"Flow packets/s",value:.82},{name:"Destination port",value:.68},{name:"Flow duration",value:.57},{name:"SYN flag count",value:.46},{name:"Idle mean",value:.34}];
export const classPerformance = [{name:"Normal",precision:98,recall:97},{name:"DoS",precision:95,recall:94},{name:"DDoS",precision:96,recall:95},{name:"Brute Force",precision:93,recall:92},{name:"Port Scan",precision:94,recall:91},{name:"Botnet",precision:89,recall:87}];
