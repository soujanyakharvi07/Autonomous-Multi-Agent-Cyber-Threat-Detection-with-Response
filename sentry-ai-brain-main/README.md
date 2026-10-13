# Sentinel Analytics

Build a complete, polished, production-quality web application called:

SENTINEL-X

Autonomous Multi-Agent Cyber Threat Detection & Response

This is an academic/research-grade cybersecurity platform based on an autonomous multi-agent LLM framework for explainable and adaptive cyber threat detection and response.

IMPORTANT:

This must NOT look like a generic AI-generated “vibe coded” dashboard.

The interface should look like a real cybersecurity research/SOC analysis product designed by an experienced product designer and security engineer.

Do not use excessive gradients, giant glowing cards, random neon effects, unnecessary animations, fake metrics, or generic AI-dashboard layouts.

Use a sophisticated dark cybersecurity interface with excellent spacing, typography, hierarchy, subtle borders, restrained accent colors, professional charts, realistic security terminology, and consistent component design.

The product should feel closer to a professional security operations/research platform than a startup landing page.

---

1. CORE PROJECT PURPOSE

The application represents this workflow:

Security Logs / CICIDS2017 Dataset

→ Data Preprocessing

→ Machine Learning Threat Detection

→ Multi-Agent Orchestrator

→ Detection Agent

→ Investigation Agent

→ Threat Intelligence / RAG Agent

→ LLM Reasoning

→ Response Agent

→ Explanation Agent

→ Risk Assessment

→ Security Report / Dashboard

The system must clearly separate:

1. Detection

2. Investigation

3. Threat intelligence

4. Retrieval

5. LLM reasoning

6. Explanation

7. Risk assessment

8. Response recommendation

The project is a defensive cybersecurity research prototype.

DO NOT implement real-world offensive actions, automatic blocking, exploitation, malware execution, or attacks against external systems.

All response recommendations must be presented as recommendations only.

---

2. TECHNOLOGY / ARCHITECTURE

Build the frontend with:

- React

- TypeScript

- Vite

- Tailwind CSS

- shadcn/ui

- Recharts or another professional charting library

- Lucide icons

Backend/API architecture should be prepared so it can connect to:

- Python

- FastAPI

- Scikit-learn

- Random Forest

- Optional XGBoost

- LangGraph

- LangChain or LlamaIndex

- Sentence Transformers

- FAISS

- PostgreSQL or SQLite

If a real backend/model cannot be executed inside the generated environment, create a clean API abstraction layer and realistic demo data.

Do NOT pretend that an actual ML model or LLM is running if it is not.

Clearly distinguish:

- Demo / simulated analysis

- Connected model analysis

The UI should be ready for the real Python backend to be connected later.

---

3. BRANDING

Product name:

SENTINEL-X

Subtitle:

Autonomous Multi-Agent Cyber Threat Detection & Response

Use a minimal security-oriented logo:

- abstract shield

- subtle network-node motif

- no cliché hacker imagery

- no skulls

- no hooded hacker graphics

Logo should work in the sidebar and login screen.

Use typography similar to modern enterprise security software.

Suggested visual language:

Background:

- very dark navy/charcoal

Primary text:

- near-white

Secondary text:

- cool gray

Accent:

- restrained cyan/blue

Risk colors:

- Low = muted green

- Medium = amber

- High = red

Do not make every element glow.

---

4. APPLICATION STRUCTURE

Create these major pages:

1. Overview

2. Threat Detection

3. Event Investigation

4. Multi-Agent Pipeline

5. Threat Intelligence

6. RAG Knowledge Base

7. Risk & Response

8. Security Reports

9. Dataset / Upload

10. Model Evaluation

11. System Settings

Use a persistent left sidebar on desktop.

Sidebar:

SENTINEL-X logo

Overview

Threat Detection

Investigation

Agent Pipeline

Threat Intelligence

Knowledge Base

Risk & Response

Reports

Dataset & Upload

Model Evaluation

Bottom:

System Status

Settings

User Profile

Include a compact top bar containing:

- Current environment: DEMO / CONNECTED

- Model status

- RAG status

- Last analysis timestamp

- Notifications

- User menu

---

5. OVERVIEW DASHBOARD

Create a serious SOC/research dashboard.

Header:

Security Operations Overview

Subtitle:

Real-time visibility into detected threats, agent activity and model-assisted analysis.

Top metric cards:

Total Events Analyzed

Threats Detected

High-Risk Events

Detection Accuracy

RAG Retrievals

Agent Runs

Do NOT use fake-looking huge numbers such as “9,999,999”.

Use realistic demo values.

Example:

Events Analyzed

24,681

Threats Detected

1,284

High Risk

143

Detection Accuracy

96.8%

RAG Queries

1,087

Agent Runs

3,421

Charts:

A. Threat Activity Timeline

Line/area chart showing events and detected threats over time.

B. Threat Distribution

Donut chart:

Normal

DoS

DDoS

Brute Force

Port Scan

Botnet

Other

C. Risk Distribution

Low

Medium

High

D. Recent Security Alerts

Table:

Timestamp

Source IP

Destination

Threat

Confidence

Risk

Status

Actions

Use realistic private IP addresses only.

Example:

192.168.10.42

10.0.0.18

Never use real people's IP addresses.

---

6. THREAT DETECTION PAGE

Title:

Threat Detection

Provide:

Upload CSV / security log button

Supported format:

CSV

Primary dataset:

CICIDS2017

Show dataset information panel:

Dataset:

CICIDS2017

Purpose:

Network intrusion detection

Supported examples:

DoS

DDoS

Brute Force

Port Scan

Botnet

Web Attacks

After upload show:

Dataset Summary

Rows

Columns

Normal Events

Malicious Events

Missing Values

Duplicate Rows

Then provide:

Run Detection

Processing pipeline:

Uploaded

→ Validated

→ Preprocessed

→ Feature Extraction

→ ML Classification

→ Results Ready

Create a professional progress visualization.

---

7. DETECTION RESULTS

Show a large results table.

Columns:

Event ID

Timestamp

Source IP

Destination IP

Protocol

Source Port

Destination Port

Prediction

Confidence

Risk

Status

Prediction examples:

Normal

DoS

DDoS

Brute Force

Port Scan

Botnet

Confidence should be shown as a percentage and progress indicator.

Clicking an event should open a detailed investigation drawer/page.

---

8. EVENT INVESTIGATION PAGE

This is one of the most important screens.

Title:

Event Investigation

Header summary:

Threat:

Possible Brute-Force Attack

Risk:

HIGH

Confidence:

94.7%

Status:

Under Investigation

Create sections:

Event Evidence

Source IP

Destination IP

Source Port

Destination Port

Protocol

Timestamp

Event Frequency

Detection Evidence

Show the features that influenced the classification.

Example:

Failed connection attempts

+ High

Request frequency

+ High

Repeated access attempts

+ High

Unusual timing

+ Medium

Present this professionally.

Do NOT claim the ML model uses a specific feature unless demo data explicitly represents it.

---

9. MULTI-AGENT PIPELINE

Create a visually impressive but professional agent workflow screen.

Title:

Multi-Agent Investigation Pipeline

Display these nodes horizontally or vertically:

1. Orchestrator

2. Detection Agent

3. Investigation Agent

4. Threat Intelligence Agent

5. RAG Agent

6. Response Agent

7. Explanation Agent

Each node should show:

Agent name

Status

Execution time

Short responsibility

Example:

Detection Agent

Completed

1.24s

“Classifies the security event using the ML detector.”

Investigation Agent

Completed

0.83s

“Examines source, destination, ports, timing and related events.”

Threat Intelligence Agent

Completed

1.12s

“Maps the event to relevant cybersecurity techniques.”

RAG Agent

Completed

0.67s

“Retrieves relevant defensive cybersecurity knowledge.”

Response Agent

Completed

0.91s

“Generates defensive response recommendations.”

Explanation Agent

Completed

1.08s

“Produces human-readable evidence-based reasoning.”

Orchestrator should visually connect all agents.

Use subtle animated connection indicators ONLY while an analysis is running.

Do not over-animate the interface.

---

10. AGENT DETAIL DRAWER

Clicking an agent opens detailed information.

Show:

Agent

Purpose

Input

Output

Status

Execution Time

Evidence Used

Example:

Detection Agent

Input:

Preprocessed network event

Output:

Threat category + confidence

Model:

Random Forest

Status:

Completed

Keep technical information visible but understandable.

---

11. THREAT INTELLIGENCE PAGE

Title:

Threat Intelligence

Create a threat mapping interface.

Show:

Detected Threat

Possible Brute-Force Attack

Relevant technique:

MITRE ATT&CK

Technique:

Brute Force

Include technique ID if available in the connected knowledge source.

Show:

Technique Description

Observed Evidence

Relevant Mitigations

Source

Sources should be clearly labeled.

Use source badges:

MITRE ATT&CK

NIST

CISA

Do not invent citations.

For demo mode, clearly label information as demonstration content.

Provide an “Open Source” action.

---

12. RAG KNOWLEDGE BASE

Title:

Cybersecurity Knowledge Base

Create a document-management style interface.

Categories:

Attack Techniques

Threat Detection

Incident Response

Mitigation

Authentication

Network Security

Malware

General Security

Example documents:

brute_force.txt

ddos.txt

port_scan.txt

phishing.txt

malware.txt

incident_response.txt

mitigation.txt

Include:

Document name

Category

Chunks

Embedding status

Last indexed

Source

Buttons:

Upload Document

Re-index Knowledge Base

Search Knowledge Base

Search interface:

“Search cybersecurity knowledge…”

Search results should show:

Document

Relevant passage

Similarity score

Source

The PDF specifies FAISS + embeddings for the RAG layer, so the UI should expose this architecture without pretending a real vector database is connected unless it actually is.

---

13. RAG QUERY INSPECTION

Create a detailed RAG inspection panel.

Show:

User/Event Query

Retrieved Documents

Similarity Scores

Context Sent to LLM

This is important for research explainability.

Example:

Query:

“Repeated SSH login failures from a single source within a short period.”

Retrieved:

brute_force.txt — 0.91

incident_response.txt — 0.84

authentication_controls.txt — 0.78

Then:

LLM Context

Display a readable evidence/context section.

---

14. EXPLAINABLE AI SECTION

Title:

Explainable Analysis

Use the example structure from the project plan:

Threat:

Possible Brute-Force Attack

Risk:

High

Why detected:

A large number of failed SSH login attempts occurred within a short period.

Evidence:

- High failed-login frequency

- Unusual timing

- Repeated access attempts

RAG knowledge:

Relevant attack technique and mitigation information retrieved from the cybersecurity knowledge base.

Recommended response:

Investigate the source, apply appropriate authentication controls, monitor subsequent attempts and follow the organization's incident-response procedure.

Important:

Label generated content clearly:

“LLM-generated explanation based on detected evidence and retrieved cybersecurity context.”

Do not present LLM reasoning as hidden chain-of-thought.

Only show concise evidence and explanation.

---

15. RISK & RESPONSE PAGE

Title:

Risk Assessment & Response

Use three levels:

LOW

MEDIUM

HIGH

Explain:

LOW:

Weak or low-confidence suspicious activity

Recommendation:

Monitor and record the event.

MEDIUM:

More evidence of malicious activity

Recommendation:

Generate alert and increase monitoring.

HIGH:

Strong evidence or potentially high-impact activity

Recommendation:

Recommend containment actions, investigation and escalation.

Important:

Display a disclaimer:

“Risk thresholds are configurable project parameters and are not universal cybersecurity standards.”

Create a risk scoring visualization.

Inputs can include:

Threat probability

Threat severity

Event frequency

Asset importance

Show how the final risk level was derived.

---

16. RESPONSE RECOMMENDATION

For each alert show:

Recommended Actions

Example:

1. Investigate source activity

2. Review authentication logs

3. Apply appropriate authentication controls

4. Increase monitoring

5. Follow organizational incident-response procedures

Add:

Why these actions?

Based on:

- Detection evidence

- Threat intelligence

- Retrieved knowledge

- Risk level

Never provide instructions for attacking another system.

---

17. SECURITY REPORT PAGE

Create a professional report viewer.

Title:

Security Analysis Report

Sections:

Executive Summary

Detected Threat

Risk Assessment

Event Evidence

ML Classification

Agent Investigation

Threat Intelligence

RAG Evidence

Explanation

Recommended Response

System Metadata

Buttons:

Export PDF

Export JSON

Print Report

The PDF export should have a professional report layout rather than simply printing the dashboard.

---

18. DATASET / UPLOAD PAGE

Create a research-oriented dataset management interface.

Show:

Current Dataset

CICIDS2017

Dataset Status

Loaded / Not Loaded

Rows

Features

Labels

Actions:

Upload Dataset

Validate Dataset

Preprocess Dataset

Run Analysis

Include an EDA section:

Class Distribution

Missing Values

Duplicate Rows

Feature Statistics

Charts should be clean and research-paper appropriate.

---

19. MODEL EVALUATION PAGE

This page is critical because the project is also a research project.

Title:

Model Evaluation

Show comparison:

Traditional ML

ML + LLM

ML + LLM + RAG

Multi-Agent + LLM + RAG

Metrics:

Accuracy

Precision

Recall

F1 Score

Processing Time

Explanation Relevance

Retrieval Relevance

Response Quality

Do NOT fabricate scientific results.

Use clearly marked DEMO / PLACEHOLDER values until actual experiments are connected.

Include:

Confusion Matrix

Class-wise Performance

ROC curve if supported by actual model output.

Feature Importance

For Random Forest:

Show a horizontal bar chart of feature importance using demo values only when the application is in demo mode.

---

20. RESEARCH EXPERIMENT TRACKING

Add a section:

Experiment Configuration

Dataset

Model

RAG

Agents

LLM

Date

Version

Example:

Experiment #0042

Dataset:

CICIDS2017

Model:

Random Forest

RAG:

Enabled

Agents:

6

Status:

Completed

This makes the application look like a genuine research system rather than a normal website.

---

21. SYSTEM STATUS

Create a compact status page.

Services:

Frontend

● Operational

FastAPI Backend

● Connected

ML Model

● Loaded

RAG

● Indexed

FAISS

● Ready

LLM

● Connected / Demo Mode

Database

● Connected

Clearly distinguish simulated services from actual services.

---

22. SETTINGS

Settings categories:

General

Model

RAG

Risk Thresholds

Data

API

Security

Risk thresholds should be configurable.

Example:

Low:

0–39

Medium:

40–69

High:

70–100

These are prototype defaults and should be clearly labeled as configurable project parameters.

---

23. DEMO MODE

The application MUST work immediately after generation without requiring external API keys.

Create a realistic DEMO MODE.

Use a local mock service/data layer containing:

- security events

- alerts

- agent execution records

- threat intelligence results

- RAG documents

- model metrics

- reports

The UI should feel fully functional in demo mode.

Add a visible badge:

DEMO MODE

Do not fake a real AI connection.

Allow switching between:

DEMO

CONNECTED

CONNECTED mode should use environment variables/API endpoints when available.

---

24. REAL DATA FLOW ARCHITECTURE

Prepare frontend API services such as:

/api/events

/api/detection

/api/investigation

/api/agents

/api/threat-intelligence

/api/rag/search

/api/risk

/api/reports

/api/datasets

/api/evaluation

/api/system/status

Create TypeScript interfaces for all API responses.

Keep API calls separated from UI components.

Do NOT put all application logic inside App.tsx.

Use a clean folder structure:

src/

components/

pages/

layouts/

services/

api/

hooks/

types/

data/

lib/

utils/

---

25. COMPONENT QUALITY

Create reusable components:

MetricCard

ThreatBadge

RiskBadge

AgentNode

AgentPipeline

SecurityEventTable

EventDetailDrawer

EvidencePanel

ThreatTimeline

ThreatDistributionChart

RiskDistributionChart

RAGResultCard

KnowledgeDocumentCard

ModelMetricCard

ConfusionMatrix

StatusIndicator

SecurityReport

UploadZone

EmptyState

LoadingState

ErrorState

Toast

Modal

Drawer

Every component should have consistent spacing and typography.

---

26. UX REQUIREMENTS

The UI must be responsive.

Desktop:

Professional enterprise dashboard.

Tablet:

Two-column adaptive layout.

Mobile:

Collapsible sidebar and stacked cards.

Tables must become usable mobile cards.

Avoid horizontal scrolling whenever possible.

Provide:

Loading states

Skeletons

Empty states

Error states

Success states

Do not use browser alert().

Use proper dialogs/toasts.

---

27. VISUAL DESIGN RULES

Absolutely avoid:

- excessive gradients

- excessive glassmorphism

- huge glowing borders

- random purple AI gradients

- generic “AI magic” icons

- excessive rounded cards

- cartoon cybersecurity imagery

- stock hacker photographs

- unnecessary 3D graphics

- excessive animations

- fake futuristic terminology

Instead use:

- subtle 1px borders

- restrained shadows

- compact cards

- clean tables

- clear information hierarchy

- professional typography

- consistent spacing

- subtle hover states

- meaningful icons

- restrained cyan/blue accents

- red/amber/green only for security state

The visual style should resemble a professional security analytics platform.

---

28. LANDING / LOGIN SCREEN

Create a professional login screen.

Dark background.

Left side:

SENTINEL-X

Autonomous Multi-Agent Cyber Threat Detection & Response

Small architecture visualization:

ML Detection

↓

Agent Orchestration

↓

Threat Intelligence

↓

RAG

↓

Explainable Response

Right side:

Sign In

Email

Password

Sign In button

Demo Mode button

Do not use social login unless actually implemented.

---

29. ASSETS

Create/use all required assets locally where possible.

Required assets:

1. SENTINEL-X logo

2. Minimal shield/network logo

3. Empty-state cybersecurity illustration

4. Dataset upload illustration

5. Report icon

6. Threat detection icon

7. Investigation icon

8. Threat intelligence icon

9. Knowledge base icon

10. Risk icon

11. Agent orchestration icon

Prefer SVG icons and CSS-based visuals over random external images.

Do NOT use copyrighted stock images unnecessarily.

The product should still look complete if there is no internet connection.

---

30. MOCK DATA

Create realistic demo data.

Threat types:

Normal

DoS

DDoS

Brute Force

Port Scan

Botnet

Example alerts:

ALRT-1042

Possible Brute-Force Attack

High

94.7%

ALRT-1041

Port Scan Activity

Medium

86.2%

ALRT-1040

Possible DDoS Pattern

High

91.3%

ALRT-1039

Unusual Network Activity

Low

63.4%

Use realistic timestamps.

Use private IP addresses.

Do not use real personal data.

---

31. AGENT EXECUTION EXAMPLE

Create demo execution:

Orchestrator

Completed

Detection Agent

Completed

1.24s

Investigation Agent

Completed

0.83s

Threat Intelligence Agent

Completed

1.12s

RAG Agent

Completed

0.67s

Response Agent

Completed

0.91s

Explanation Agent

Completed

1.08s

Total:

5.85s

Make the pipeline visually update when “Run Analysis” is clicked.

---

32. MAIN DEMO FLOW

The most important user journey should be:

Dashboard

→ Upload CICIDS2017 CSV

→ Dataset Validation

→ Preprocessing

→ Run Threat Detection

→ Detection Results

→ Select Threat

→ Start Investigation

→ Watch Multi-Agent Pipeline

→ View Threat Intelligence

→ View RAG Evidence

→ View Explanation

→ View Risk

→ View Recommended Response

→ Generate Security Report

This flow must work end-to-end in DEMO MODE.

---

33. SECURITY / ETHICS

Include an About / Scope note:

“This project is a defensive cybersecurity research prototype. It analyzes security events and provides evidence-based recommendations. It does not perform attacks, exploit external systems, automatically block hosts, or analyze unauthorized private traffic.”

---

34. CODE QUALITY

Very important:

Do not generate one giant App.tsx.

Do not duplicate components.

Do not hard-code repeated UI.

Use reusable components.

Use proper TypeScript types.

Use clean naming.

Use meaningful comments only where necessary.

Keep mock data in separate files.

Keep API functions in sepa

This project was built with [Lovable](https://lovable.dev).

## Build with Lovable

Continue developing this project in the [Lovable editor](https://lovable.dev/projects/a67c2f7c-40ec-54ca-8612-179d36610dc6).

- **Ship faster**: describe what you want to build and Lovable handles the code.
- **Stay in sync**: every change made in Lovable is committed straight to this repository.
- **Full ownership**: this code is yours. Push to `main` on GitHub and your changes sync back into Lovable, ready for your next prompt.

## Development

Prefer working locally? You need Node.js and npm — [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating).

```sh
git clone <this-repository-url>
cd <repository-name>
npm i
npm run dev
```
