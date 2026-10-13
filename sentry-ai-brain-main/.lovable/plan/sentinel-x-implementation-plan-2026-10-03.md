# SENTINEL-X implementation plan

## Product direction
Build a dense, dark, research-grade SOC workspace—not a marketing site. The interface will use restrained cyan/blue accents, compact data surfaces, subtle borders, square-to-small-radius controls, security-state colors, accessible contrast, and responsive desktop/tablet/mobile layouts.

## Application shell and navigation
- Replace the placeholder with a demo sign-in screen and a persistent authenticated shell.
- Add a collapsible desktop/mobile sidebar, compact operational top bar, DEMO/CONNECTED selector, model/RAG status, timestamp, notifications, and user menu.
- Create dedicated routes for Overview, Threat Detection, Investigation, Agent Pipeline, Threat Intelligence, Knowledge Base, Risk & Response, Reports, Dataset & Upload, Model Evaluation, System Status, and Settings.
- Add unique page metadata for every route.

## Demo data and architecture
- Define strict TypeScript models for events, alerts, agents, intelligence, RAG documents/results, risk assessments, datasets, evaluations, experiments, reports, and system status.
- Add a centralized mock dataset using private IP addresses and clearly marked simulated values.
- Add a clean API service abstraction matching the requested future endpoints, with demo and connected adapters. Connected mode will report unavailable until an endpoint is configured; it will never imply a live model when none exists.
- Keep shared state for selected event, dataset progress, pipeline execution, thresholds, and generated reports in a focused application provider.

## Core end-to-end flow
- Implement upload/selection of a CICIDS2017 CSV, simulated validation and preprocessing, detection execution, results browsing, event selection, investigation, staged multi-agent execution, intelligence and RAG evidence review, explainable assessment, risk derivation, recommendations, and report generation.
- Keep every automated response advisory-only and include the defensive research scope note.
- Add restrained progress feedback and only animate agent links while analysis is running.

## Screens and reusable UI
- Build reusable metrics, badges, status indicators, charts, data tables/mobile cards, evidence views, upload zone, pipeline nodes, agent detail drawer, RAG inspection, risk scoring, report viewer, confusion matrix, loading/empty/error states, dialogs, and toasts.
- Populate all requested pages with realistic demo content and explicit DEMO / PLACEHOLDER labeling where scientific or model output is simulated.
- Add export-ready JSON and print/PDF report layouts; browser print will produce the dedicated report layout rather than the dashboard.

## Verification
- Check the complete journey in the live preview at desktop and mobile widths.
- Verify navigation, responsive tables/cards, upload flow, pipeline updates, drawers, risk controls, report generation/export, and demo/connected labeling.
- Resolve build/runtime/console errors and add focused tests for routing and the core demo state flow.

## Technical notes
- Use the existing TanStack Start routing foundation with React 19, TypeScript, Tailwind CSS v4, shadcn components, Recharts, and Lucide.
- Keep design tokens in `src/styles.css`, API contracts separate from UI, and route files thin by composing feature components.
- Record the chosen frontend architecture in `AGENTS.md` and maintain a concise implementation roadmap while building.
