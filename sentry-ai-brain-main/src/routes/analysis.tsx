import { createFileRoute } from "@tanstack/react-router";
import { AnalysisPage } from "@/pages/analysis-page";

export const Route = createFileRoute("/analysis")({
  head: () => ({ meta: [
    { title: "Log Analysis — SENTINEL-X" },
    { name: "description", content: "Upload security logs and run the multi-agent analysis." },
    { property: "og:title", content: "Log Analysis — SENTINEL-X" },
    { property: "og:type", content: "website" },
  ] }),
  component: AnalysisPage,
});
