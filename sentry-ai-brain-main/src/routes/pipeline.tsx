import { createFileRoute } from "@tanstack/react-router";
import { PipelinePage } from "@/pages/pipeline-page";

export const Route = createFileRoute("/pipeline")({
  head: () => ({ meta: [
    { title: "Multi-Agent Pipeline — SENTINEL-X" },
    { name: "description", content: "Trace the orchestrated detection, investigation, intelligence, retrieval, response and explanation agents." },
    { property: "og:title", content: "Multi-Agent Pipeline — SENTINEL-X" },
    { property: "og:description", content: "Trace the orchestrated detection, investigation, intelligence, retrieval, response and explanation agents." },
    { property: "og:type", content: "website" },
    { name: "twitter:card", content: "summary_large_image" },
  ] }),
  component: PipelinePage,
});
