import { createFileRoute } from "@tanstack/react-router";
import { KnowledgePage } from "@/pages/research-pages";

export const Route = createFileRoute("/knowledge")({
  head: () => ({ meta: [
    { title: "Cybersecurity Knowledge Base — SENTINEL-X" },
    { name: "description", content: "Inspect cybersecurity documents, retrieval scores and evidence context for explainable analysis." },
    { property: "og:title", content: "Cybersecurity Knowledge Base — SENTINEL-X" },
    { property: "og:description", content: "Inspect cybersecurity documents, retrieval scores and evidence context for explainable analysis." },
    { property: "og:type", content: "website" },
    { name: "twitter:card", content: "summary_large_image" },
  ] }),
  component: KnowledgePage,
});
