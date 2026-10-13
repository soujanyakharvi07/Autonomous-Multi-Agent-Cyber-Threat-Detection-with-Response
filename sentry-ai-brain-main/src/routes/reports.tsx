import { createFileRoute } from "@tanstack/react-router";
import { ReportsPage } from "@/pages/research-pages";

export const Route = createFileRoute("/reports")({
  head: () => ({ meta: [
    { title: "Security Reports — SENTINEL-X" },
    { name: "description", content: "Review and export evidence-based security analysis reports." },
    { property: "og:title", content: "Security Reports — SENTINEL-X" },
    { property: "og:description", content: "Review and export evidence-based security analysis reports." },
    { property: "og:type", content: "website" },
    { name: "twitter:card", content: "summary_large_image" },
  ] }),
  component: ReportsPage,
});
