import { createFileRoute } from "@tanstack/react-router";
import { IntelligencePage } from "@/pages/research-pages";

export const Route = createFileRoute("/intelligence")({
  head: () => ({ meta: [
    { title: "Threat Intelligence — SENTINEL-X" },
    { name: "description", content: "Map detected behavior to clearly sourced defensive cybersecurity knowledge." },
    { property: "og:title", content: "Threat Intelligence — SENTINEL-X" },
    { property: "og:description", content: "Map detected behavior to clearly sourced defensive cybersecurity knowledge." },
    { property: "og:type", content: "website" },
    { name: "twitter:card", content: "summary_large_image" },
  ] }),
  component: IntelligencePage,
});
