import { createFileRoute } from "@tanstack/react-router";
import { LivePage } from "@/pages/live-page";

export const Route = createFileRoute("/live")({
  head: () => ({ meta: [
    { title: "Live Analysis — SENTINEL-X" },
    { name: "description", content: "Real detection, multi-agent investigation, explanation and approval-gated response." },
    { property: "og:title", content: "Live Analysis — SENTINEL-X" },
    { property: "og:type", content: "website" },
  ] }),
  component: LivePage,
});
