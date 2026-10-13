import { createFileRoute } from "@tanstack/react-router";
import { SystemStatusPage } from "@/pages/research-pages";

export const Route = createFileRoute("/system-status")({
  head: () => ({ meta: [
    { title: "System Status — SENTINEL-X" },
    { name: "description", content: "Inspect live, simulated and unavailable SENTINEL-X service states." },
    { property: "og:title", content: "System Status — SENTINEL-X" },
    { property: "og:description", content: "Inspect live, simulated and unavailable SENTINEL-X service states." },
    { property: "og:type", content: "website" },
    { name: "twitter:card", content: "summary_large_image" },
  ] }),
  component: SystemStatusPage,
});
