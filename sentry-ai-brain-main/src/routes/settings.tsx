import { createFileRoute } from "@tanstack/react-router";
import { SettingsPage } from "@/pages/research-pages";

export const Route = createFileRoute("/settings")({
  head: () => ({ meta: [
    { title: "System Settings — SENTINEL-X" },
    { name: "description", content: "Configure prototype risk thresholds and research environment parameters." },
    { property: "og:title", content: "System Settings — SENTINEL-X" },
    { property: "og:description", content: "Configure prototype risk thresholds and research environment parameters." },
    { property: "og:type", content: "website" },
    { name: "twitter:card", content: "summary_large_image" },
  ] }),
  component: SettingsPage,
});
