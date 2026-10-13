import { createFileRoute } from "@tanstack/react-router";
import { OverviewPage } from "@/pages/overview-page";

export const Route = createFileRoute("/")({
  head: () => ({ meta: [
    { title: "Security Operations Overview — SENTINEL-X" },
    { name: "description", content: "Monitor detected threats, agent activity, model-assisted analysis and recent security alerts." },
    { property: "og:title", content: "Security Operations Overview — SENTINEL-X" },
    { property: "og:description", content: "Monitor detected threats, agent activity, model-assisted analysis and recent security alerts." },
    { property: "og:type", content: "website" },
    { name: "twitter:card", content: "summary_large_image" },
  ] }),
  component: OverviewPage,
});
