import { createFileRoute } from "@tanstack/react-router";
import { DetectionPage } from "@/pages/detection-page";

export const Route = createFileRoute("/detection")({
  head: () => ({ meta: [
    { title: "Threat Detection — SENTINEL-X" },
    { name: "description", content: "Validate CICIDS2017 security logs and review transparent demo classification results." },
    { property: "og:title", content: "Threat Detection — SENTINEL-X" },
    { property: "og:description", content: "Validate CICIDS2017 security logs and review transparent demo classification results." },
    { property: "og:type", content: "website" },
    { name: "twitter:card", content: "summary_large_image" },
  ] }),
  component: DetectionPage,
});
