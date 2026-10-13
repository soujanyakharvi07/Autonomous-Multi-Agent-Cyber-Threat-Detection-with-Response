import { createFileRoute } from "@tanstack/react-router";
import { InvestigationPage } from "@/pages/investigation-page";

export const Route = createFileRoute("/investigation")({
  head: () => ({ meta: [
    { title: "Event Investigation — SENTINEL-X" },
    { name: "description", content: "Inspect event evidence, classification factors and defensive investigation context." },
    { property: "og:title", content: "Event Investigation — SENTINEL-X" },
    { property: "og:description", content: "Inspect event evidence, classification factors and defensive investigation context." },
    { property: "og:type", content: "website" },
    { name: "twitter:card", content: "summary_large_image" },
  ] }),
  component: InvestigationPage,
});
