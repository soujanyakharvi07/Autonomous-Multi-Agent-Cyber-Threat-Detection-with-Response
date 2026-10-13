import { createFileRoute } from "@tanstack/react-router";
import { RiskResponsePage } from "@/pages/research-pages";

export const Route = createFileRoute("/risk-response")({
  head: () => ({ meta: [
    { title: "Risk & Response — SENTINEL-X" },
    { name: "description", content: "Review transparent risk derivation and analyst-approved defensive response recommendations." },
    { property: "og:title", content: "Risk & Response — SENTINEL-X" },
    { property: "og:description", content: "Review transparent risk derivation and analyst-approved defensive response recommendations." },
    { property: "og:type", content: "website" },
    { name: "twitter:card", content: "summary_large_image" },
  ] }),
  component: RiskResponsePage,
});
