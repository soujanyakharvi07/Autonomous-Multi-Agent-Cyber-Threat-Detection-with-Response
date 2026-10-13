import { createFileRoute } from "@tanstack/react-router";
import { DatasetPage } from "@/pages/research-pages";

export const Route = createFileRoute("/datasets")({
  head: () => ({ meta: [
    { title: "Dataset & Upload — SENTINEL-X" },
    { name: "description", content: "Manage CICIDS2017 research data, validation, preprocessing and exploratory analysis." },
    { property: "og:title", content: "Dataset & Upload — SENTINEL-X" },
    { property: "og:description", content: "Manage CICIDS2017 research data, validation, preprocessing and exploratory analysis." },
    { property: "og:type", content: "website" },
    { name: "twitter:card", content: "summary_large_image" },
  ] }),
  component: DatasetPage,
});
