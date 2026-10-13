import { createFileRoute } from "@tanstack/react-router";
import { EvaluationPage } from "@/pages/research-pages";

export const Route = createFileRoute("/evaluation")({
  head: () => ({ meta: [
    { title: "Model Evaluation — SENTINEL-X" },
    { name: "description", content: "Compare clearly marked experimental model, retrieval and multi-agent evaluation metrics." },
    { property: "og:title", content: "Model Evaluation — SENTINEL-X" },
    { property: "og:description", content: "Compare clearly marked experimental model, retrieval and multi-agent evaluation metrics." },
    { property: "og:type", content: "website" },
    { name: "twitter:card", content: "summary_large_image" },
  ] }),
  component: EvaluationPage,
});
