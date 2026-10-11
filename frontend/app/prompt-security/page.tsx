"use client";

import { AnalysisForm, useAnalysis } from "@/components/sentivra/analysis-result";
import { PageHeader } from "@/components/sentivra/states";
import { api } from "@/lib/api";

export default function PromptSecurityPage() {
  const { result, error, busy, run } = useAnalysis();

  return (
    <>
      <PageHeader
        title="Prompt Security"
        description="Prompt-injection, jailbreak and system-prompt-extraction detection for text headed to an LLM."
      />
      <AnalysisForm label="Analyze prompt" placeholder="Paste a prompt to check for injection, jailbreak, or extraction signals…" onSubmit={(value) => run("prompt", () => api.analyzePrompt(value))} result={result} error={error} busy={busy !== null} />
    </>
  );
}
