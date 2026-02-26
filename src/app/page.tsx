"use client";

import { useState, useCallback } from "react";
import { useIsAuthenticated, useMsal } from "@azure/msal-react";
import { loadTenantContext, TenantContext } from "@/lib/graph-client";
import { analyzeAllPolicies, AnalysisResult } from "@/lib/analyzer";
import { analyzeTemplates, TemplateAnalysisResult } from "@/lib/template-matcher";
import { runCISAlignment, CISAlignmentResult } from "@/data/cis-benchmarks";
import { Dashboard } from "@/components/dashboard";
import { PolicyList } from "@/components/policy-list";
import { FindingsList } from "@/components/findings-list";
import { TemplatesView } from "@/components/templates-view";
import { CISView } from "@/components/cis-view";
import { Shield, Loader2, Play, Download, RefreshCw } from "lucide-react";
import { cn } from "@/lib/utils";

type ViewTab = "dashboard" | "policies" | "findings" | "templates" | "cis";

export default function Home() {
  const isAuthenticated = useIsAuthenticated();
  const { instance, accounts } = useMsal();

  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState("");
  const [context, setContext] = useState<TenantContext | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [templateResult, setTemplateResult] = useState<TemplateAnalysisResult | null>(null);
  const [cisResult, setCisResult] = useState<CISAlignmentResult | null>(null);
  const [activeTab, setActiveTab] = useState<ViewTab>("dashboard");
  const [error, setError] = useState<string | null>(null);

  const runAnalysis = useCallback(async () => {
    if (!accounts[0]) return;
    setLoading(true);
    setError(null);

    try {
      const ctx = await loadTenantContext(instance, accounts[0], setProgress);
      setContext(ctx);

      setProgress("Analyzing policies…");
      const analysisResult = analyzeAllPolicies(ctx);
      setResult(analysisResult);

      setProgress("Matching against policy templates…");
      const templates = analyzeTemplates(ctx);
      setTemplateResult(templates);

      setProgress("Running CIS alignment checks…");
      const cis = runCISAlignment(ctx);
      setCisResult(cis);

      setActiveTab("dashboard");
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Unknown error occurred";
      setError(msg);
      console.error("Analysis failed:", e);
    } finally {
      setLoading(false);
      setProgress("");
    }
  }, [instance, accounts]);

  const exportResults = useCallback(() => {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `ca-analysis-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [result]);

  // ── Not Authenticated ─────────────────────────────────────────────────
  if (!isAuthenticated) {
    return (
      <div className="flex flex-col items-center justify-center py-32 text-center">
        <Shield className="h-16 w-16 text-blue-500 mb-6" />
        <h2 className="text-3xl font-bold text-white mb-3">
          CA Policy Analyzer
        </h2>
        <p className="max-w-lg text-gray-400 mb-2">
          Connect your Entra ID tenant to analyze Conditional Access policies
          for best practices, FOCI token-sharing risks, and known bypasses
          documented by Fabian Bader and the EntraScopes project.
        </p>
        <p className="max-w-lg text-sm text-gray-600 mb-8">
          Requires <code className="text-gray-400">Policy.Read.All</code>,{" "}
          <code className="text-gray-400">Application.Read.All</code>, and{" "}
          <code className="text-gray-400">Directory.Read.All</code> delegated
          permissions.
        </p>
        <p className="text-sm text-gray-600">
          Click <strong className="text-gray-400">Connect Tenant</strong> in the
          header to get started.
        </p>
      </div>
    );
  }

  // ── Authenticated but not yet analyzed ────────────────────────────────
  if (!result) {
    return (
      <div className="flex flex-col items-center justify-center py-24 text-center">
        <Shield className="h-12 w-12 text-blue-500 mb-4" />
        <h2 className="text-2xl font-bold text-white mb-2">
          Ready to Analyze
        </h2>
        <p className="max-w-md text-gray-400 mb-6">
          Connected as{" "}
          <strong className="text-white">
            {accounts[0]?.name ?? accounts[0]?.username}
          </strong>
          . Click below to read your CA policies via Microsoft Graph and run the
          best-practice analysis.
        </p>

        {error && (
          <div className="mb-4 max-w-md rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-400">
            {error}
          </div>
        )}

        <button
          onClick={runAnalysis}
          disabled={loading}
          className={cn(
            "flex items-center gap-2 rounded-lg px-6 py-3 text-sm font-semibold transition-colors",
            loading
              ? "bg-gray-800 text-gray-500 cursor-not-allowed"
              : "bg-blue-600 text-white hover:bg-blue-500"
          )}
        >
          {loading ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" />
              {progress || "Loading…"}
            </>
          ) : (
            <>
              <Play className="h-4 w-4" />
              Run Analysis
            </>
          )}
        </button>
      </div>
    );
  }

  // ── Results View ──────────────────────────────────────────────────────
  return (
    <div className="space-y-6">
      {/* Tab Bar + Actions */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex gap-1 rounded-lg bg-gray-900 p-1">
          {(
            [
              { key: "dashboard", label: "Dashboard" },
              { key: "policies", label: "Policies" },
              { key: "findings", label: "All Findings" },
              { key: "templates", label: "Templates" },
              { key: "cis", label: "CIS Alignment" },
            ] as const
          ).map((tab) => (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key)}
              className={cn(
                "rounded-md px-4 py-2 text-sm font-medium transition-colors",
                activeTab === tab.key
                  ? "bg-gray-800 text-white"
                  : "text-gray-400 hover:text-white"
              )}
            >
              {tab.label}
            </button>
          ))}
        </div>

        <div className="flex gap-2">
          <button
            onClick={runAnalysis}
            disabled={loading}
            className="flex items-center gap-2 rounded-lg border border-gray-700 px-3 py-2 text-sm text-gray-300 hover:bg-gray-800 transition-colors"
          >
            <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
            Re-scan
          </button>
          <button
            onClick={exportResults}
            className="flex items-center gap-2 rounded-lg border border-gray-700 px-3 py-2 text-sm text-gray-300 hover:bg-gray-800 transition-colors"
          >
            <Download className="h-4 w-4" />
            Export JSON
          </button>
        </div>
      </div>

      {/* Tab Content */}
      {activeTab === "dashboard" && <Dashboard result={result} />}
      {activeTab === "policies" && (
        <PolicyList results={result.policyResults} />
      )}
      {activeTab === "findings" && (
        <FindingsList findings={result.findings} title="All Findings" />
      )}
      {activeTab === "templates" && templateResult && (
        <TemplatesView result={templateResult} />
      )}
      {activeTab === "cis" && cisResult && (
        <CISView result={cisResult} />
      )}
    </div>
  );
}
