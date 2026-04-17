"use client";

import { useState, useCallback } from "react";
import { useIsAuthenticated, useMsal } from "@azure/msal-react";
import { loadTenantContext, TenantContext } from "@/lib/graph-client";
import { analyzeAllPolicies, AnalysisResult, calculateCompositeScore, CompositeScoreResult } from "@/lib/analyzer";
import { analyzeTemplates, TemplateAnalysisResult } from "@/lib/template-matcher";
import { fetchGitHubTemplates } from "@/lib/github-templates";
import { runCISAlignment, CISAlignmentResult } from "@/data/cis-benchmarks";
import { Dashboard } from "@/components/dashboard";
import { PolicyList } from "@/components/policy-list";
import { FindingsList } from "@/components/findings-list";
import { TemplatesView } from "@/components/templates-view";
import { CISView } from "@/components/cis-view";
import { ExclusionsView } from "@/components/exclusions-view";
import { LocationsView } from "@/components/locations-view";
import { analyzeNamedLocations, LocationAnalysisResult } from "@/lib/location-analyzer";
import { exportToExcel, exportToPowerPoint, loadDefaultLogo } from "@/lib/export-utils";
import { Shield, Loader2, Play, Download, RefreshCw, LayoutDashboard, FileText, AlertTriangle, Layers, CheckSquare, BookOpen, FileSpreadsheet, Presentation, MapPin } from "lucide-react";
import { cn } from "@/lib/utils";

type ViewTab = "dashboard" | "policies" | "findings" | "templates" | "cis" | "locations" | "ms-learn";

export default function Home() {
  const isAuthenticated = useIsAuthenticated();
  const { instance, accounts } = useMsal();

  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState("");
  const [context, setContext] = useState<TenantContext | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [templateResult, setTemplateResult] = useState<TemplateAnalysisResult | null>(null);
  const [customRepoDisplay, setCustomRepoDisplay] = useState<string | null>(null);
  const [cisResult, setCisResult] = useState<CISAlignmentResult | null>(null);
  const [compositeScore, setCompositeScore] = useState<CompositeScoreResult | null>(null);
  const [locationResult, setLocationResult] = useState<LocationAnalysisResult | null>(null);
  const [activeTab, setActiveTab] = useState<ViewTab>("dashboard");
  const [error, setError] = useState<string | null>(null);
  const [hideMicrosoft, setHideMicrosoft] = useState(false);
  const [logoBase64, setLogoBase64] = useState<string | null>(null);

  /** Load templates from a custom GitHub repo and re-run template analysis */
  const handleLoadGitHub = useCallback(async (url: string): Promise<string | null> => {
    if (!context) return "Run an analysis first before loading custom templates.";
    const result = await fetchGitHubTemplates(url);
    if (result.error && result.templates.length === 0) return result.error;
    const templates = analyzeTemplates(context, result.templates);
    setTemplateResult(templates);
    setCustomRepoDisplay(result.repoDisplay);
    return result.error ?? null; // partial error (some files skipped)
  }, [context]);

  /** Reset back to built-in templates */
  const handleResetTemplates = useCallback(() => {
    if (!context) return;
    const templates = analyzeTemplates(context);
    setTemplateResult(templates);
    setCustomRepoDisplay(null);
  }, [context]);

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

      setProgress("Analyzing named locations…");
      const locResult = analyzeNamedLocations(ctx);
      setLocationResult(locResult);

      setProgress("Computing security posture score…");
      const composite = calculateCompositeScore(analysisResult, cis, templates);
      setCompositeScore(composite);

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
    const exportData = { ...result, compositeScore: compositeScore ?? undefined };
    const blob = new Blob([JSON.stringify(exportData, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `ca-analysis-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [result, compositeScore]);

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
          for best practices, FOCI token-sharing risks, and known bypasses.
          Built on research by{" "}
          <a
            href="https://www.entrascopes.com"
            target="_blank"
            rel="noopener noreferrer"
            className="text-blue-400 underline hover:text-blue-300"
          >
            Fabian Bader / EntraScopes
          </a>.
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

  // ── Tab definitions ──────────────────────────────────────────────────
  const tabs = [
    { key: "dashboard" as const, label: "Dashboard", icon: LayoutDashboard },
    { key: "policies" as const, label: "Policies", icon: FileText },
    { key: "findings" as const, label: "Findings", icon: AlertTriangle },
    { key: "templates" as const, label: "Templates", icon: Layers },
    { key: "cis" as const, label: "CIS", icon: CheckSquare },
    { key: "locations" as const, label: "Locations", icon: MapPin },
    { key: "ms-learn" as const, label: "MS Learn", icon: BookOpen },
  ];

  // ── Results View ──────────────────────────────────────────────────────
  const tenantName = context?.tenantDisplayName ?? accounts[0]?.username?.split("@")[1] ?? "Unknown";
  const tenantId = context?.tenantId ?? accounts[0]?.tenantId ?? "";

  return (
    <div className="space-y-6">
      {/* Tenant Identity Banner */}
      <div className="rounded-xl border border-gray-800 bg-gray-900 px-5 py-4">
        <p className="text-sm text-gray-400">
          CA Policy Analysis for
        </p>
        <h2 className="text-xl font-bold text-white mt-0.5">
          {tenantName}
        </h2>
        {tenantId && (
          <p className="text-xs text-gray-600 font-mono mt-1">
            Tenant ID: {tenantId}
          </p>
        )}
      </div>

      {/* Tab Bar + Actions */}
      <div className="flex items-center justify-between gap-2">
        {/* Scrollable tab strip — icons only on mobile, icons + labels on sm+ */}
        <div className="min-w-0 flex-1 overflow-x-auto scrollbar-hide">
          <div className="inline-flex gap-1 rounded-lg bg-gray-900 p-1">
            {tabs.map((tab) => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.key}
                  onClick={() => setActiveTab(tab.key)}
                  title={tab.label}
                  className={cn(
                    "flex items-center gap-1.5 whitespace-nowrap rounded-md px-2.5 py-2 text-sm font-medium transition-colors sm:px-3",
                    activeTab === tab.key
                      ? "bg-gray-800 text-white"
                      : "text-gray-400 hover:text-white"
                  )}
                >
                  <Icon className="h-4 w-4 shrink-0" />
                  <span className="hidden sm:inline">{tab.label}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Action buttons — icon-only on mobile */}
        <div className="flex shrink-0 gap-2">
          <button
            onClick={runAnalysis}
            disabled={loading}
            title="Re-scan"
            className="flex items-center gap-2 rounded-lg border border-gray-700 px-2.5 py-2 text-sm text-gray-300 hover:bg-gray-800 transition-colors sm:px-3"
          >
            <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
            <span className="hidden sm:inline">Re-scan</span>
          </button>
          <button
            onClick={exportResults}
            title="Export JSON"
            className="flex items-center gap-2 rounded-lg border border-gray-700 px-2.5 py-2 text-sm text-gray-300 hover:bg-gray-800 transition-colors sm:px-3"
          >
            <Download className="h-4 w-4" />
            <span className="hidden sm:inline">JSON</span>
          </button>
          <button
            onClick={() => result && exportToExcel(result, cisResult, compositeScore, { hideMicrosoftPolicies: hideMicrosoft, tenantDisplayName: tenantName, tenantId, resolverMaps: context ? { directoryObjects: context.directoryObjects, servicePrincipals: context.servicePrincipals } : undefined })}
            title="Export Excel"
            className="flex items-center gap-2 rounded-lg border border-gray-700 px-2.5 py-2 text-sm text-gray-300 hover:bg-gray-800 transition-colors sm:px-3"
          >
            <FileSpreadsheet className="h-4 w-4" />
            <span className="hidden sm:inline">Excel</span>
          </button>
          <button
            onClick={async () => {
              if (!result) return;
              // Load default logo on first export (retry if previous attempt failed)
              let logo = logoBase64;
              if (!logo) {
                logo = await loadDefaultLogo();
                if (logo) setLogoBase64(logo);
              }
              await exportToPowerPoint(result, cisResult, compositeScore, {
                hideMicrosoftPolicies: hideMicrosoft,
                logoBase64: logo,
                tenantDisplayName: tenantName,
                tenantId,
                resolverMaps: context ? { directoryObjects: context.directoryObjects, servicePrincipals: context.servicePrincipals } : undefined,
              });
            }}
            title="Export PowerPoint"
            className="flex items-center gap-2 rounded-lg border border-gray-700 px-2.5 py-2 text-sm text-gray-300 hover:bg-gray-800 transition-colors sm:px-3"
          >
            <Presentation className="h-4 w-4" />
            <span className="hidden sm:inline">PPTX</span>
          </button>
        </div>
      </div>

      {/* Tab Content */}
      {activeTab === "dashboard" && <Dashboard result={result} compositeScore={compositeScore} licenses={context?.licenses} />}
      {activeTab === "policies" && (
        <PolicyList results={result.policyResults} hideMicrosoft={hideMicrosoft} onToggleHideMicrosoft={setHideMicrosoft} resolverMaps={context ? { directoryObjects: context.directoryObjects, servicePrincipals: context.servicePrincipals } : undefined} />
      )}
      {activeTab === "findings" && (
        <FindingsList findings={result.findings} title="All Findings" />
      )}
      {activeTab === "templates" && templateResult && (
        <TemplatesView result={templateResult} customRepoDisplay={customRepoDisplay} onLoadGitHub={handleLoadGitHub} onResetTemplates={handleResetTemplates} />
      )}
      {activeTab === "cis" && cisResult && (
        <CISView result={cisResult} />
      )}
      {activeTab === "locations" && locationResult && (
        <LocationsView result={locationResult} />
      )}
      {activeTab === "ms-learn" && result && (
        <ExclusionsView findings={result.exclusionFindings} />
      )}
    </div>
  );
}
