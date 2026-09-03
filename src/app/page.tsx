"use client";

import { useState, useCallback, useMemo, useEffect } from "react";
import { useIsAuthenticated, useMsal } from "@azure/msal-react";
import { loadTenantContext, TenantContext } from "@/lib/graph-client";
import { analyzeAllPolicies, AnalysisResult, calculateCompositeScore, CompositeScoreResult, withExtraFindings } from "@/lib/analyzer";
import { analyzeTemplates, TemplateAnalysisResult } from "@/lib/template-matcher";
import { fetchGitHubTemplates, fetchLayeredGitHubTemplates } from "@/lib/github-templates";
import { runCISAlignment, CISAlignmentResult } from "@/data/cis-benchmarks";
import { Dashboard } from "@/components/dashboard";
import { PolicyList } from "@/components/policy-list";
import { FindingsList } from "@/components/findings-list";
import { TemplatesView } from "@/components/templates-view";
import { CISView } from "@/components/cis-view";
import { ExclusionsView } from "@/components/exclusions-view";
import { LocationsView } from "@/components/locations-view";
import { PersonaView } from "@/components/persona-view";
import { analyzeNamedLocations, LocationAnalysisResult } from "@/lib/location-analyzer";
import { analyzePersonaCoverage, PersonaCoverageResult } from "@/lib/persona-coverage";
import { analyzeSignInAppGap } from "@/lib/signin-app-gap";
import { buildZeroTrustScorecard, ZeroTrustScorecard } from "@/lib/zero-trust-scorecard";
import { analyzeBaselineGaps, BaselineGapResult } from "@/lib/baseline-gap";
import { TemplateCategory } from "@/data/policy-templates";
import { BaselineGapView } from "@/components/baseline-gap-view";
import { exportToExcel, exportToPowerPoint, loadDefaultLogo } from "@/lib/export-utils";
import { buildTenantContextFromOfflineExport, OfflineExportPayload } from "@/lib/offline-import";
import { scopesFor } from "@/lib/msal-config";
import { RUN_STEPS, liveStepList, offlineStepList } from "@/lib/run-steps";
import { RunProgress } from "@/components/run-progress";
import { ScanComplete } from "@/components/scan-complete";
import { Shield, Play, Download, RefreshCw, LayoutDashboard, FileText, AlertTriangle, Layers, CheckSquare, BookOpen, FileSpreadsheet, Presentation, MapPin, Users, GitCompareArrows, ScanSearch } from "lucide-react";
import Link from "next/link";
import { cn } from "@/lib/utils";

type ViewTab = "dashboard" | "policies" | "findings" | "templates" | "baseline" | "cis" | "locations" | "personas" | "ms-learn";
const MAX_OFFLINE_IMPORT_BYTES = 20 * 1024 * 1024; // 20MB

/** Opt-out, not opt-in: the scan runs unless the user turns it off. */
const SIGNIN_SCAN_KEY = "includeSignInLogs";

/** The steps this run will walk through, plus an optional footnote. */
interface RunPlan {
  steps: string[];
  note?: string;
}

/** How long the completion panel holds before the dashboard takes over. */
const COMPLETION_HOLD_MS = 3200;

/** Never reports 0s - a run that fast still took a moment worth naming. */
function elapsedSeconds(startedAt: number): number {
  return Math.max(1, Math.round((Date.now() - startedAt) / 1000));
}

interface Completion {
  steps: number;
  seconds: number;
  /** True for a first run, where the panel replaces the centered progress it
   * followed. A re-scan renders it in place of the progress card instead, so
   * the results view doesn't get yanked away for three seconds. */
  takeover: boolean;
}

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
  const [personaResult, setPersonaResult] = useState<PersonaCoverageResult | null>(null);
  const [scorecard, setScorecard] = useState<ZeroTrustScorecard | null>(null);
  const [compositeScore, setCompositeScore] = useState<CompositeScoreResult | null>(null);
  const [locationResult, setLocationResult] = useState<LocationAnalysisResult | null>(null);
  const [activeTab, setActiveTab] = useState<ViewTab>("dashboard");
  const [error, setError] = useState<string | null>(null);
  const [hideMicrosoft, setHideMicrosoft] = useState(false);
  const [baselineCategory, setBaselineCategory] = useState<TemplateCategory | null>(null);
  const [logoBase64, setLogoBase64] = useState<string | null>(null);
  const [includeSignInLogs, setIncludeSignInLogs] = useState(true);
  const [runPlan, setRunPlan] = useState<RunPlan | null>(null);
  const [completion, setCompletion] = useState<Completion | null>(null);

  // Auto-advance: the panel marks the moment, it doesn't ask to be dismissed.
  useEffect(() => {
    if (!completion) return;
    const timer = setTimeout(() => setCompletion(null), COMPLETION_HOLD_MS);
    return () => clearTimeout(timer);
  }, [completion]);

  // Read on the client only - this page is statically exported, so localStorage
  // isn't available while it prerenders.
  useEffect(() => {
    setIncludeSignInLogs(localStorage.getItem(SIGNIN_SCAN_KEY) !== "false");
  }, []);

  const toggleSignInLogs = useCallback((next: boolean) => {
    setIncludeSignInLogs(next);
    localStorage.setItem(SIGNIN_SCAN_KEY, String(next));
  }, []);

  const setAppMode = useCallback((mode: "offline" | "live" | null) => {
    if (mode === null) {
      localStorage.removeItem("caAnalyzerMode");
    } else {
      localStorage.setItem("caAnalyzerMode", mode);
    }
    window.dispatchEvent(new CustomEvent("ca-analyzer-mode", { detail: mode }));
  }, []);

  useEffect(() => {
    if (!result) setAppMode(null);
  }, [result, setAppMode]);

  const executeAnalysis = useCallback(async (ctx: TenantContext) => {
    setContext(ctx);

    setProgress(RUN_STEPS.analyzePolicies);
    const analysisResult = analyzeAllPolicies(ctx);
    setResult(analysisResult);

    setProgress(RUN_STEPS.templates);
    let activeTemplates = analyzeTemplates(ctx);
    setTemplateResult(activeTemplates);

    // Restore custom repo from previous session if saved. Stays inside the
    // template step - it is template work, and it only happens for some users.
    const savedRepoUrl = localStorage.getItem("customRepoUrl");
    if (savedRepoUrl) {
      // Saved value is either a plain URL string (legacy) or a JSON
      // `{ url, fallbackUrl }` payload for layered baselines.
      let parsedUrl = savedRepoUrl;
      let parsedFallback: string | undefined;
      if (savedRepoUrl.startsWith("{")) {
        try {
          const j = JSON.parse(savedRepoUrl) as { url?: string; fallbackUrl?: string };
          if (j.url) parsedUrl = j.url;
          parsedFallback = j.fallbackUrl;
        } catch {
          // Fall through and treat as a plain URL.
        }
      }
      const custom = parsedFallback
        ? await fetchLayeredGitHubTemplates(parsedUrl, parsedFallback)
        : await fetchGitHubTemplates(parsedUrl);
      if (custom.templates.length > 0) {
        activeTemplates = analyzeTemplates(ctx, custom.templates);
        setTemplateResult(activeTemplates);
        setCustomRepoDisplay(custom.repoDisplay);
      } else {
        localStorage.removeItem("customRepoUrl");
      }
    }

    // One step from here on: all of it is local computation over data that is
    // already in hand, so splitting it further only makes labels flicker.
    setProgress(RUN_STEPS.posture);
    const cis = runCISAlignment(ctx);
    setCisResult(cis);

    const locResult = analyzeNamedLocations(ctx);
    setLocationResult(locResult);

    const persona = analyzePersonaCoverage(ctx);
    setPersonaResult(persona);

    const signInGap = analyzeSignInAppGap(ctx, activeTemplates);

    // Merge into the main list so they surface in the Findings tab and exports.
    // withExtraFindings re-derives the summary and score, so the dashboard,
    // completion panel and export can't disagree with the Findings tab.
    const mergedResult = withExtraFindings(ctx, analysisResult, [
      ...persona.findings,
      ...signInGap.findings,
    ]);
    if (mergedResult !== analysisResult) setResult(mergedResult);

    const composite = calculateCompositeScore(mergedResult, cis, activeTemplates);
    setCompositeScore(composite);

    const zt = buildZeroTrustScorecard(ctx, mergedResult, persona);
    setScorecard(zt);

    setActiveTab("dashboard");
  }, []);

  /** Lazy-derived baseline gap report. Recomputes whenever templates or context change. */
  const baselineGapResult: BaselineGapResult | null = useMemo(() => {
    if (!context || !templateResult) return null;
    return analyzeBaselineGaps(context, templateResult, baselineCategory);
  }, [context, templateResult, baselineCategory]);

  /** Load templates from a custom GitHub repo and re-run template analysis */
  const handleLoadGitHub = useCallback(async (url: string, fallbackUrl?: string): Promise<string | null> => {
    if (!context) return "Run an analysis first before loading custom templates.";
    const result = fallbackUrl
      ? await fetchLayeredGitHubTemplates(url, fallbackUrl)
      : await fetchGitHubTemplates(url);
    if (result.error && result.templates.length === 0) return result.error;
    const templates = analyzeTemplates(context, result.templates);
    setTemplateResult(templates);
    setCustomRepoDisplay(result.repoDisplay);
    // Persist as JSON when a fallback is in play, otherwise keep the legacy
    // plain-string format so older saved values still work.
    if (fallbackUrl) {
      localStorage.setItem(
        "customRepoUrl",
        JSON.stringify({ url, fallbackUrl })
      );
    } else {
      localStorage.setItem("customRepoUrl", url);
    }
    return result.error ?? null; // partial error (some files skipped)
  }, [context]);

  /** Reset back to built-in templates */
  const handleResetTemplates = useCallback(() => {
    if (!context) return;
    const templates = analyzeTemplates(context);
    setTemplateResult(templates);
    setCustomRepoDisplay(null);
    localStorage.removeItem("customRepoUrl");
  }, [context]);

  /** `withSignInLogs` is explicit so "Re-scan with sign-in logs" can override
   * the saved preference for a single run. */
  const runAnalysis = useCallback(async (withSignInLogs: boolean) => {
    if (!accounts[0]) return;
    const steps = liveStepList(withSignInLogs);
    const startedAt = Date.now();
    setLoading(true);
    setError(null);
    setCompletion(null);
    setRunPlan({
      steps,
      note: withSignInLogs ? undefined : "sign-in log scan skipped",
    });

    try {
      setAppMode("live");
      const ctx = await loadTenantContext(instance, accounts[0], setProgress, {
        includeSignInLogs: withSignInLogs,
      });
      await executeAnalysis(ctx);
      setCompletion({
        steps: steps.length,
        seconds: elapsedSeconds(startedAt),
        takeover: result === null,
      });
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Unknown error occurred";
      setError(msg);
      console.error("Analysis failed:", e);
    } finally {
      setLoading(false);
      setProgress("");
      setRunPlan(null);
    }
  }, [instance, accounts, executeAnalysis, setAppMode, result]);

  const handleLogin = useCallback(() => {
    setAppMode("live");
    // Consent covers the scan only when it is switched on. Turning it on later
    // triggers an incremental consent redirect from the Graph auth provider.
    instance.loginRedirect({ scopes: scopesFor(includeSignInLogs) }).catch((e) => {
      console.error("Login failed:", e);
    });
  }, [instance, setAppMode, includeSignInLogs]);

  const handleOfflineImport = useCallback(async (file: File) => {
    const startedAt = Date.now();
    setLoading(true);
    setError(null);
    setCompletion(null);
    setRunPlan({ steps: offlineStepList });

    try {
      setProgress(RUN_STEPS.parseOffline);
      if (file.size > MAX_OFFLINE_IMPORT_BYTES) {
        throw new Error(
          `Offline export is too large (${Math.round(file.size / (1024 * 1024))}MB). Max supported size is 20MB.`
        );
      }
      const text = await file.text();
      const parsed = JSON.parse(text) as OfflineExportPayload;

      const asAny = parsed as Record<string, unknown>;
      if (asAny.policyResults !== undefined || asAny.findings !== undefined || asAny.overallScore !== undefined) {
        throw new Error(
          "This looks like an analysis results export, not a raw policy export. " +
          "To use offline mode, export your policies directly from PowerShell using " +
          "Get-MgIdentityConditionalAccessPolicy | ConvertTo-Json -Depth 10, then upload that file."
        );
      }

      const ctx = buildTenantContextFromOfflineExport(parsed);
      if (ctx.policies.length === 0) {
        throw new Error("No Conditional Access policies found. Make sure you're uploading a raw Graph PowerShell export (Get-MgIdentityConditionalAccessPolicy | ConvertTo-Json -Depth 10).");
      }
      setAppMode("offline");
      await executeAnalysis(ctx);
      setCompletion({
        steps: offlineStepList.length,
        seconds: elapsedSeconds(startedAt),
        takeover: result === null,
      });
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Failed to import offline export";
      setError(msg);
      console.error("Offline import failed:", e);
    } finally {
      setLoading(false);
      setProgress("");
      setRunPlan(null);
    }
  }, [executeAnalysis, setAppMode, result]);

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

  // Built once, rendered either full-screen (first run) or as a card in the
  // results view (re-scan).
  const completionPanel =
    completion && result ? (
      <ScanComplete
        summary={result.tenantSummary}
        score={compositeScore?.overall ?? result.overallScore}
        grade={compositeScore?.grade}
        steps={completion.steps}
        seconds={completion.seconds}
        signInScanRan={!!context?.unregisteredSignInApps}
        onRescanWithSignInLogs={
          isAuthenticated ? () => void runAnalysis(true) : null
        }
        onDismiss={() => setCompletion(null)}
      />
    ) : null;

  // ── Not Authenticated and no offline result yet ──────────────────────
  if (!isAuthenticated && !result) {
    return (
      <div className="flex flex-col items-center justify-center py-32 text-center">
        <Shield className="h-16 w-16 text-blue-500 mb-6" />
        <h2 className="text-3xl font-bold text-white mb-3">
          CA Policy Analyzer
        </h2>
        <p className="max-w-lg text-gray-400 mb-2">
          Analyze Conditional Access policies for best practices, FOCI token-sharing risks, and known bypasses.
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
        <div className="mt-8 grid w-full max-w-4xl gap-4 text-left md:grid-cols-2">
          <div className="rounded-xl border border-blue-500/30 bg-blue-500/5 p-5">
            <p className="text-sm font-medium text-gray-100">Offline export import</p>
            <p className="mt-1 text-xs text-gray-400">
              Default mode for least privilege and fully offline analysis. Export once, then upload JSON.
            </p>
            <p className="mt-2 text-xs text-gray-500">
              Limits: offline import supports JSON files up to 20MB.
            </p>
            <div className="mt-4 flex flex-wrap gap-2">
              <label
                htmlFor="offline-import"
                className="inline-flex cursor-pointer items-center gap-2 rounded-lg bg-blue-600 px-3 py-2 text-sm text-white hover:bg-blue-500"
              >
                <Download className="h-4 w-4" />
                Import Offline Export
              </label>
              <Link
                href="/offline-export"
                className="inline-flex items-center gap-2 rounded-lg border border-gray-700 px-3 py-2 text-sm text-gray-300 hover:bg-gray-800"
              >
                Offline Export Instructions
              </Link>
            </div>
            <input
              id="offline-import"
              type="file"
              accept=".json,application/json"
              className="hidden"
              disabled={loading}
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) {
                  void handleOfflineImport(file);
                  e.target.value = "";
                }
              }}
            />
          </div>

          <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
            <p className="text-sm font-medium text-gray-200">Direct tenant connection</p>
            <p className="mt-1 text-xs text-gray-500">
              Connect live to Microsoft Graph for real-time reads using delegated permissions.
            </p>
            <p className="mt-2 text-xs text-gray-600">
              Requires <code className="text-gray-400">Policy.Read.All</code>,{" "}
              <code className="text-gray-400">Application.Read.All</code> and{" "}
              <code className="text-gray-400">Directory.Read.All</code>
              {includeSignInLogs && (
                <>
                  , plus <code className="text-gray-400">AuditLog.Read.All</code> for the
                  sign-in log scan
                </>
              )}
              . All read-only.
            </p>

            <SignInScanToggle
              className="mt-4"
              checked={includeSignInLogs}
              onChange={toggleSignInLogs}
            />

            <button
              onClick={handleLogin}
              className="mt-4 inline-flex items-center gap-2 rounded-lg bg-gray-800 px-3 py-2 text-sm font-medium text-white hover:bg-gray-700"
            >
              <Play className="h-4 w-4" />
              Connect Tenant
              <span className="text-xs text-gray-500">
                ({includeSignInLogs ? 4 : 3} permissions)
              </span>
            </button>
          </div>
        </div>

        {loading && runPlan && (
          <div className="mt-10 flex justify-center">
            <RunProgress steps={runPlan.steps} current={progress} note={runPlan.note} />
          </div>
        )}
        {error && (
          <div className="mt-8 max-w-md rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-left text-sm text-red-400">
            {error}
          </div>
        )}
      </div>
    );
  }

  // ── Authenticated but not yet analyzed ────────────────────────────────
  if (isAuthenticated && !result) {
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

        {loading && runPlan ? (
          <div className="flex justify-center">
            <RunProgress steps={runPlan.steps} current={progress} note={runPlan.note} />
          </div>
        ) : (
          <>
            <SignInScanToggle
              checked={includeSignInLogs}
              onChange={toggleSignInLogs}
            />

            <p className="mt-3 text-xs text-gray-500">
              {includeSignInLogs
                ? "Run time: slower - the sign-in log scan is the heaviest step"
                : "Run time: fastest - no audit log queries"}
            </p>

            <button
              onClick={() => runAnalysis(includeSignInLogs)}
              className="mt-5 flex items-center gap-2 rounded-lg bg-blue-600 px-6 py-3 text-sm font-semibold text-white transition-colors hover:bg-blue-500"
            >
              <Play className="h-4 w-4" />
              {includeSignInLogs ? "Run Analysis with sign-in logs" : "Run Analysis"}
            </button>

            {includeSignInLogs && (
              <p className="mt-3 max-w-md text-xs text-gray-600">
                If this session has not granted{" "}
                <code className="text-gray-500">AuditLog.Read.All</code> yet, Microsoft asks
                for consent once before the scan starts.
              </p>
            )}
          </>
        )}
      </div>
    );
  }

  // ── Run just finished, first result ──────────────────────────────────
  // Full-screen, following the centered progress it replaces. Re-scans get the
  // card version further down instead.
  if (completionPanel && completion?.takeover) {
    return (
      <div className="flex flex-col items-center justify-center py-24">
        {completionPanel}
      </div>
    );
  }

  // ── Tab definitions ──────────────────────────────────────────────────
  const tabs = [
    { key: "dashboard" as const, label: "Dashboard", icon: LayoutDashboard },
    { key: "policies" as const, label: "Policies", icon: FileText },
    { key: "findings" as const, label: "Findings", icon: AlertTriangle },
    { key: "templates" as const, label: "Templates", icon: Layers },
    { key: "baseline" as const, label: "Baseline Gap", icon: GitCompareArrows },
    { key: "cis" as const, label: "CIS", icon: CheckSquare },
    { key: "locations" as const, label: "Locations", icon: MapPin },
    { key: "personas" as const, label: "Personas", icon: Users },
    { key: "ms-learn" as const, label: "MS Learn", icon: BookOpen },
  ];

  // ── Results View ──────────────────────────────────────────────────────
  const tenantName =
    context?.tenantDisplayName ??
    accounts[0]?.username?.split("@")[1] ??
    "Unknown";
  const tenantId = context?.tenantId ?? accounts[0]?.tenantId ?? "";
  if (!result) return null;

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
      <div className="space-y-2">
        {/* Scrollable tab strip - icons only on mobile, icons + labels on sm+ */}
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

        {/* Action buttons - icon-only on mobile */}
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => runAnalysis(includeSignInLogs)}
            disabled={loading}
            title="Re-scan"
            className="flex items-center gap-2 rounded-lg border border-gray-700 px-2.5 py-2 text-sm text-gray-300 hover:bg-gray-800 transition-colors sm:px-3"
          >
            <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
            <span className="hidden sm:inline">Re-scan</span>
          </button>
          {/* Only when the scan didn't run - otherwise plain Re-scan already is
              the full run and this would be a second button doing the same. */}
          {isAuthenticated && !context?.unregisteredSignInApps && (
            <button
              onClick={() => runAnalysis(true)}
              disabled={loading}
              title="Re-scan with sign-in logs (requests AuditLog.Read.All)"
              className="flex items-center gap-2 rounded-lg border border-gray-700 px-2.5 py-2 text-sm text-gray-300 hover:bg-gray-800 transition-colors sm:px-3"
            >
              <ScanSearch className="h-4 w-4" />
              <span className="hidden sm:inline">Re-scan with sign-in logs</span>
            </button>
          )}
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
                personaResult,
                scorecard,
                baselineGap: baselineGapResult,
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

      {/* Re-scan in progress - same step list as the first run */}
      {loading && runPlan && (
        <div className="rounded-xl border border-gray-800 bg-gray-900 px-5 py-5">
          <RunProgress steps={runPlan.steps} current={progress} note={runPlan.note} />
        </div>
      )}

      {/* Re-scan finished - same panel, in the slot the progress just left */}
      {!loading && completionPanel && (
        <div className="rounded-xl border border-gray-800 bg-gray-900 px-5 py-8">
          {completionPanel}
        </div>
      )}

      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-400">
          {error}
        </div>
      )}

      {/* Tab Content */}
      {activeTab === "dashboard" && <Dashboard result={result} compositeScore={compositeScore} licenses={context?.licenses} scorecard={scorecard} />}
      {activeTab === "policies" && (
        <PolicyList results={result.policyResults} hideMicrosoft={hideMicrosoft} onToggleHideMicrosoft={setHideMicrosoft} resolverMaps={context ? { directoryObjects: context.directoryObjects, servicePrincipals: context.servicePrincipals } : undefined} />
      )}
      {activeTab === "findings" && (
        <FindingsList
          findings={result.findings}
          title="All Findings"
          tenantDisplayName={tenantName}
          tenantId={tenantId}
        />
      )}
      {activeTab === "templates" && templateResult && (
        <TemplatesView result={templateResult} customRepoDisplay={customRepoDisplay} onLoadGitHub={handleLoadGitHub} onResetTemplates={handleResetTemplates} categoryFilter={baselineCategory} onCategoryFilterChange={setBaselineCategory} />
      )}
      {activeTab === "baseline" && baselineGapResult && (
        <BaselineGapView result={baselineGapResult} baselineLabel={baselineCategory === "lewis-barry" ? "Lewis Barry - Baseline" : (customRepoDisplay ?? "built-in template set")} templateResult={templateResult} />
      )}
      {activeTab === "cis" && cisResult && (
        <CISView result={cisResult} />
      )}
      {activeTab === "locations" && locationResult && (
        <LocationsView result={locationResult} />
      )}
      {activeTab === "personas" && personaResult && (
        <PersonaView result={personaResult} />
      )}
      {activeTab === "ms-learn" && result && (

        <ExclusionsView findings={result.exclusionFindings} />
      )}
    </div>
  );
}

/**
 * The one control for the sign-in log scan. Shown before connecting (it decides
 * which scopes consent covers) and before running (it decides whether the scan
 * happens at all).
 */
function SignInScanToggle({
  checked,
  onChange,
  className,
}: {
  checked: boolean;
  onChange: (next: boolean) => void;
  className?: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      onClick={() => onChange(!checked)}
      className={cn(
        "flex w-full max-w-lg items-start gap-3 rounded-xl border p-4 text-left transition-colors",
        checked
          ? "border-blue-500/40 bg-blue-500/5"
          : "border-gray-800 bg-gray-900 hover:border-gray-700",
        className
      )}
    >
      <span
        className={cn(
          "relative mt-0.5 h-5 w-9 shrink-0 rounded-full transition-colors",
          checked ? "bg-blue-600" : "bg-gray-700"
        )}
      >
        <span
          className={cn(
            "absolute left-0.5 top-0.5 h-4 w-4 rounded-full bg-white transition-transform",
            checked && "translate-x-4"
          )}
        />
      </span>
      <span>
        <span
          className={cn(
            "flex flex-wrap items-center gap-2 text-sm font-medium",
            checked ? "text-white" : "text-gray-300"
          )}
        >
          Scan sign-in logs
          <span className="rounded-full bg-amber-500/10 px-2 py-0.5 text-[10px] font-semibold text-amber-300">
            slower
          </span>
        </span>
        <span className="mt-1 block text-xs text-gray-500">
          Finds enterprise apps that sign in but have no service principal - those
          sit outside every Conditional Access policy, so they never show up as a
          gap. Needs <code className="text-gray-400">AuditLog.Read.All</code> (admin
          consent) and Entra ID P1.
        </span>
      </span>
    </button>
  );
}
