"use client";

import { useState } from "react";
import {
  TemplateAnalysisResult,
  TemplateMatch,
  MatchStatus,
} from "@/lib/template-matcher";
import {
  TemplateCategory,
  CATEGORY_META,
  TemplatePriority,
} from "@/data/policy-templates";
import { ScoreRing, Card } from "./ui-primitives";
import {
  CheckCircle2,
  AlertCircle,
  XCircle,
  ChevronDown,
  ChevronRight,
  Download,
  ExternalLink,
  Filter,
} from "lucide-react";
import { cn } from "@/lib/utils";

// ─── Props ───────────────────────────────────────────────────────────────────

interface TemplatesViewProps {
  result: TemplateAnalysisResult;
}

// ─── Status Badge ────────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: MatchStatus }) {
  const map: Record<
    MatchStatus,
    { label: string; color: string; Icon: typeof CheckCircle2 }
  > = {
    present: { label: "Present", color: "text-emerald-400 bg-emerald-400/10", Icon: CheckCircle2 },
    partial: { label: "Partial", color: "text-amber-400 bg-amber-400/10", Icon: AlertCircle },
    missing: { label: "Missing", color: "text-red-400 bg-red-400/10", Icon: XCircle },
  };
  const { label, color, Icon } = map[status];
  return (
    <span className={cn("inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium", color)}>
      <Icon className="h-3.5 w-3.5" />
      {label}
    </span>
  );
}

function PriorityBadge({ priority }: { priority: TemplatePriority }) {
  const colors: Record<TemplatePriority, string> = {
    critical: "text-red-300 bg-red-400/10",
    recommended: "text-blue-300 bg-blue-400/10",
    optional: "text-gray-400 bg-gray-400/10",
  };
  return (
    <span className={cn("rounded-full px-2 py-0.5 text-xs font-medium", colors[priority])}>
      {priority}
    </span>
  );
}

// ─── Template Card ───────────────────────────────────────────────────────────

function TemplateCard({ match }: { match: TemplateMatch }) {
  const [expanded, setExpanded] = useState(false);
  const t = match.template;

  const handleExport = () => {
    const json = JSON.stringify(t.deploymentJson, null, 2);
    const blob = new Blob([json], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${t.id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div
      className={cn(
        "rounded-lg border bg-gray-900 transition-colors",
        match.status === "present"
          ? "border-emerald-800/50"
          : match.status === "partial"
            ? "border-amber-800/50"
            : "border-gray-800"
      )}
    >
      {/* Header */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex w-full items-center justify-between gap-3 p-4 text-left"
      >
        <div className="flex items-center gap-3 min-w-0">
          {expanded ? (
            <ChevronDown className="h-4 w-4 shrink-0 text-gray-500" />
          ) : (
            <ChevronRight className="h-4 w-4 shrink-0 text-gray-500" />
          )}
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <h4 className="text-sm font-semibold text-white truncate">
                {t.displayName}
              </h4>
              <PriorityBadge priority={t.priority} />
            </div>
            <p className="text-xs text-gray-500 mt-0.5">{t.summary}</p>
          </div>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          {match.confidence > 0 && (
            <span className="text-xs text-gray-500">
              {match.confidence}% match
            </span>
          )}
          <StatusBadge status={match.status} />
        </div>
      </button>

      {/* Expanded Content */}
      {expanded && (
        <div className="border-t border-gray-800 p-4 space-y-4">
          {/* Rationale */}
          <div>
            <h5 className="text-xs font-medium text-gray-400 uppercase mb-1">
              Why this matters
            </h5>
            <p className="text-sm text-gray-300">{t.rationale}</p>
          </div>

          {/* CIS Mapping */}
          {t.cisControls && t.cisControls.length > 0 && (
            <div>
              <h5 className="text-xs font-medium text-gray-400 uppercase mb-1">
                CIS Controls
              </h5>
              <div className="flex gap-2 flex-wrap">
                {t.cisControls.map((c) => (
                  <span
                    key={c}
                    className="rounded bg-indigo-400/10 px-2 py-0.5 text-xs text-indigo-300 font-mono"
                  >
                    CIS {c}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Matching Policies */}
          {match.matchingPolicies.length > 0 && (
            <div>
              <h5 className="text-xs font-medium text-gray-400 uppercase mb-1">
                Matching Tenant Policies
              </h5>
              <div className="space-y-1">
                {match.matchingPolicies.map((mp) => (
                  <div
                    key={mp.policy.id}
                    className="flex items-center justify-between rounded bg-gray-800 px-3 py-2 text-sm"
                  >
                    <span className="text-gray-300 truncate">
                      {mp.policy.displayName}
                    </span>
                    <span
                      className={cn(
                        "text-xs font-mono",
                        mp.similarity >= 85
                          ? "text-emerald-400"
                          : mp.similarity >= 60
                            ? "text-amber-400"
                            : "text-gray-500"
                      )}
                    >
                      {mp.similarity}%
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Differences */}
          {match.differences.length > 0 && (
            <div>
              <h5 className="text-xs font-medium text-gray-400 uppercase mb-1">
                Differences
              </h5>
              <ul className="space-y-1 text-xs text-gray-400">
                {match.differences.map((d, i) => (
                  <li key={i} className="flex gap-2">
                    <span className="text-amber-400">•</span>
                    {d}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Actions */}
          <div className="flex gap-2 pt-2">
            <button
              onClick={handleExport}
              className="flex items-center gap-1.5 rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:bg-gray-800 transition-colors"
            >
              <Download className="h-3.5 w-3.5" />
              Download JSON
            </button>
            <a
              href="https://github.com/Jhope188/ConditionalAccessPolicies"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1.5 rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:bg-gray-800 transition-colors"
            >
              <ExternalLink className="h-3.5 w-3.5" />
              View Repo
            </a>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Category Section ────────────────────────────────────────────────────────

function CategorySection({
  category,
  matches,
  score,
}: {
  category: TemplateCategory;
  matches: TemplateMatch[];
  score: number;
}) {
  const meta = CATEGORY_META[category];
  const [collapsed, setCollapsed] = useState(false);

  const present = matches.filter((m) => m.status === "present").length;
  const partial = matches.filter((m) => m.status === "partial").length;
  const missing = matches.filter((m) => m.status === "missing").length;

  return (
    <div className="space-y-3">
      <button
        onClick={() => setCollapsed(!collapsed)}
        className="flex w-full items-center justify-between"
      >
        <div className="flex items-center gap-2">
          <span className="text-lg">{meta.icon}</span>
          <h3 className="text-base font-semibold text-white">{meta.label}</h3>
          <span className="text-xs text-gray-500">
            {present}/{matches.length} present
          </span>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex gap-1.5 text-xs">
            {present > 0 && (
              <span className="text-emerald-400">{present}✓</span>
            )}
            {partial > 0 && (
              <span className="text-amber-400">{partial}~</span>
            )}
            {missing > 0 && (
              <span className="text-red-400">{missing}✗</span>
            )}
          </div>
          <div
            className={cn(
              "h-2 w-16 rounded-full bg-gray-800 overflow-hidden"
            )}
          >
            <div
              className={cn(
                "h-full rounded-full transition-all",
                score >= 80
                  ? "bg-emerald-500"
                  : score >= 50
                    ? "bg-amber-500"
                    : "bg-red-500"
              )}
              style={{ width: `${score}%` }}
            />
          </div>
          {collapsed ? (
            <ChevronRight className="h-4 w-4 text-gray-500" />
          ) : (
            <ChevronDown className="h-4 w-4 text-gray-500" />
          )}
        </div>
      </button>
      <p className="text-xs text-gray-500 -mt-1">{meta.description}</p>

      {!collapsed && (
        <div className="space-y-2">
          {matches.map((match) => (
            <TemplateCard key={match.template.id} match={match} />
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Main View ───────────────────────────────────────────────────────────────

export function TemplatesView({ result }: TemplatesViewProps) {
  const [statusFilter, setStatusFilter] = useState<MatchStatus | "all">("all");

  const filteredMatches =
    statusFilter === "all"
      ? result.matches
      : result.matches.filter((m) => m.status === statusFilter);

  // Group by category
  const categories = [
    ...new Set(result.matches.map((m) => m.template.category)),
  ] as TemplateCategory[];

  const categoryOrder: TemplateCategory[] = [
    "foundation",
    "baseline",
    "app-specific",
    "intune",
    "p2",
    "ztca",
    "agent",
  ];
  categories.sort(
    (a, b) => categoryOrder.indexOf(a) - categoryOrder.indexOf(b)
  );

  const handleExportAll = () => {
    const missingTemplates = result.matches
      .filter((m) => m.status === "missing")
      .map((m) => m.template.deploymentJson);
    const blob = new Blob([JSON.stringify(missingTemplates, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `missing-policy-templates-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Summary Header */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
        <Card className="flex flex-col items-center justify-center p-6 sm:col-span-2">
          <ScoreRing score={result.coverageScore} />
          <p className="mt-3 text-sm text-gray-400">Template Coverage</p>
          <p className="text-xs text-gray-600">
            Based on {result.totalTemplates} recommended policies
          </p>
        </Card>

        <Card className="flex flex-col items-center justify-center p-4">
          <div className="text-3xl font-bold text-emerald-400">
            {result.presentCount}
          </div>
          <div className="text-xs text-gray-400 mt-1">Present</div>
        </Card>
        <Card className="flex flex-col items-center justify-center p-4">
          <div className="text-3xl font-bold text-amber-400">
            {result.partialCount}
          </div>
          <div className="text-xs text-gray-400 mt-1">Partial</div>
        </Card>
        <Card className="flex flex-col items-center justify-center p-4">
          <div className="text-3xl font-bold text-red-400">
            {result.missingCount}
          </div>
          <div className="text-xs text-gray-400 mt-1">Missing</div>
        </Card>
      </div>

      {/* Source Attribution */}
      <div className="flex items-center justify-between rounded-lg border border-gray-800 bg-gray-900 px-4 py-3">
        <div className="flex items-center gap-2 text-sm text-gray-400">
          <span>📋</span>
          Templates from{" "}
          <a
            href="https://github.com/Jhope188/ConditionalAccessPolicies"
            target="_blank"
            rel="noopener noreferrer"
            className="text-blue-400 hover:text-blue-300 underline"
          >
            Jhope188/ConditionalAccessPolicies
          </a>
        </div>
        <div className="flex gap-2">
          <button
            onClick={handleExportAll}
            disabled={result.missingCount === 0}
            className={cn(
              "flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs transition-colors",
              result.missingCount > 0
                ? "border border-gray-700 text-gray-300 hover:bg-gray-800"
                : "text-gray-600 cursor-not-allowed"
            )}
          >
            <Download className="h-3.5 w-3.5" />
            Export Missing ({result.missingCount})
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-2">
        <Filter className="h-4 w-4 text-gray-500" />
        {(["all", "missing", "partial", "present"] as const).map((f) => (
          <button
            key={f}
            onClick={() => setStatusFilter(f)}
            className={cn(
              "rounded-md px-3 py-1.5 text-xs font-medium transition-colors",
              statusFilter === f
                ? "bg-gray-700 text-white"
                : "text-gray-400 hover:text-white"
            )}
          >
            {f === "all" ? "All" : f.charAt(0).toUpperCase() + f.slice(1)}
            {f !== "all" && (
              <span className="ml-1 text-gray-500">
                (
                {f === "missing"
                  ? result.missingCount
                  : f === "partial"
                    ? result.partialCount
                    : result.presentCount}
                )
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Category Sections */}
      <div className="space-y-8">
        {categories.map((cat) => {
          const catMatches = filteredMatches.filter(
            (m) => m.template.category === cat
          );
          if (catMatches.length === 0) return null;
          return (
            <CategorySection
              key={cat}
              category={cat}
              matches={catMatches}
              score={result.byCategoryScore[cat] ?? 0}
            />
          );
        })}
      </div>
    </div>
  );
}
