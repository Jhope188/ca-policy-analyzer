"use client";

import { Finding, ExcludedAppDetail } from "@/lib/analyzer";
import { SeverityBadge, Card } from "./ui-primitives";
import { ChevronDown, ChevronRight, Lightbulb, ShieldAlert } from "lucide-react";
import { useState } from "react";
import { cn } from "@/lib/utils";

function ExcludedAppBadge({ risk }: { risk: string }) {
  const colors: Record<string, string> = {
    critical: "bg-red-500/10 text-red-400",
    high: "bg-orange-500/10 text-orange-400",
    medium: "bg-yellow-500/10 text-yellow-400",
    low: "bg-gray-800 text-gray-400",
  };
  return (
    <span className={cn("text-[10px] font-medium rounded px-1.5 py-0.5 uppercase", colors[risk] ?? colors.low)}>
      {risk}
    </span>
  );
}

function ExcludedAppRow({ app }: { app: ExcludedAppDetail }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="rounded-md border border-gray-800 bg-gray-900/60">
      <button
        onClick={() => setOpen(!open)}
        className="flex w-full items-center gap-2 p-2.5 text-left hover:bg-gray-800/30 transition-colors"
      >
        {open ? (
          <ChevronDown className="h-3 w-3 text-gray-600 shrink-0" />
        ) : (
          <ChevronRight className="h-3 w-3 text-gray-600 shrink-0" />
        )}
        <span className="text-xs font-medium text-gray-300 flex-1 truncate">{app.displayName}</span>
        <ExcludedAppBadge risk={app.risk} />
      </button>
      {open && (
        <div className="border-t border-gray-800/50 p-2.5 space-y-1.5">
          <div>
            <span className="text-[10px] font-medium uppercase text-gray-600">What it does</span>
            <p className="text-xs text-gray-400">{app.purpose}</p>
          </div>
          <div>
            <span className="text-[10px] font-medium uppercase text-gray-600">Why it&apos;s excluded</span>
            <p className="text-xs text-gray-400">{app.exclusionReason}</p>
          </div>
          <p className="text-[10px] text-gray-700 font-mono">{app.appId}</p>
        </div>
      )}
    </div>
  );
}

export function FindingCard({ finding }: { finding: Finding }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div
      className={cn(
        "rounded-lg border border-gray-800 bg-gray-900/50 transition-colors hover:border-gray-700",
        finding.severity === "critical" && "border-red-500/30 hover:border-red-500/50",
        finding.severity === "high" && "border-orange-500/20 hover:border-orange-500/40"
      )}
    >
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex w-full items-start gap-3 p-4 text-left"
      >
        <div className="mt-0.5">
          {expanded ? (
            <ChevronDown className="h-4 w-4 text-gray-500" />
          ) : (
            <ChevronRight className="h-4 w-4 text-gray-500" />
          )}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2 mb-1">
            <SeverityBadge severity={finding.severity} />
            <span className="text-xs text-gray-600 font-mono">{finding.id}</span>
            <span className="rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-400">
              {finding.category}
            </span>
          </div>
          <h4 className="text-sm font-medium text-gray-200">{finding.title}</h4>
          {!expanded && (
            <p className="mt-1 text-xs text-gray-500 line-clamp-1">
              {finding.description}
            </p>
          )}
        </div>
      </button>

      {expanded && (
        <div className="border-t border-gray-800 px-4 pb-4 pt-3 ml-7">
          <p className="text-sm text-gray-400 leading-relaxed">
            {finding.description}
          </p>
          <div className="mt-3 flex items-start gap-2 rounded-lg bg-blue-500/5 border border-blue-500/20 p-3">
            <Lightbulb className="mt-0.5 h-4 w-4 shrink-0 text-blue-400" />
            <p className="text-sm text-blue-300">{finding.recommendation}</p>
          </div>
          {/* Excluded app details */}
          {finding.excludedApps && finding.excludedApps.length > 0 && (
            <div className="mt-3 space-y-2">
              <div className="flex items-center gap-1.5">
                <ShieldAlert className="h-3.5 w-3.5 text-gray-500" />
                <span className="text-xs font-medium text-gray-500 uppercase">
                  Excluded apps ({finding.excludedApps.length})
                </span>
              </div>
              <div className="space-y-1">
                {finding.excludedApps.map((app) => (
                  <ExcludedAppRow key={app.appId} app={app} />
                ))}
              </div>
            </div>
          )}
          {finding.policyName !== "Tenant-Wide Analysis" && (
            <p className="mt-2 text-xs text-gray-600">
              Policy: {finding.policyName}
            </p>
          )}
        </div>
      )}
    </div>
  );
}

export function FindingsList({
  findings,
  title,
}: {
  findings: Finding[];
  title?: string;
}) {
  const [filter, setFilter] = useState<string>("all");

  const filtered =
    filter === "all"
      ? findings
      : findings.filter((f) => f.severity === filter);

  const severityCounts = {
    critical: findings.filter((f) => f.severity === "critical").length,
    high: findings.filter((f) => f.severity === "high").length,
    medium: findings.filter((f) => f.severity === "medium").length,
    low: findings.filter((f) => f.severity === "low").length,
    info: findings.filter((f) => f.severity === "info").length,
  };

  return (
    <Card>
      <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
        <h3 className="text-lg font-semibold text-white">
          {title ?? "Findings"}{" "}
          <span className="text-gray-500 font-normal">({filtered.length})</span>
        </h3>
        <div className="flex gap-1">
          {[
            { key: "all", label: "All" },
            { key: "critical", label: `Critical (${severityCounts.critical})` },
            { key: "high", label: `High (${severityCounts.high})` },
            { key: "medium", label: `Medium (${severityCounts.medium})` },
            { key: "low", label: `Low (${severityCounts.low})` },
            { key: "info", label: `Info (${severityCounts.info})` },
          ]
            .filter((f) => f.key === "all" || severityCounts[f.key as keyof typeof severityCounts] > 0)
            .map((f) => (
              <button
                key={f.key}
                onClick={() => setFilter(f.key)}
                className={cn(
                  "rounded-lg px-3 py-1.5 text-xs font-medium transition-colors",
                  filter === f.key
                    ? "bg-blue-600 text-white"
                    : "bg-gray-800 text-gray-400 hover:text-white"
                )}
              >
                {f.label}
              </button>
            ))}
        </div>
      </div>

      {filtered.length === 0 ? (
        <p className="py-8 text-center text-sm text-gray-600">
          No findings match the selected filter.
        </p>
      ) : (
        <div className="space-y-2">
          {filtered.map((finding) => (
            <FindingCard key={finding.id} finding={finding} />
          ))}
        </div>
      )}
    </Card>
  );
}
