"use client";

import { PolicyResult } from "@/lib/analyzer";
import { SeverityBadge, Card } from "./ui-primitives";
import { cn } from "@/lib/utils";
import {
  Users,
  Cloud,
  Filter,
  ShieldCheck,
  Clock,
  ChevronDown,
  ChevronRight,
  AlertCircle,
} from "lucide-react";
import { useState } from "react";

function PolicyFlowSection({
  icon: Icon,
  label,
  items,
  emptyText = "None",
}: {
  icon: typeof Users;
  label: string;
  items: string[];
  emptyText?: string;
}) {
  return (
    <div className="flex items-start gap-2">
      <Icon className="mt-0.5 h-4 w-4 shrink-0 text-gray-500" />
      <div>
        <p className="text-xs font-medium text-gray-400">{label}</p>
        {items.length > 0 ? (
          <ul className="mt-0.5">
            {items.map((item, i) => (
              <li key={i} className="text-sm text-gray-300">
                {item}
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-gray-600">{emptyText}</p>
        )}
      </div>
    </div>
  );
}

function PolicyCard({ result }: { result: PolicyResult }) {
  const [expanded, setExpanded] = useState(false);
  const { policy, visualization, findings } = result;

  const hasCritical = findings.some((f) => f.severity === "critical");
  const hasHigh = findings.some((f) => f.severity === "high");

  return (
    <div
      className={cn(
        "rounded-xl border transition-colors",
        hasCritical
          ? "border-red-500/30 bg-red-500/5"
          : hasHigh
          ? "border-orange-500/20 bg-orange-500/5"
          : "border-gray-800 bg-gray-900"
      )}
    >
      {/* Header */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex w-full items-center gap-3 p-4 text-left"
      >
        <div>
          {expanded ? (
            <ChevronDown className="h-5 w-5 text-gray-500" />
          ) : (
            <ChevronRight className="h-5 w-5 text-gray-500" />
          )}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span
              className={cn(
                "text-xs font-medium rounded px-1.5 py-0.5",
                policy.state === "enabled"
                  ? "bg-green-500/10 text-green-400"
                  : policy.state === "enabledForReportingButNotEnforced"
                  ? "bg-yellow-500/10 text-yellow-400"
                  : "bg-gray-800 text-gray-500"
              )}
            >
              {visualization.state}
            </span>
            <h3 className="text-sm font-semibold text-white truncate">
              {policy.displayName}
            </h3>
          </div>
          <div className="mt-1 flex flex-wrap gap-3 text-xs text-gray-500">
            <span>{visualization.targetUsers}</span>
            <span>→</span>
            <span>{visualization.targetApps}</span>
            <span>→</span>
            <span>
              {visualization.grantControls.length > 0
                ? visualization.grantControls.join(", ")
                : "No grant controls"}
            </span>
          </div>
        </div>
        {findings.length > 0 && (
          <div className="flex items-center gap-1.5 shrink-0">
            <AlertCircle
              className={cn(
                "h-4 w-4",
                hasCritical
                  ? "text-red-400"
                  : hasHigh
                  ? "text-orange-400"
                  : "text-yellow-400"
              )}
            />
            <span className="text-xs text-gray-400">
              {findings.length} finding{findings.length !== 1 ? "s" : ""}
            </span>
          </div>
        )}
      </button>

      {/* Expanded Detail */}
      {expanded && (
        <div className="border-t border-gray-800 p-4">
          {/* Flow Visualization */}
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
            <PolicyFlowSection
              icon={Users}
              label="Users"
              items={[visualization.targetUsers]}
            />
            <PolicyFlowSection
              icon={Cloud}
              label="Cloud Apps"
              items={[visualization.targetApps]}
            />
            <PolicyFlowSection
              icon={Filter}
              label="Conditions"
              items={visualization.conditions}
              emptyText="No conditions"
            />
            <PolicyFlowSection
              icon={ShieldCheck}
              label="Grant Controls"
              items={visualization.grantControls}
              emptyText="No grant controls"
            />
            <PolicyFlowSection
              icon={Clock}
              label="Session Controls"
              items={visualization.sessionControls}
              emptyText="No session controls"
            />
          </div>

          {/* Policy Findings */}
          {findings.length > 0 && (
            <div className="mt-4 space-y-2">
              <h4 className="text-xs font-medium text-gray-500 uppercase tracking-wider">
                Findings for this policy
              </h4>
              {findings.map((f) => (
                <div
                  key={f.id}
                  className="flex items-start gap-2 rounded-lg bg-gray-950/50 p-3"
                >
                  <SeverityBadge severity={f.severity} />
                  <div className="min-w-0">
                    <p className="text-sm text-gray-300">{f.title}</p>
                    <p className="mt-0.5 text-xs text-gray-500 line-clamp-2">
                      {f.description}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Raw Policy ID */}
          <p className="mt-3 text-xs text-gray-700 font-mono">
            ID: {policy.id}
          </p>
        </div>
      )}
    </div>
  );
}

/** Detect Microsoft-managed / built-in policies */
function isMicrosoftManaged(result: PolicyResult): boolean {
  const p = result.policy;
  // Graph sets templateId on Microsoft-managed policies
  if (p.templateId && p.templateId !== "00000000-0000-0000-0000-000000000000") return true;
  // Fallback: naming convention
  const name = p.displayName.toLowerCase();
  return name.startsWith("microsoft-managed") || name.startsWith("[microsoft");
}

export function PolicyList({ results }: { results: PolicyResult[] }) {
  const [sortBy, setSortBy] = useState<"findings" | "name" | "state">("findings");
  const [hideMicrosoft, setHideMicrosoft] = useState(false);

  const microsoftCount = results.filter(isMicrosoftManaged).length;

  const filtered = hideMicrosoft
    ? results.filter((r) => !isMicrosoftManaged(r))
    : results;

  const sorted = [...filtered].sort((a, b) => {
    switch (sortBy) {
      case "findings":
        return b.findings.length - a.findings.length;
      case "name":
        return a.policy.displayName.localeCompare(b.policy.displayName);
      case "state":
        return a.policy.state.localeCompare(b.policy.state);
      default:
        return 0;
    }
  });

  return (
    <Card>
      <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
        <h3 className="text-lg font-semibold text-white">
          Policies{" "}
          <span className="text-gray-500 font-normal">
            ({filtered.length}{hideMicrosoft ? ` of ${results.length}` : ""})
          </span>
        </h3>
        <div className="flex flex-wrap items-center gap-2">
          {/* Hide Microsoft-managed toggle */}
          {microsoftCount > 0 && (
            <button
              onClick={() => setHideMicrosoft(!hideMicrosoft)}
              className={cn(
                "rounded-lg px-3 py-1.5 text-xs font-medium transition-colors",
                hideMicrosoft
                  ? "bg-purple-600 text-white"
                  : "bg-gray-800 text-gray-400 hover:text-white"
              )}
            >
              {hideMicrosoft ? `Show Microsoft (${microsoftCount})` : "Hide Microsoft"}
            </button>
          )}

          {/* Sort buttons */}
          <div className="flex gap-1">
            {(["findings", "name", "state"] as const).map((s) => (
              <button
                key={s}
                onClick={() => setSortBy(s)}
                className={cn(
                  "rounded-lg px-3 py-1.5 text-xs font-medium capitalize transition-colors",
                  sortBy === s
                    ? "bg-blue-600 text-white"
                    : "bg-gray-800 text-gray-400 hover:text-white"
                )}
              >
                {s === "findings" ? "Most Findings" : s}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="space-y-2">
        {sorted.map((result) => (
          <PolicyCard key={result.policy.id} result={result} />
        ))}
        {sorted.length === 0 && (
          <p className="py-8 text-center text-sm text-gray-500">
            No policies to display.
          </p>
        )}
      </div>
    </Card>
  );
}
