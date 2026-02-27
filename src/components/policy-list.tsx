"use client";

import { PolicyResult, Finding, ExcludedAppDetail } from "@/lib/analyzer";
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
  Info,
  ShieldAlert,
  Search,
  X,
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

// ─── Risk badge for excluded app details ─────────────────────────────────────

function RiskBadge({ risk }: { risk: string }) {
  const colors: Record<string, string> = {
    critical: "bg-red-500/10 text-red-400",
    high: "bg-orange-500/10 text-orange-400",
    medium: "bg-yellow-500/10 text-yellow-400",
    low: "bg-gray-800 text-gray-400",
  };
  return (
    <span className={cn("text-[10px] font-medium rounded px-1.5 py-0.5 uppercase", colors[risk] ?? colors.low)}>
      {risk} risk
    </span>
  );
}

// ─── Single excluded app detail card ─────────────────────────────────────────

function ExcludedAppCard({ app }: { app: ExcludedAppDetail }) {
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-900/50 p-3 space-y-1.5">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm font-medium text-white">{app.displayName}</span>
        <RiskBadge risk={app.risk} />
      </div>
      <div className="space-y-1">
        <div>
          <span className="text-[10px] font-medium uppercase text-gray-600">What it does</span>
          <p className="text-xs text-gray-400">{app.purpose}</p>
        </div>
        <div>
          <span className="text-[10px] font-medium uppercase text-gray-600">Why it&apos;s excluded</span>
          <p className="text-xs text-gray-400">{app.exclusionReason}</p>
        </div>
      </div>
      <p className="text-[10px] text-gray-700 font-mono">{app.appId}</p>
    </div>
  );
}

// ─── Collapsible finding row ─────────────────────────────────────────────────

function FindingRow({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  const hasDetails = finding.excludedApps && finding.excludedApps.length > 0;

  return (
    <div className="rounded-lg bg-gray-950/50 overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="flex w-full items-start gap-2 p-3 text-left hover:bg-gray-950/80 transition-colors"
      >
        <SeverityBadge severity={finding.severity} />
        <div className="flex-1 min-w-0">
          <p className="text-sm text-gray-300">{finding.title}</p>
          {!open && (
            <p className="mt-0.5 text-xs text-gray-500 line-clamp-2">
              {finding.description}
            </p>
          )}
        </div>
        <div className="shrink-0 mt-0.5">
          {open ? (
            <ChevronDown className="h-4 w-4 text-gray-600" />
          ) : (
            <ChevronRight className="h-4 w-4 text-gray-600" />
          )}
        </div>
      </button>

      {open && (
        <div className="border-t border-gray-800/50 p-3 space-y-3">
          <p className="text-xs text-gray-400">{finding.description}</p>

          {/* Recommendation */}
          <div className="flex items-start gap-2 rounded-md bg-blue-500/5 border border-blue-500/10 p-2">
            <Info className="h-3.5 w-3.5 shrink-0 mt-0.5 text-blue-400" />
            <p className="text-xs text-blue-300">{finding.recommendation}</p>
          </div>

          {/* Excluded app details with per-app descriptions */}
          {hasDetails && (
            <div className="space-y-2">
              <div className="flex items-center gap-1.5">
                <ShieldAlert className="h-3.5 w-3.5 text-gray-500" />
                <span className="text-[10px] font-medium uppercase text-gray-500">
                  Excluded apps ({finding.excludedApps!.length})
                </span>
              </div>
              <div className="grid gap-2 sm:grid-cols-2">
                {finding.excludedApps!.map((app) => (
                  <ExcludedAppCard key={app.appId} app={app} />
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Group findings by severity ──────────────────────────────────────────────

type SeverityGroup = { severity: string; label: string; findings: Finding[]; color: string };

function FindingsGrouped({ findings }: { findings: Finding[] }) {
  const [openGroups, setOpenGroups] = useState<Set<string>>(new Set(["critical", "high"]));

  const groups: SeverityGroup[] = [
    { severity: "critical", label: "Critical", findings: [], color: "text-red-400" },
    { severity: "high", label: "High", findings: [], color: "text-orange-400" },
    { severity: "medium", label: "Medium", findings: [], color: "text-yellow-400" },
    { severity: "low", label: "Low", findings: [], color: "text-gray-400" },
    { severity: "info", label: "Info", findings: [], color: "text-blue-400" },
  ];

  for (const f of findings) {
    const g = groups.find((g) => g.severity === f.severity);
    if (g) g.findings.push(f);
  }

  const nonEmpty = groups.filter((g) => g.findings.length > 0);

  // If 3 or fewer total findings, just show them flat (no grouping needed)
  if (findings.length <= 3) {
    return (
      <div className="space-y-2">
        {findings.map((f) => (
          <FindingRow key={f.id} finding={f} />
        ))}
      </div>
    );
  }

  const toggle = (sev: string) => {
    setOpenGroups((prev) => {
      const next = new Set(prev);
      if (next.has(sev)) next.delete(sev);
      else next.add(sev);
      return next;
    });
  };

  return (
    <div className="space-y-1.5">
      {nonEmpty.map((g) => (
        <div key={g.severity}>
          <button
            onClick={() => toggle(g.severity)}
            className="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left hover:bg-gray-950/50 transition-colors"
          >
            {openGroups.has(g.severity) ? (
              <ChevronDown className="h-3.5 w-3.5 text-gray-600" />
            ) : (
              <ChevronRight className="h-3.5 w-3.5 text-gray-600" />
            )}
            <span className={cn("text-xs font-medium", g.color)}>
              {g.label}
            </span>
            <span className="text-xs text-gray-600">
              ({g.findings.length})
            </span>
          </button>
          {openGroups.has(g.severity) && (
            <div className="ml-2 space-y-1.5 mt-1">
              {g.findings.map((f) => (
                <FindingRow key={f.id} finding={f} />
              ))}
            </div>
          )}
        </div>
      ))}
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

{/* Policy Findings — grouped by severity with dropdowns */}
            {findings.length > 0 && (
              <div className="mt-4 space-y-2">
                <h4 className="text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Findings for this policy
                </h4>
                <FindingsGrouped findings={findings} />
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
  const [search, setSearch] = useState("");

  const microsoftCount = results.filter(isMicrosoftManaged).length;

  const filtered = results.filter((r) => {
    if (hideMicrosoft && isMicrosoftManaged(r)) return false;
    if (search.trim()) {
      const q = search.toLowerCase();
      const p = r.policy;
      const v = r.visualization;
      return (
        p.displayName.toLowerCase().includes(q) ||
        p.id.toLowerCase().includes(q) ||
        v.targetUsers.toLowerCase().includes(q) ||
        v.targetApps.toLowerCase().includes(q) ||
        v.grantControls.some((c) => c.toLowerCase().includes(q)) ||
        v.conditions.some((c) => c.toLowerCase().includes(q)) ||
        p.state.toLowerCase().includes(q)
      );
    }
    return true;
  });

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
            ({filtered.length}{hideMicrosoft || search ? ` of ${results.length}` : ""})
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

      {/* Search */}
      <div className="relative mb-4">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-500" />
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search policies by name, state, users, apps, controls…"
          className="w-full rounded-lg border border-gray-800 bg-gray-950 py-2 pl-9 pr-9 text-sm text-gray-300 placeholder:text-gray-600 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500 transition-colors"
        />
        {search && (
          <button
            onClick={() => setSearch("")}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
          >
            <X className="h-4 w-4" />
          </button>
        )}
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
