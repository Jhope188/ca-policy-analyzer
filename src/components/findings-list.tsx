"use client";

import { Finding, ExcludedAppDetail, Severity } from "@/lib/analyzer";
import { SeverityBadge, Card } from "./ui-primitives";
import {
  ChevronDown,
  ChevronRight,
  Lightbulb,
  ShieldAlert,
  AlertTriangle,
  Shield,
  Info,
  Layers,
} from "lucide-react";
import { useState, useMemo } from "react";
import { cn } from "@/lib/utils";

// ─── Severity helpers ────────────────────────────────────────────────────────

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

// ─── Category metadata ──────────────────────────────────────────────────────

const CATEGORY_META: Record<string, { icon: React.ElementType; color: string }> = {
  "FOCI Token Sharing": { icon: AlertTriangle, color: "text-red-400" },
  "Resource Exclusion Bypass": { icon: ShieldAlert, color: "text-orange-400" },
  "CA-Immune Resources": { icon: Info, color: "text-blue-400" },
  "Swiss Cheese Model": { icon: Layers, color: "text-orange-400" },
  "Device Registration Bypass": { icon: ShieldAlert, color: "text-orange-400" },
  "App Exclusion": { icon: Shield, color: "text-yellow-400" },
  "Policy Scope": { icon: Shield, color: "text-yellow-400" },
  "Policy State": { icon: Info, color: "text-blue-400" },
  "Resilience": { icon: AlertTriangle, color: "text-yellow-400" },
  "Location Configuration": { icon: Info, color: "text-gray-400" },
  "Legacy Authentication": { icon: AlertTriangle, color: "text-orange-400" },
  "MFA Coverage": { icon: ShieldAlert, color: "text-red-400" },
  "Legacy Auth": { icon: AlertTriangle, color: "text-red-400" },
  "Break-Glass": { icon: Info, color: "text-blue-400" },
  "MS Learn: Documented Exclusion": { icon: ShieldAlert, color: "text-orange-400" },
  "Privileged Role Exclusion": { icon: ShieldAlert, color: "text-red-400" },
  "Guest/External User Exclusion": { icon: AlertTriangle, color: "text-orange-400" },
  "Guest/External User Coverage": { icon: ShieldAlert, color: "text-orange-400" },
  "User-Agent Bypass": { icon: AlertTriangle, color: "text-orange-400" },
  "Microsoft-Managed Policies": { icon: Info, color: "text-blue-400" },
  "Credential Registration Constraints": { icon: ShieldAlert, color: "text-orange-400" },
  "Guest Authentication Requirements": { icon: AlertTriangle, color: "text-orange-400" },
  "Protected Actions Configuration": { icon: Shield, color: "text-purple-400" },
  "Identity Protection": { icon: ShieldAlert, color: "text-red-400" },
  "Application Coverage": { icon: ShieldAlert, color: "text-red-400" },
};

// ─── Deduplicated finding group ─────────────────────────────────────────────

interface FindingGroup {
  key: string;
  title: string;
  category: string;
  severity: Severity;
  description: string;
  recommendation: string;
  findings: Finding[];
  policyNames: string[];
  excludedApps: ExcludedAppDetail[];
}

function groupFindings(findings: Finding[]): FindingGroup[] {
  const map = new Map<string, FindingGroup>();

  for (const f of findings) {
    const key = `${f.category}::${f.title}`;
    const existing = map.get(key);

    if (existing) {
      existing.findings.push(f);
      if (
        f.policyName &&
        f.policyName !== "Tenant-Wide Analysis" &&
        !existing.policyNames.includes(f.policyName)
      ) {
        existing.policyNames.push(f.policyName);
      }
      if (f.excludedApps) {
        for (const app of f.excludedApps) {
          if (!existing.excludedApps.some((a) => a.appId === app.appId)) {
            existing.excludedApps.push(app);
          }
        }
      }
      if ((SEVERITY_ORDER[f.severity] ?? 4) < (SEVERITY_ORDER[existing.severity] ?? 4)) {
        existing.severity = f.severity;
      }
    } else {
      map.set(key, {
        key,
        title: f.title,
        category: f.category,
        severity: f.severity,
        description: f.description,
        recommendation: f.recommendation,
        findings: [f],
        policyNames:
          f.policyName && f.policyName !== "Tenant-Wide Analysis"
            ? [f.policyName]
            : [],
        excludedApps: f.excludedApps ? [...f.excludedApps] : [],
      });
    }
  }

  return [...map.values()].sort(
    (a, b) => (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4)
  );
}

// ─── Category grouping ──────────────────────────────────────────────────────

interface CategoryGroup {
  category: string;
  severity: Severity;
  groups: FindingGroup[];
  totalFindings: number;
}

function groupByCategory(findingGroups: FindingGroup[]): CategoryGroup[] {
  const map = new Map<string, CategoryGroup>();

  for (const g of findingGroups) {
    const existing = map.get(g.category);
    if (existing) {
      existing.groups.push(g);
      existing.totalFindings += g.findings.length;
      if ((SEVERITY_ORDER[g.severity] ?? 4) < (SEVERITY_ORDER[existing.severity] ?? 4)) {
        existing.severity = g.severity;
      }
    } else {
      map.set(g.category, {
        category: g.category,
        severity: g.severity,
        groups: [g],
        totalFindings: g.findings.length,
      });
    }
  }

  return [...map.values()].sort(
    (a, b) => (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4)
  );
}

// ─── Excluded app components ────────────────────────────────────────────────

function ExcludedAppBadge({ risk }: { risk: string }) {
  const colors: Record<string, string> = {
    critical: "bg-red-500/10 text-red-400",
    high: "bg-orange-500/10 text-orange-400",
    medium: "bg-yellow-500/10 text-yellow-400",
    low: "bg-gray-800 text-gray-400",
  };
  return (
    <span
      className={cn(
        "text-[10px] font-medium rounded px-1.5 py-0.5 uppercase",
        colors[risk] ?? colors.low
      )}
    >
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
        <span className="text-xs font-medium text-gray-300 flex-1 truncate">
          {app.displayName}
        </span>
        <ExcludedAppBadge risk={app.risk} />
      </button>
      {open && (
        <div className="border-t border-gray-800/50 p-2.5 space-y-1.5">
          <div>
            <span className="text-[10px] font-medium uppercase text-gray-600">
              What it does
            </span>
            <p className="text-xs text-gray-400">{app.purpose}</p>
          </div>
          <div>
            <span className="text-[10px] font-medium uppercase text-gray-600">
              Why it&apos;s excluded
            </span>
            <p className="text-xs text-gray-400">{app.exclusionReason}</p>
          </div>
          <p className="text-[10px] text-gray-700 font-mono">{app.appId}</p>
        </div>
      )}
    </div>
  );
}

// ─── Finding group card ─────────────────────────────────────────────────────

function FindingGroupCard({ group }: { group: FindingGroup }) {
  const [expanded, setExpanded] = useState(false);
  const isTenantWide = group.policyNames.length === 0;
  const policyCount = group.policyNames.length;

  return (
    <div
      className={cn(
        "rounded-lg border border-gray-800 bg-gray-900/50 transition-colors hover:border-gray-700",
        group.severity === "critical" &&
          "border-red-500/30 hover:border-red-500/50",
        group.severity === "high" &&
          "border-orange-500/20 hover:border-orange-500/40"
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
            <SeverityBadge severity={group.severity} />
            {!isTenantWide && policyCount > 0 && (
              <span className="rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-400">
                {policyCount} {policyCount === 1 ? "policy" : "policies"}
              </span>
            )}
            {isTenantWide && (
              <span className="rounded bg-blue-500/10 px-2 py-0.5 text-xs text-blue-400">
                Tenant-wide
              </span>
            )}
          </div>
          <h4 className="text-sm font-medium text-gray-200">{group.title}</h4>
          {!expanded && (
            <p className="mt-1 text-xs text-gray-500 line-clamp-1">
              {group.description}
            </p>
          )}
        </div>
      </button>

      {expanded && (
        <div className="border-t border-gray-800 px-4 pb-4 pt-3 ml-7 space-y-3">
          <p className="text-sm text-gray-400 leading-relaxed">
            {group.description}
          </p>

          {/* Recommendation */}
          <div className="flex items-start gap-2 rounded-lg bg-blue-500/5 border border-blue-500/20 p-3">
            <Lightbulb className="mt-0.5 h-4 w-4 shrink-0 text-blue-400" />
            <p className="text-sm text-blue-300">{group.recommendation}</p>
          </div>

          {/* Affected policies */}
          {policyCount > 0 && (
            <div className="space-y-1.5">
              <span className="text-xs font-medium text-gray-500 uppercase">
                Affected policies ({policyCount})
              </span>
              <div className="flex flex-wrap gap-1.5">
                {group.policyNames.map((name) => (
                  <span
                    key={name}
                    className="rounded bg-gray-800 px-2 py-1 text-xs text-gray-400"
                  >
                    {name}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Excluded app details */}
          {group.excludedApps.length > 0 && (
            <div className="space-y-2">
              <div className="flex items-center gap-1.5">
                <ShieldAlert className="h-3.5 w-3.5 text-gray-500" />
                <span className="text-xs font-medium text-gray-500 uppercase">
                  Excluded apps ({group.excludedApps.length})
                </span>
              </div>
              <div className="space-y-1">
                {group.excludedApps.map((app) => (
                  <ExcludedAppRow key={app.appId} app={app} />
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Category section ───────────────────────────────────────────────────────

function CategorySection({
  categoryGroup,
}: {
  categoryGroup: CategoryGroup;
}) {
  const [open, setOpen] = useState(true);
  const meta = CATEGORY_META[categoryGroup.category] ?? {
    icon: Shield,
    color: "text-gray-400",
  };
  const Icon = meta.icon;

  return (
    <div className="space-y-2">
      <button
        onClick={() => setOpen(!open)}
        className="flex w-full items-center gap-2 py-1 text-left group"
      >
        {open ? (
          <ChevronDown className="h-4 w-4 text-gray-600" />
        ) : (
          <ChevronRight className="h-4 w-4 text-gray-600" />
        )}
        <Icon className={cn("h-4 w-4", meta.color)} />
        <span className="text-sm font-semibold text-gray-300 group-hover:text-white transition-colors">
          {categoryGroup.category}
        </span>
        <span className="text-xs text-gray-600">
          {categoryGroup.groups.length}{" "}
          {categoryGroup.groups.length === 1 ? "issue" : "issues"} ·{" "}
          {categoryGroup.totalFindings}{" "}
          {categoryGroup.totalFindings === 1 ? "finding" : "findings"}
        </span>
        <SeverityBadge severity={categoryGroup.severity} />
      </button>
      {open && (
        <div className="space-y-2 ml-2">
          {categoryGroup.groups.map((g) => (
            <FindingGroupCard key={g.key} group={g} />
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Exported components ────────────────────────────────────────────────────

/** Single finding card — still used by PolicyCard in the Policies tab */
export function FindingCard({ finding }: { finding: Finding }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div
      className={cn(
        "rounded-lg border border-gray-800 bg-gray-900/50 transition-colors hover:border-gray-700",
        finding.severity === "critical" &&
          "border-red-500/30 hover:border-red-500/50",
        finding.severity === "high" &&
          "border-orange-500/20 hover:border-orange-500/40"
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
            <span className="text-xs text-gray-600 font-mono">
              {finding.id}
            </span>
            <span className="rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-400">
              {finding.category}
            </span>
          </div>
          <h4 className="text-sm font-medium text-gray-200">
            {finding.title}
          </h4>
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

/** The main Findings tab — grouped, deduplicated view */
export function FindingsList({
  findings,
  title,
}: {
  findings: Finding[];
  title?: string;
}) {
  const [filter, setFilter] = useState<string>("all");

  const filtered =
    filter === "all" ? findings : findings.filter((f) => f.severity === filter);

  const findingGroups = useMemo(() => groupFindings(filtered), [filtered]);
  const categories = useMemo(
    () => groupByCategory(findingGroups),
    [findingGroups]
  );

  const uniqueIssueCount = findingGroups.length;

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
        <div>
          <h3 className="text-lg font-semibold text-white">
            {title ?? "Findings"}{" "}
            <span className="text-gray-500 font-normal">
              ({uniqueIssueCount}{" "}
              {uniqueIssueCount === 1 ? "issue" : "unique issues"})
            </span>
          </h3>
          <p className="text-xs text-gray-600 mt-0.5">
            {findings.length} total across {categories.length}{" "}
            {categories.length === 1 ? "category" : "categories"} · grouped by
            type, showing affected policies
          </p>
        </div>
        <div className="flex gap-1">
          {[
            { key: "all", label: "All" },
            {
              key: "critical",
              label: `Critical (${severityCounts.critical})`,
            },
            { key: "high", label: `High (${severityCounts.high})` },
            { key: "medium", label: `Medium (${severityCounts.medium})` },
            { key: "low", label: `Low (${severityCounts.low})` },
            { key: "info", label: `Info (${severityCounts.info})` },
          ]
            .filter(
              (f) =>
                f.key === "all" ||
                severityCounts[f.key as keyof typeof severityCounts] > 0
            )
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

      {categories.length === 0 ? (
        <p className="py-8 text-center text-sm text-gray-600">
          No findings match the selected filter.
        </p>
      ) : (
        <div className="space-y-6">
          {categories.map((cat) => (
            <CategorySection key={cat.category} categoryGroup={cat} />
          ))}
        </div>
      )}
    </Card>
  );
}
