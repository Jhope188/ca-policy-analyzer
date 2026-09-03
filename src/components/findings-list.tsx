"use client";

import {
  Finding,
  ExcludedAppDetail,
  DiscoveredAppDetail,
  Severity,
} from "@/lib/analyzer";
import { PolicyAppImpact } from "@/lib/policy-app-impact";
import { buildCreateServicePrincipalsScript } from "@/lib/signin-app-gap";
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
  Download,
  Copy,
  Check,
  ExternalLink,
  PlugZap,
} from "lucide-react";
import { useState, useMemo } from "react";
import { cn } from "@/lib/utils";

import {
  AppliedCaPolicy,
  ENTRA_SIGNIN_LOGS_URL,
  ENTRA_SIGNIN_LOGS_PATH,
} from "@/lib/graph-client";

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
  "Low-Privilege Scope Enforcement": { icon: AlertTriangle, color: "text-yellow-400" },
  "Found missing service principals that bypasses your security gate": { icon: PlugZap, color: "text-red-400" },
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
  discoveredApps: DiscoveredAppDetail[];
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
      if (f.discoveredApps) {
        for (const app of f.discoveredApps) {
          if (!existing.discoveredApps.some((a) => a.appId === app.appId)) {
            existing.discoveredApps.push(app);
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
        discoveredApps: f.discoveredApps ? [...f.discoveredApps] : [],
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

// ─── Discovered app components ──────────────────────────────────────────────

const OBSERVED_RESULT_STYLES: Record<string, string> = {
  success: "bg-green-500/10 text-green-400",
  failure: "bg-red-500/10 text-red-400",
  notApplied: "bg-orange-500/10 text-orange-400",
  notEnabled: "bg-gray-800 text-gray-500",
  reportOnlySuccess: "bg-blue-500/10 text-blue-400",
  reportOnlyFailure: "bg-blue-500/10 text-blue-400",
  reportOnlyNotApplied: "bg-blue-500/10 text-blue-400",
  reportOnlyInterrupted: "bg-blue-500/10 text-blue-400",
};

/** The only impact worth showing inline: what would actually block. */
export function blockingPolicies(impact: PolicyAppImpact[]): PolicyAppImpact[] {
  return impact.filter(
    (i) => i.state === "enabled" && i.blocks && i.verdict !== "willNotApply"
  );
}

/**
 * Nearly every policy records `notApplied` for these apps, so a row per policy
 * is noise. Keep a count, and rows only for policies that actually fired.
 */
export function summarizeObserved(policies?: AppliedCaPolicy[]) {
  if (!policies || policies.length === 0) return null;
  return {
    total: policies.length,
    outsideTargetResources: policies.filter((p) =>
      p.conditionsNotSatisfied?.includes("application")
    ).length,
    applied: policies.filter(
      (p) => p.result === "success" || p.result === "failure"
    ),
  };
}

function MetaField({ label, value }: { label: string; value?: string | number }) {
  if (value === undefined || value === null || value === "") return null;
  return (
    <div>
      <span className="text-[10px] font-medium uppercase text-gray-600">
        {label}
      </span>
      <p className="text-xs text-gray-400 break-words">{value}</p>
    </div>
  );
}

function DiscoveredAppRow({ app }: { app: DiscoveredAppDetail }) {
  const [open, setOpen] = useState(false);
  const blocking = useMemo(() => blockingPolicies(app.predictedImpact), [app]);
  // A policy can also reach the app by ID or via the Office 365 suite, so only
  // claim "they all target All cloud apps" when that is actually true.
  const allBlockingViaAllApps = useMemo(
    () =>
      blocking.length > 0 &&
      blocking.every((i) => i.reasons.some((r) => r.includes("All resources"))),
    [blocking]
  );
  const observed = useMemo(() => summarizeObserved(app.observedPolicies), [app]);

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
        <span className="text-[10px] text-gray-500 tabular-nums">
          {app.signInCount.toLocaleString()} sign-ins
        </span>
        <ExcludedAppBadge risk={app.severity} />
      </button>

      {open && (
        <div className="space-y-3 border-t border-gray-800/50 p-2.5">
          <p className="font-mono text-[10px] text-gray-600">{app.appId}</p>

          <div className="grid gap-2 sm:grid-cols-2">
            <MetaField label="Seen in" value={app.seenIn} />
            <MetaField label="Last seen" value={app.lastSeen} />
            <MetaField
              label="Signed in by"
              value={
                app.isWorkloadIdentity
                  ? "Workload identity (no user)"
                  : app.userPrincipalName
              }
            />
            <MetaField label="From IP" value={app.ipAddress} />
            <MetaField label="Client app" value={app.clientAppUsed} />
            <MetaField label="Reached resource" value={app.resourceDisplayName} />
            <MetaField label="CA status on that sign-in" value={app.conditionalAccessStatus} />
            <MetaField label="Request ID" value={app.requestId} />
          </div>

          {app.evidenceMissing && (
            <p className="text-[11px] text-gray-600">
              No log entry was fetched for this app - it is listed by app ID and
              sign-in count only, so the sign-in type is unknown. The Graph
              Explorer link below therefore returns{" "}
              <span className="text-gray-500">interactive</span> sign-ins, which
              is what the endpoint gives by default. If it comes back empty this
              app signs in another way; add one clause to the filter to see the
              rest:
              <code className="mt-1 block break-all font-mono text-[10px] text-gray-500">
                and signInEventTypes/any(t: t eq
                &apos;nonInteractiveUser&apos;)
              </code>
              <span className="text-gray-600">
                …or swap in <code className="font-mono">servicePrincipal</code> or{" "}
                <code className="font-mono">managedIdentity</code>.
              </span>
            </p>
          )}

          {app.bypassNote && (
            <div className="rounded border border-red-500/30 bg-red-500/5 p-2">
              <p className="text-[11px] text-red-300">{app.bypassNote}</p>
            </div>
          )}

          {app.phantomExclusionPolicies.length > 0 && (
            <div className="rounded border border-red-500/30 bg-red-500/5 p-2">
              <p className="text-[11px] text-red-300">
                Excluded by name in {app.phantomExclusionPolicies.length} policy(s) -{" "}
                {app.phantomExclusionPolicies.join(", ")} - even though the app has
                no service principal. The exclusion protects nothing today and
                becomes live the moment the app is created.
              </p>
            </div>
          )}

          {app.baselineNote && (
            <div className="rounded border border-blue-500/20 bg-blue-500/5 p-2">
              <p className="text-[11px] text-blue-300">{app.baselineNote}</p>
            </div>
          )}

          {observed && (
            <div className="space-y-1.5">
              <span className="text-[10px] font-medium uppercase text-gray-600">
                Recorded on that sign-in
              </span>
              <p className="text-[11px] text-gray-500">
                Entra evaluated {observed.total}{" "}
                {observed.total === 1 ? "policy" : "policies"}
                {observed.outsideTargetResources > 0 && (
                  <>
                    ; {observed.outsideTargetResources} did not apply because
                    this app was outside their target resources
                  </>
                )}
                .
              </p>
              {observed.applied.map((p) => (
                <div
                  key={p.id || p.displayName}
                  className="rounded border border-gray-800/70 bg-gray-950/40 p-2"
                >
                  <div className="flex items-center gap-2">
                    <span className="flex-1 truncate text-xs text-gray-300">
                      {p.displayName}
                    </span>
                    <span
                      className={cn(
                        "rounded px-1.5 py-0.5 text-[10px] font-medium",
                        OBSERVED_RESULT_STYLES[p.result] ??
                          "bg-gray-800 text-gray-400"
                      )}
                    >
                      {p.result}
                    </span>
                  </div>
                  {p.enforcedGrantControls.length > 0 && (
                    <p className="mt-0.5 text-[11px] text-gray-600">
                      Enforced: {p.enforcedGrantControls.join(", ")}
                    </p>
                  )}
                </div>
              ))}
            </div>
          )}

          <div className="space-y-1.5">
            <span className="text-[10px] font-medium uppercase text-gray-600">
              After creating the service principal
            </span>
            {blocking.length === 0 ? (
              <p className="text-[11px] text-gray-500">
                No enabled policy would block this app.
              </p>
            ) : (
              <>
                <p className="text-[11px] text-red-300">
                  {blocking.length}{" "}
                  {blocking.length === 1 ? "policy" : "policies"} could
                  potentially block access - sign-ins that work today may stop.
                  {allBlockingViaAllApps && (
                    <>
                      {" "}
                      <span className="text-gray-500">
                        {blocking.length === 1 ? "It targets" : "They all target"}{" "}
                        All cloud apps, so{" "}
                        {blocking.length === 1 ? "it starts" : "they start"}{" "}
                        applying the moment this app exists.
                      </span>
                    </>
                  )}
                </p>
                {blocking.map((i) => (
                  <div
                    key={i.policyId}
                    className="rounded border border-red-500/30 bg-red-500/5 p-2"
                  >
                    <p className="text-xs font-medium text-gray-200">
                      {i.policyName}
                    </p>
                    {i.verdict === "mayApply" && (
                      <p className="mt-0.5 text-[11px] text-gray-500">
                        Depends on the signing-in user, device, location or
                        risk - verify before you create this app.
                      </p>
                    )}
                    {i.gatedBy.length > 0 && (
                      <p className="mt-0.5 text-[11px] text-gray-600">
                        Must also match: {i.gatedBy.join(" · ")}
                      </p>
                    )}
                  </div>
                ))}
              </>
            )}
          </div>

          <div className="flex flex-wrap gap-3 pt-1">
            <a
              href={app.logQueryUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-[11px] text-blue-400 hover:text-blue-300"
            >
              <ExternalLink className="h-3 w-3" />
              Log entries in Graph Explorer
            </a>
            <a
              href={ENTRA_SIGNIN_LOGS_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-[11px] text-blue-400 hover:text-blue-300"
              title={`Search the Request ID above. Opens on the last 24 hours - widen the range if the sign-in is older. Also reachable via ${ENTRA_SIGNIN_LOGS_PATH}`}
            >
              <ExternalLink className="h-3 w-3" />
              Sign-in logs
            </a>
          </div>
        </div>
      )}
    </div>
  );
}

const APP_ROWS_BEFORE_FOLD = 8;

const SEVERITY_GROUP_LABELS: Record<Severity, string> = {
  critical: "Needs a decision first",
  high: "Actively used, policies would apply",
  medium: "Lower impact",
  low: "Lower impact",
  info: "No policy would reach them",
};

/** One severity tier: collapsed unless it is the worst, folded after a handful
 * of rows. A flat list of every app is unreadable on a real tenant. */
function SeverityAppGroup({
  severity,
  apps,
  defaultOpen,
}: {
  severity: Severity;
  apps: DiscoveredAppDetail[];
  defaultOpen: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const [showAll, setShowAll] = useState(false);

  const visible = showAll ? apps : apps.slice(0, APP_ROWS_BEFORE_FOLD);
  const hidden = apps.length - visible.length;

  return (
    <div>
      <button
        onClick={() => setOpen(!open)}
        className="flex w-full items-center gap-2 py-1 text-left"
      >
        {open ? (
          <ChevronDown className="h-3.5 w-3.5 shrink-0 text-gray-600" />
        ) : (
          <ChevronRight className="h-3.5 w-3.5 shrink-0 text-gray-600" />
        )}
        <SeverityBadge severity={severity} />
        <span className="text-xs text-gray-400">
          {SEVERITY_GROUP_LABELS[severity]}
        </span>
        <span className="ml-auto text-xs tabular-nums text-gray-600">
          {apps.length}
        </span>
      </button>
      {open && (
        <div className="mt-1 space-y-1 pl-5">
          {visible.map((app) => (
            <DiscoveredAppRow key={app.appId} app={app} />
          ))}
          {hidden > 0 && (
            <button
              onClick={() => setShowAll(true)}
              className="w-full rounded-md border border-dashed border-gray-800 py-1.5 text-xs text-gray-500 hover:border-gray-700 hover:text-gray-300 transition-colors"
            >
              Show {hidden} more
            </button>
          )}
          {showAll && apps.length > APP_ROWS_BEFORE_FOLD && (
            <button
              onClick={() => setShowAll(false)}
              className="w-full py-1 text-xs text-gray-600 hover:text-gray-400 transition-colors"
            >
              Collapse
            </button>
          )}
        </div>
      )}
    </div>
  );
}

/** Decision summary and script up front, then the app list by severity. */
export function DiscoveredAppsBlock({
  apps,
  tenantDisplayName,
  tenantId,
}: {
  apps: DiscoveredAppDetail[];
  tenantDisplayName?: string;
  tenantId?: string;
}) {
  const [copied, setCopied] = useState(false);

  const stats = useMemo(() => {
    const blocking = apps.filter((a) =>
      a.predictedImpact.some(
        (i) => i.state === "enabled" && i.blocks && i.verdict === "willApply"
      )
    ).length;
    const uncovered = apps.filter(
      (a) =>
        !a.predictedImpact.some(
          (i) => i.state === "enabled" && i.verdict !== "willNotApply"
        )
    ).length;
    return { blocking, uncovered };
  }, [apps]);

  const severityGroups = useMemo(() => {
    const order: Severity[] = ["critical", "high", "medium", "low", "info"];
    return order
      .map((severity) => ({
        severity,
        apps: apps.filter((a) => a.severity === severity),
      }))
      .filter((g) => g.apps.length > 0);
  }, [apps]);

  const script = useMemo(
    () =>
      buildCreateServicePrincipalsScript(apps, {
        tenantDisplayName,
        tenantId,
      }),
    [apps, tenantDisplayName, tenantId]
  );

  const download = () => {
    const blob = new Blob([script], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `Register-MissingServicePrincipals-${new Date()
      .toISOString()
      .slice(0, 10)}.ps1`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(script);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Browser policy can block the clipboard - the download still works
    }
  };

  return (
    <div className="space-y-3">
      <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3">
        <div className="flex items-start gap-2">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
          <div className="space-y-2 text-xs text-amber-200/90">
            <p className="font-medium text-amber-200">
              Before you create these
            </p>
            <div className="flex flex-wrap gap-x-4 gap-y-1">
              <span>
                <strong className="text-base tabular-nums text-amber-200">
                  {stats.blocking}
                </strong>{" "}
                could be blocked
              </span>
              <span>
                <strong className="text-base tabular-nums text-amber-200">
                  {stats.uncovered}
                </strong>{" "}
                still unreached
              </span>
            </div>
            <p>
              Creating a service principal makes the app visible to Entra ID, so
              policies targeting <strong>All cloud apps</strong> apply to it
              immediately. Run the script with{" "}
              <code className="text-amber-100">-WhatIf</code> first and create in
              waves.
              {stats.blocking > 0 && (
                <>
                  {" "}
                  The {stats.blocking} app{stats.blocking === 1 ? "" : "s"} a
                  block policy would catch{" "}
                  {stats.blocking === 1 ? "is" : "are"} marked{" "}
                  <code className="text-amber-100">BLOCKED BY</code> in the
                  script - add an exclusion or set that policy to report-only
                  first, or delete those lines to leave them for later.
                </>
              )}
            </p>
          </div>
        </div>
        <div className="mt-3 flex flex-wrap gap-2 pl-6">
          <button
            onClick={download}
            className="inline-flex items-center gap-1.5 rounded-lg bg-amber-500/15 px-2.5 py-1.5 text-xs font-medium text-amber-200 hover:bg-amber-500/25 transition-colors"
          >
            <Download className="h-3.5 w-3.5" />
            Download PowerShell script
          </button>
          <button
            onClick={copy}
            className="inline-flex items-center gap-1.5 rounded-lg border border-amber-500/30 px-2.5 py-1.5 text-xs font-medium text-amber-200 hover:bg-amber-500/10 transition-colors"
          >
            {copied ? (
              <Check className="h-3.5 w-3.5" />
            ) : (
              <Copy className="h-3.5 w-3.5" />
            )}
            {copied ? "Copied" : "Copy script"}
          </button>
        </div>
      </div>

      <div className="space-y-2">
        <div className="flex items-center gap-1.5">
          <PlugZap className="h-3.5 w-3.5 text-gray-500" />
          <span className="text-xs font-medium uppercase text-gray-500">
            Apps without a service principal ({apps.length})
          </span>
        </div>
        {severityGroups.map((group, index) => (
          <SeverityAppGroup
            key={group.severity}
            severity={group.severity}
            apps={group.apps}
            defaultOpen={index === 0}
          />
        ))}
      </div>
    </div>
  );
}

// ─── Finding group card ─────────────────────────────────────────────────────

function FindingGroupCard({
  group,
  tenantDisplayName,
  tenantId,
}: {
  group: FindingGroup;
  tenantDisplayName?: string;
  tenantId?: string;
}) {
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

          {group.discoveredApps.length > 0 && (
            <DiscoveredAppsBlock
              apps={group.discoveredApps}
              tenantDisplayName={tenantDisplayName}
              tenantId={tenantId}
            />
          )}
        </div>
      )}
    </div>
  );
}

// ─── Category section ───────────────────────────────────────────────────────

function CategorySection({
  categoryGroup,
  tenantDisplayName,
  tenantId,
}: {
  categoryGroup: CategoryGroup;
  tenantDisplayName?: string;
  tenantId?: string;
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
            <FindingGroupCard
              key={g.key}
              group={g}
              tenantDisplayName={tenantDisplayName}
              tenantId={tenantId}
            />
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
  tenantDisplayName,
  tenantId,
}: {
  findings: Finding[];
  title?: string;
  /** Only stamps the generated remediation script header. */
  tenantDisplayName?: string;
  tenantId?: string;
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
            <CategorySection
              key={cat.category}
              categoryGroup={cat}
              tenantDisplayName={tenantDisplayName}
              tenantId={tenantId}
            />
          ))}
        </div>
      )}
    </Card>
  );
}
