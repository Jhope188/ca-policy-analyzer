/**
 * Named Locations View
 *
 * Displays all named locations in the tenant with:
 *   - Type badge (IP Range / Country / Compliant Network)
 *   - Trusted status
 *   - Which policies reference each location
 *   - Warnings for misconfigurations (untrusted locations used in trusted-only
 *     policies, empty country lists, orphaned references, broad IP ranges, etc.)
 *   - Tenant-wide warnings banner
 *   - Filter by location type, trusted status, and search
 *   - Clickable policy references showing include/exclude usage
 */

"use client";

import { useState, useMemo } from "react";
import { Card } from "./ui-primitives";
import {
  LocationAnalysisResult,
  LocationAnalysis,
  LocationWarning,
  PolicyReference,
  OrphanedLocationRef,
  getLocationType,
  getLocationSummary,
} from "@/lib/location-analyzer";
import { cn } from "@/lib/utils";
import {
  MapPin,
  Globe,
  Wifi,
  ShieldCheck,
  ShieldAlert,
  ChevronDown,
  ChevronRight,
  AlertTriangle,
  AlertCircle,
  Info,
  Search,
  X,
} from "lucide-react";

// ─── Warning level config ────────────────────────────────────────────────────

const WARNING_CONFIG: Record<
  string,
  { icon: typeof AlertCircle; className: string; label: string }
> = {
  critical: {
    icon: ShieldAlert,
    label: "Critical",
    className: "bg-red-500/10 text-red-400 border-red-500/30",
  },
  high: {
    icon: AlertCircle,
    label: "High",
    className: "bg-orange-500/10 text-orange-400 border-orange-500/30",
  },
  medium: {
    icon: AlertTriangle,
    label: "Medium",
    className: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
  },
  info: {
    icon: Info,
    label: "Info",
    className: "bg-gray-500/10 text-gray-400 border-gray-500/30",
  },
};

function WarningBadge({ level }: { level: string }) {
  const config = WARNING_CONFIG[level] ?? WARNING_CONFIG.info;
  const Icon = config.icon;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-medium",
        config.className
      )}
    >
      <Icon className="h-3 w-3" />
      {config.label}
    </span>
  );
}

// ─── Location type icon ──────────────────────────────────────────────────────

function LocationTypeIcon({ type }: { type: string }) {
  switch (type) {
    case "IP Range":
      return <Wifi className="h-4 w-4 text-blue-400" />;
    case "Country":
      return <Globe className="h-4 w-4 text-green-400" />;
    case "Compliant Network":
      return <ShieldCheck className="h-4 w-4 text-purple-400" />;
    default:
      return <MapPin className="h-4 w-4 text-gray-400" />;
  }
}

// ─── Policy reference row ────────────────────────────────────────────────────

function PolicyRefRow({ ref: r }: { ref: PolicyReference }) {
  const stateClass =
    r.policyState === "enabled"
      ? "text-green-400"
      : r.policyState === "enabledForReportingButNotEnforced"
      ? "text-yellow-400"
      : "text-gray-500";

  const stateLabel =
    r.policyState === "enabled"
      ? "Enabled"
      : r.policyState === "enabledForReportingButNotEnforced"
      ? "Report-only"
      : "Disabled";

  return (
    <div className="flex items-center gap-2 rounded-md bg-gray-950/50 px-3 py-1.5 text-xs">
      <span
        className={cn(
          "inline-block h-2 w-2 rounded-full shrink-0",
          r.policyState === "enabled"
            ? "bg-green-500"
            : r.policyState === "enabledForReportingButNotEnforced"
            ? "bg-yellow-500"
            : "bg-gray-600"
        )}
      />
      <span className="text-gray-300 truncate flex-1">{r.policyName}</span>
      <span
        className={cn(
          "rounded px-1.5 py-0.5 text-[10px] font-medium uppercase",
          r.usage === "include"
            ? "bg-blue-500/10 text-blue-400"
            : "bg-purple-500/10 text-purple-400"
        )}
      >
        {r.usage}
      </span>
      <span className={cn("text-[10px]", stateClass)}>{stateLabel}</span>
    </div>
  );
}

// ─── Warning card ────────────────────────────────────────────────────────────

function WarningCard({ warning }: { warning: LocationWarning }) {
  const [open, setOpen] = useState(false);
  const config = WARNING_CONFIG[warning.level] ?? WARNING_CONFIG.info;

  return (
    <div className={cn("rounded-lg border", config.className.replace(/text-\S+/, ""))}>
      <button
        onClick={() => setOpen(!open)}
        className="flex w-full items-start gap-2 p-3 text-left"
      >
        <WarningBadge level={warning.level} />
        <p className="flex-1 text-xs text-gray-300">{warning.title}</p>
        {open ? (
          <ChevronDown className="h-3.5 w-3.5 text-gray-600 shrink-0 mt-0.5" />
        ) : (
          <ChevronRight className="h-3.5 w-3.5 text-gray-600 shrink-0 mt-0.5" />
        )}
      </button>
      {open && (
        <div className="border-t border-gray-800/50 px-3 pb-3 pt-2 space-y-2">
          <p className="text-xs text-gray-400">{warning.detail}</p>
          <div className="flex items-start gap-2 rounded-md bg-blue-500/5 border border-blue-500/10 p-2">
            <Info className="h-3.5 w-3.5 shrink-0 mt-0.5 text-blue-400" />
            <p className="text-xs text-blue-300">{warning.recommendation}</p>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Single location card ────────────────────────────────────────────────────

function LocationCard({ analysis }: { analysis: LocationAnalysis }) {
  const [expanded, setExpanded] = useState(false);
  const loc = analysis.location;
  const locType = getLocationType(loc);
  const summary = getLocationSummary(loc);
  const totalRefs =
    analysis.directReferences.length + analysis.trustedLocationReferences.length;
  const hasWarnings = analysis.warnings.length > 0;
  const highestWarning = analysis.warnings.reduce<string | null>(
    (acc, w) => {
      const order = ["critical", "high", "medium", "info"];
      if (!acc) return w.level;
      return order.indexOf(w.level) < order.indexOf(acc) ? w.level : acc;
    },
    null
  );

  return (
    <div
      className={cn(
        "rounded-xl border transition-colors",
        hasWarnings
          ? highestWarning === "critical"
            ? "border-red-500/30 bg-red-500/5"
            : highestWarning === "high"
            ? "border-orange-500/20 bg-orange-500/5"
            : highestWarning === "medium"
            ? "border-yellow-500/20 bg-yellow-500/5"
            : "border-gray-800 bg-gray-900"
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
        <LocationTypeIcon type={locType} />
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="text-sm font-semibold text-white truncate">
              {loc.displayName}
            </h3>
            <span className="text-[10px] font-medium rounded px-1.5 py-0.5 bg-gray-800 text-gray-400">
              {locType}
            </span>
            {/* Trust badges: only show for IP-range and compliant-network locations.
                Country locations don't have a trusted toggle in Entra ID. */}
            {loc["@odata.type"] !== "#microsoft.graph.countryNamedLocation" && (
              loc.isTrusted ? (
                <span className="inline-flex items-center gap-1 text-[10px] font-medium rounded px-1.5 py-0.5 bg-green-500/10 text-green-400">
                  <ShieldCheck className="h-3 w-3" />
                  Trusted
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 text-[10px] font-medium rounded px-1.5 py-0.5 bg-gray-800 text-gray-500">
                  <ShieldAlert className="h-3 w-3" />
                  Not trusted
                </span>
              )
            )}
          </div>
          <p className="mt-0.5 text-xs text-gray-500">{summary}</p>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          {hasWarnings && (
            <div className="flex items-center gap-1">
              <AlertTriangle
                className={cn(
                  "h-4 w-4",
                  highestWarning === "critical"
                    ? "text-red-400"
                    : highestWarning === "high"
                    ? "text-orange-400"
                    : "text-yellow-400"
                )}
              />
              <span className="text-xs text-gray-400">
                {analysis.warnings.length}
              </span>
            </div>
          )}
          <span className="text-xs text-gray-500">
            {totalRefs} {totalRefs === 1 ? "policy" : "policies"}
          </span>
        </div>
      </button>

      {/* Expanded */}
      {expanded && (
        <div className="border-t border-gray-800 p-4 space-y-4">
          {/* Warnings */}
          {hasWarnings && (
            <div className="space-y-2">
              <h4 className="text-xs font-medium text-gray-500 uppercase tracking-wider">
                Warnings ({analysis.warnings.length})
              </h4>
              {analysis.warnings.map((w, i) => (
                <WarningCard key={i} warning={w} />
              ))}
            </div>
          )}

          {/* Location details */}
          <div>
            <h4 className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-2">
              Location Details
            </h4>
            <div className="rounded-lg border border-gray-800 overflow-hidden">
              <table className="w-full text-xs">
                <tbody>
                  <tr className="border-b border-gray-800">
                    <td className="px-3 py-1.5 text-gray-500 font-medium whitespace-nowrap w-36 bg-gray-900/50">
                      Type
                    </td>
                    <td className="px-3 py-1.5 text-gray-300">{locType}</td>
                  </tr>
                  {/* Trust row — only meaningful for IP-range locations */}
                  {loc["@odata.type"] !== "#microsoft.graph.countryNamedLocation" && (
                    <tr className="border-b border-gray-800">
                      <td className="px-3 py-1.5 text-gray-500 font-medium whitespace-nowrap w-36 bg-gray-900/50">
                        Trusted
                      </td>
                      <td className="px-3 py-1.5 text-gray-300">
                        {loc.isTrusted ? "Yes" : "No"}
                      </td>
                    </tr>
                  )}
                  {loc["@odata.type"] ===
                    "#microsoft.graph.countryNamedLocation" && (
                    <>
                      <tr className="border-b border-gray-800">
                        <td className="px-3 py-1.5 text-gray-500 font-medium whitespace-nowrap w-36 bg-gray-900/50">
                          Countries
                        </td>
                        <td className="px-3 py-1.5 text-gray-300">
                          {loc.countriesAndRegions?.join(", ") || "None"}
                        </td>
                      </tr>
                      <tr className="border-b border-gray-800">
                        <td className="px-3 py-1.5 text-gray-500 font-medium whitespace-nowrap w-36 bg-gray-900/50">
                          Lookup method
                        </td>
                        <td className="px-3 py-1.5 text-gray-300">
                          {loc.countryLookupMethod === "authenticatorAppGps"
                            ? "GPS coordinates (Authenticator app)"
                            : loc.countryLookupMethod === "clientIpAddress"
                            ? "IP address (IPv4 and IPv6)"
                            : loc.countryLookupMethod ?? "—"}
                        </td>
                      </tr>
                      <tr className="border-b border-gray-800">
                        <td className="px-3 py-1.5 text-gray-500 font-medium whitespace-nowrap w-36 bg-gray-900/50">
                          Include unknown
                        </td>
                        <td className={cn(
                          "px-3 py-1.5",
                          loc.includeUnknownCountriesAndRegions ? "text-yellow-400" : "text-gray-300"
                        )}>
                          {loc.includeUnknownCountriesAndRegions ? "Yes" : "No"}
                        </td>
                      </tr>
                    </>
                  )}
                  {loc["@odata.type"] ===
                    "#microsoft.graph.ipNamedLocation" &&
                    loc.ipRanges && (
                      <tr className="border-b border-gray-800">
                        <td className="px-3 py-1.5 text-gray-500 font-medium whitespace-nowrap w-36 bg-gray-900/50">
                          IP Ranges
                        </td>
                        <td className="px-3 py-1.5 text-gray-300 break-all">
                          {loc.ipRanges
                            .map((r) => r.cidrAddress)
                            .join(", ")}
                        </td>
                      </tr>
                    )}
                  <tr>
                    <td className="px-3 py-1.5 text-gray-500 font-medium whitespace-nowrap w-36 bg-gray-900/50">
                      ID
                    </td>
                    <td className="px-3 py-1.5 text-gray-600 font-mono break-all">
                      {loc.id}
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          {/* Direct policy references */}
          {analysis.directReferences.length > 0 && (
            <div>
              <h4 className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-2">
                Direct Policy References ({analysis.directReferences.length})
              </h4>
              <div className="space-y-1">
                {analysis.directReferences.map((r) => (
                  <PolicyRefRow key={`${r.policyId}-${r.usage}`} ref={r} />
                ))}
              </div>
            </div>
          )}

          {/* Trusted location policy references (via AllTrustedLocations) */}
          {analysis.trustedLocationReferences.length > 0 && (
            <div>
              <h4 className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-2">
                Via &quot;All Trusted Locations&quot; ({analysis.trustedLocationReferences.length})
              </h4>
              <div className="space-y-1">
                {analysis.trustedLocationReferences.map((r) => (
                  <PolicyRefRow key={`${r.policyId}-trusted-${r.usage}`} ref={r} />
                ))}
              </div>
            </div>
          )}

          {totalRefs === 0 && (
            <p className="text-xs text-gray-600 italic">
              This location is not referenced by any policy.
            </p>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Tenant-wide warning banner ──────────────────────────────────────────────

function TenantWarningsBanner({
  warnings,
  orphaned,
}: {
  warnings: LocationWarning[];
  orphaned: OrphanedLocationRef[];
}) {
  const [expanded, setExpanded] = useState(true);

  if (warnings.length === 0 && orphaned.length === 0) return null;

  return (
    <div className="rounded-xl border border-orange-500/30 bg-orange-500/5 overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex w-full items-center gap-2 px-4 py-3 text-left"
      >
        <AlertTriangle className="h-5 w-5 text-orange-400 shrink-0" />
        <h3 className="text-sm font-semibold text-orange-300 flex-1">
          Tenant-Wide Location Warnings
        </h3>
        <span className="text-xs text-orange-400/60">
          {warnings.length + (orphaned.length > 0 ? 1 : 0)} issue
          {warnings.length + (orphaned.length > 0 ? 1 : 0) !== 1 ? "s" : ""}
        </span>
        {expanded ? (
          <ChevronDown className="h-4 w-4 text-orange-400/60" />
        ) : (
          <ChevronRight className="h-4 w-4 text-orange-400/60" />
        )}
      </button>
      {expanded && (
        <div className="border-t border-orange-500/20 px-4 pb-4 pt-3 space-y-2">
          {warnings.map((w, i) => (
            <WarningCard key={i} warning={w} />
          ))}
          {orphaned.length > 0 && (
            <div className="rounded-lg border border-yellow-500/20 p-3 space-y-2">
              <div className="flex items-center gap-2">
                <WarningBadge level="medium" />
                <span className="text-xs text-gray-300">
                  Orphaned location references
                </span>
              </div>
              <div className="space-y-1">
                {orphaned.map((o, i) => (
                  <div
                    key={i}
                    className="flex items-center gap-2 text-xs text-gray-400"
                  >
                    <span className="font-mono text-gray-600 truncate max-w-[200px]">
                      {o.locationId}
                    </span>
                    <span>→</span>
                    <span className="text-gray-300 truncate">
                      {o.policyName}
                    </span>
                    <span
                      className={cn(
                        "rounded px-1.5 py-0.5 text-[10px] font-medium uppercase",
                        o.usage === "include"
                          ? "bg-blue-500/10 text-blue-400"
                          : "bg-purple-500/10 text-purple-400"
                      )}
                    >
                      {o.usage}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Main Component ──────────────────────────────────────────────────────────

type TypeFilter = "all" | "ip" | "country" | "compliant";
type TrustFilter = "all" | "trusted" | "untrusted";

export function LocationsView({ result }: { result: LocationAnalysisResult }) {
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState<TypeFilter>("all");
  const [trustFilter, setTrustFilter] = useState<TrustFilter>("all");
  const [showOnlyWarnings, setShowOnlyWarnings] = useState(false);

  const filtered = useMemo(() => {
    return result.locations.filter((a) => {
      const loc = a.location;

      // Search filter
      if (search.trim()) {
        const q = search.toLowerCase();
        const matchesName = loc.displayName.toLowerCase().includes(q);
        const matchesCountry = loc.countriesAndRegions?.some((c) =>
          c.toLowerCase().includes(q)
        );
        const matchesIP = loc.ipRanges?.some((r) =>
          r.cidrAddress.includes(q)
        );
        const matchesPolicy =
          a.directReferences.some((r) =>
            r.policyName.toLowerCase().includes(q)
          ) ||
          a.trustedLocationReferences.some((r) =>
            r.policyName.toLowerCase().includes(q)
          );
        if (!matchesName && !matchesCountry && !matchesIP && !matchesPolicy)
          return false;
      }

      // Type filter
      if (typeFilter !== "all") {
        const type = getLocationType(loc);
        if (typeFilter === "ip" && type !== "IP Range") return false;
        if (typeFilter === "country" && type !== "Country") return false;
        if (typeFilter === "compliant" && type !== "Compliant Network")
          return false;
      }

      // Trust filter
      if (trustFilter === "trusted" && !loc.isTrusted) return false;
      if (trustFilter === "untrusted" && loc.isTrusted) return false;

      // Warnings-only filter
      if (showOnlyWarnings && a.warnings.length === 0) return false;

      return true;
    });
  }, [result.locations, search, typeFilter, trustFilter, showOnlyWarnings]);

  const totalWarnings = result.locations.reduce(
    (sum, a) => sum + a.warnings.length,
    0
  );
  // Only count trust for location types that support it (IP-range, compliant network — NOT country)
  const trustableLocations = result.locations.filter(
    (a) => a.location["@odata.type"] !== "#microsoft.graph.countryNamedLocation"
  );
  const trustedCount = trustableLocations.filter(
    (a) => a.location.isTrusted
  ).length;
  const untrustedCount = trustableLocations.length - trustedCount;
  const countryCount = result.locations.length - trustableLocations.length;

  return (
    <div className="space-y-4">
      {/* Tenant-wide warnings */}
      <TenantWarningsBanner
        warnings={result.tenantWarnings}
        orphaned={result.orphanedReferences}
      />

      <Card>
        {/* Header stats */}
        <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
          <div>
            <h3 className="text-lg font-semibold text-white">
              Named Locations{" "}
              <span className="text-gray-500 font-normal">
                ({filtered.length}
                {filtered.length !== result.locations.length
                  ? ` of ${result.locations.length}`
                  : ""}
                )
              </span>
            </h3>
            <p className="text-xs text-gray-500 mt-0.5">
              {trustedCount} trusted · {untrustedCount} untrusted
              {countryCount > 0 && ` · ${countryCount} country`} ·{" "}
              {result.policiesUsingLocations} policies using locations ·{" "}
              {totalWarnings} warning{totalWarnings !== 1 ? "s" : ""}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Warnings-only toggle */}
            <button
              onClick={() => setShowOnlyWarnings(!showOnlyWarnings)}
              className={cn(
                "flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition-colors",
                showOnlyWarnings
                  ? "bg-orange-600 text-white"
                  : "bg-gray-800 text-gray-400 hover:text-white"
              )}
            >
              <AlertTriangle className="h-3.5 w-3.5" />
              {showOnlyWarnings ? "Show All" : "Warnings Only"}
            </button>

            {/* Type filter */}
            <div className="flex gap-1">
              {(
                [
                  { key: "all", label: "All Types" },
                  { key: "ip", label: "IP" },
                  { key: "country", label: "Country" },
                  { key: "compliant", label: "Compliant" },
                ] as const
              ).map((f) => (
                <button
                  key={f.key}
                  onClick={() => setTypeFilter(f.key)}
                  className={cn(
                    "rounded-lg px-2.5 py-1.5 text-xs font-medium transition-colors",
                    typeFilter === f.key
                      ? "bg-blue-600 text-white"
                      : "bg-gray-800 text-gray-400 hover:text-white"
                  )}
                >
                  {f.label}
                </button>
              ))}
            </div>

            {/* Trust filter */}
            <div className="flex gap-1">
              {(
                [
                  { key: "all", label: "Any Trust" },
                  { key: "trusted", label: "Trusted" },
                  { key: "untrusted", label: "Untrusted" },
                ] as const
              ).map((f) => (
                <button
                  key={f.key}
                  onClick={() => setTrustFilter(f.key)}
                  className={cn(
                    "rounded-lg px-2.5 py-1.5 text-xs font-medium transition-colors",
                    trustFilter === f.key
                      ? "bg-green-600 text-white"
                      : "bg-gray-800 text-gray-400 hover:text-white"
                  )}
                >
                  {f.label}
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
            placeholder="Search by location name, country, IP range, or policy name…"
            className="w-full rounded-lg border border-gray-700 bg-gray-800/50 py-2 pl-9 pr-9 text-sm text-gray-200 placeholder:text-gray-500 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500 transition-colors"
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

        {/* Location cards */}
        <div className="space-y-2">
          {filtered.map((analysis) => (
            <LocationCard key={analysis.location.id} analysis={analysis} />
          ))}
          {filtered.length === 0 && (
            <p className="py-8 text-center text-sm text-gray-500">
              {result.locations.length === 0
                ? "No named locations are configured in this tenant."
                : "No locations match the current filters."}
            </p>
          )}
        </div>
      </Card>
    </div>
  );
}
