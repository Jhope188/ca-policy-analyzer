/**
 * Named Location Analyzer
 *
 * Cross-references named locations against Conditional Access policies to:
 *   - Map which policies reference each named location
 *   - Detect "AllTrustedLocations" usage when some named locations aren't trusted
 *   - Flag country-based locations with empty country lists
 *   - Warn when a location is referenced but no longer exists (orphaned reference)
 *   - Surface IP-range locations that might be stale or overly broad
 */

import {
  NamedLocation,
  TenantContext,
} from "./graph-client";

// ─── Types ───────────────────────────────────────────────────────────────────

export type LocationWarningLevel = "critical" | "high" | "medium" | "info";

export interface LocationWarning {
  level: LocationWarningLevel;
  title: string;
  detail: string;
  recommendation: string;
}

export interface PolicyReference {
  policyId: string;
  policyName: string;
  policyState: string;
  /** "include" or "exclude" — how the location is used in the policy */
  usage: "include" | "exclude";
}

export interface LocationAnalysis {
  location: NamedLocation;
  /** All policies that reference this named location (by ID, or via AllTrustedLocations) */
  directReferences: PolicyReference[];
  /** Policies that reach this location via "AllTrustedLocations" (only if trusted) */
  trustedLocationReferences: PolicyReference[];
  /** Warnings specific to this named location */
  warnings: LocationWarning[];
}

export interface OrphanedLocationRef {
  locationId: string;
  policyId: string;
  policyName: string;
  usage: "include" | "exclude";
}

export interface LocationAnalysisResult {
  locations: LocationAnalysis[];
  /** Location IDs referenced by policies but not found in namedLocations */
  orphanedReferences: OrphanedLocationRef[];
  /** Tenant-wide location warnings (e.g. "AllTrustedLocations" with untrusted locations) */
  tenantWarnings: LocationWarning[];
  /** Total count of policies that use any location condition */
  policiesUsingLocations: number;
}

// ─── Well-known location pseudo-IDs ──────────────────────────────────────────

const ALL_TRUSTED_LOCATIONS = "AllTrusted";
/** Some tenants use the literal "All" keyword for locations */
const ALL_LOCATIONS = "All";

// ─── Analyzer ────────────────────────────────────────────────────────────────

export function analyzeNamedLocations(context: TenantContext): LocationAnalysisResult {
  const { policies, namedLocations } = context;

  // Build a lookup from location ID → NamedLocation
  const locationMap = new Map<string, NamedLocation>();
  for (const loc of namedLocations) {
    locationMap.set(loc.id, loc);
  }

  // Initialize per-location analysis
  const analysisMap = new Map<string, LocationAnalysis>();
  for (const loc of namedLocations) {
    analysisMap.set(loc.id, {
      location: loc,
      directReferences: [],
      trustedLocationReferences: [],
      warnings: [],
    });
  }

  const orphanedReferences: OrphanedLocationRef[] = [];
  let policiesUsingLocations = 0;

  // Track which policies use AllTrustedLocations
  const policiesUsingAllTrusted: PolicyReference[] = [];

  // Walk every policy and collect references
  for (const policy of policies) {
    const locs = policy.conditions.locations;
    if (!locs) continue;

    const hasAnyLocationCondition =
      locs.includeLocations.length > 0 || locs.excludeLocations.length > 0;
    if (hasAnyLocationCondition) policiesUsingLocations++;

    const processRefs = (ids: string[], usage: "include" | "exclude") => {
      for (const id of ids) {
        // Handle pseudo-IDs
        if (id === ALL_TRUSTED_LOCATIONS) {
          const ref: PolicyReference = {
            policyId: policy.id,
            policyName: policy.displayName,
            policyState: policy.state,
            usage,
          };
          policiesUsingAllTrusted.push(ref);

          // Link to every trusted location
          for (const loc of namedLocations) {
            if (loc.isTrusted) {
              analysisMap.get(loc.id)?.trustedLocationReferences.push(ref);
            }
          }
          continue;
        }

        if (id === ALL_LOCATIONS) continue; // "All" = all locations, no specific ref

        // Direct named location reference
        const analysis = analysisMap.get(id);
        if (analysis) {
          analysis.directReferences.push({
            policyId: policy.id,
            policyName: policy.displayName,
            policyState: policy.state,
            usage,
          });
        } else {
          // Orphaned — policy references a location that doesn't exist
          orphanedReferences.push({
            locationId: id,
            policyId: policy.id,
            policyName: policy.displayName,
            usage,
          });
        }
      }
    };

    processRefs(locs.includeLocations, "include");
    processRefs(locs.excludeLocations, "exclude");
  }

  // ── Per-location warnings ──────────────────────────────────────────────

  for (const [, analysis] of analysisMap) {
    const loc = analysis.location;
    const allRefs = [...analysis.directReferences, ...analysis.trustedLocationReferences];

    // 1) Country-based location with no countries defined
    if (
      loc["@odata.type"] === "#microsoft.graph.countryNamedLocation" &&
      (!loc.countriesAndRegions || loc.countriesAndRegions.length === 0)
    ) {
      analysis.warnings.push({
        level: "high",
        title: "Country location has no countries defined",
        detail:
          `"${loc.displayName}" is a country-based named location but has zero countries configured. ` +
          `Any policy referencing this location will not match any traffic, potentially creating an ` +
          `unintended gap or locking users out.`,
        recommendation:
          "Add the intended countries to this named location, or remove it from policies that reference it.",
      });
    }

    // 2) Location is NOT trusted but policies use "AllTrustedLocations"
    //    → this location is silently excluded from those policies' trust scope
    if (!loc.isTrusted && policiesUsingAllTrusted.length > 0 && allRefs.length === 0) {
      // Only warn if this location has direct refs from policies OR is the kind of
      // location you'd expect to be trusted (IP ranges, country locations)
      // Actually — the more important case is direct references + not trusted.
      // We handle that below.
    }

    // 3) Location is directly referenced in a policy that EXCLUDES trusted locations
    //    (i.e., policy says "block except trusted") but this location isn't trusted
    //    Country locations don't have a trusted toggle, so skip them here.
    if (
      !loc.isTrusted &&
      analysis.directReferences.length > 0 &&
      loc["@odata.type"] !== "#microsoft.graph.countryNamedLocation"
    ) {
      // Find policies that both reference this location AND use AllTrustedLocations
      const policyIdsReferencingThis = new Set(
        analysis.directReferences.map((r) => r.policyId)
      );
      const overlapPolicies = policiesUsingAllTrusted.filter(
        (r) => policyIdsReferencingThis.has(r.policyId)
      );

      if (overlapPolicies.length > 0) {
        analysis.warnings.push({
          level: "high",
          title: "Location referenced in policy but not marked as trusted",
          detail:
            `"${loc.displayName}" is directly referenced by ${overlapPolicies.length} policy(ies) that also use ` +
            `"All trusted locations". Since this location is NOT marked as trusted, users ` +
            `coming from this location will NOT be recognized as trusted and may be blocked or challenged unexpectedly.`,
          recommendation:
            `Mark "${loc.displayName}" as trusted in Entra ID → Protection → Conditional Access → Named locations, ` +
            `or remove it from the policy's location condition if it should not be trusted.`,
        });
      }
    }

    // 4) Named location is not trusted — general awareness
    //    Country locations do NOT have a trusted toggle (only IP-range locations do),
    //    so we skip this warning for country-based locations.
    if (
      !loc.isTrusted &&
      allRefs.length > 0 &&
      loc["@odata.type"] !== "#microsoft.graph.countryNamedLocation"
    ) {
      const enabledRefs = allRefs.filter((r) => r.policyState === "enabled");
      if (enabledRefs.length > 0) {
        analysis.warnings.push({
          level: "medium",
          title: "Location used by active policies but not marked as trusted",
          detail:
            `"${loc.displayName}" is referenced by ${enabledRefs.length} enabled policy(ies) but is not marked ` +
            `as trusted. If any of these policies condition on "All trusted locations", ` +
            `this location's IP ranges will not be included in the trusted set.`,
          recommendation:
            `Review whether "${loc.displayName}" should be marked as trusted. If it represents ` +
            `corporate offices, VPN exit points, or other known-good networks, mark it as trusted.`,
        });
      }
    }

    // 4b) Country location: check lookup method and unknown countries setting
    if (loc["@odata.type"] === "#microsoft.graph.countryNamedLocation") {
      // GPS lookup method warning
      if (loc.countryLookupMethod === "clientIpAddress") {
        // IP-based lookup is the default and most common — no warning needed
      } else if (loc.countryLookupMethod === "authenticatorAppGps") {
        analysis.warnings.push({
          level: "info",
          title: "Country lookup uses GPS coordinates (Authenticator app)",
          detail:
            `"${loc.displayName}" determines country by GPS coordinates from the Microsoft Authenticator app ` +
            `rather than IP address geolocation. GPS-based lookup requires users to have the Authenticator app ` +
            `installed with location sharing enabled. Users without the app or with GPS disabled will not ` +
            `match this location.`,
          recommendation:
            "Ensure all users in scope have the Microsoft Authenticator app installed with GPS location " +
            "sharing enabled. Consider whether IP-based lookup would provide broader coverage.",
        });
      }

      // Include unknown countries/regions
      if (loc.includeUnknownCountriesAndRegions) {
        analysis.warnings.push({
          level: "medium",
          title: "Include unknown countries/regions is enabled",
          detail:
            `"${loc.displayName}" includes unknown countries and regions. Traffic from IP addresses that ` +
            `cannot be mapped to a country (e.g., VPNs, Tor exit nodes, or new IP allocations) will match ` +
            `this location. This broadens the scope and may include traffic from unexpected sources.`,
          recommendation:
            "Unless you specifically need to capture unresolvable traffic, consider disabling " +
            "\"Include unknown countries/regions\" to tighten the location scope.",
        });
      }
    }

    // 5) IP-range location with very broad CIDR ranges
    if (
      loc["@odata.type"] === "#microsoft.graph.ipNamedLocation" &&
      loc.ipRanges
    ) {
      const broadRanges = loc.ipRanges.filter((r) => {
        const parts = r.cidrAddress.split("/");
        const prefix = parseInt(parts[1] ?? "32", 10);
        // IPv4: /8 or less, IPv6: /32 or less
        const isIPv6 = r.cidrAddress.includes(":");
        return isIPv6 ? prefix <= 32 : prefix <= 16;
      });

      if (broadRanges.length > 0) {
        analysis.warnings.push({
          level: "info",
          title: "Very broad IP range detected",
          detail:
            `"${loc.displayName}" contains ${broadRanges.length} very broad CIDR range(s): ` +
            `${broadRanges.map((r) => r.cidrAddress).join(", ")}. ` +
            `Broad ranges may inadvertently trust traffic from unintended sources.`,
          recommendation:
            "Review whether these broad ranges are intentional. Consider narrowing to specific subnets.",
        });
      }
    }

    // 6) Location is trusted but has no policy references at all (unused)
    if (loc.isTrusted && analysis.directReferences.length === 0 && analysis.trustedLocationReferences.length === 0) {
      // Only flag if there ARE policies using locations (otherwise tenant just doesn't use location conditions)
      if (policiesUsingLocations > 0) {
        analysis.warnings.push({
          level: "info",
          title: "Trusted location not referenced by any policy",
          detail:
            `"${loc.displayName}" is marked as trusted but no policy references it directly or via "All trusted locations". ` +
            `This location has no effect on Conditional Access evaluation.`,
          recommendation:
            "If this location is no longer needed, consider removing it. If policies should reference it, " +
            "update the relevant policies to include or exclude this location.",
        });
      }
    }
  }

  // ── Tenant-wide location warnings ──────────────────────────────────────

  const tenantWarnings: LocationWarning[] = [];

  // Warn if policies use "AllTrustedLocations" but some named locations aren't trusted
  if (policiesUsingAllTrusted.length > 0) {
    const untrustedLocations = namedLocations.filter((l) => !l.isTrusted);
    if (untrustedLocations.length > 0) {
      const untrustedNames = untrustedLocations.map((l) => l.displayName);
      tenantWarnings.push({
        level: "high",
        title: `${policiesUsingAllTrusted.length} policy(ies) use "All trusted locations" but ${untrustedLocations.length} location(s) are NOT trusted`,
        detail:
          `Policies referencing "All trusted locations" will NOT include: ${untrustedNames.join(", ")}. ` +
          `Users signing in from these locations will not be recognized as trusted and may be ` +
          `blocked or required to satisfy additional controls. This can cause accidental lockouts ` +
          `if administrators expect all named locations to be treated as trusted.`,
        recommendation:
          "Review each untrusted named location and mark it as trusted if it represents a known-good " +
          "network (corporate office, VPN, datacenter). If it should NOT be trusted, ensure policies " +
          "handle non-trusted traffic appropriately.",
      });
    }
  }

  // Warn about orphaned references
  if (orphanedReferences.length > 0) {
    const uniqueLocIds = [...new Set(orphanedReferences.map((r) => r.locationId))];
    tenantWarnings.push({
      level: "medium",
      title: `${uniqueLocIds.length} deleted or missing named location(s) still referenced by policies`,
      detail:
        `${orphanedReferences.length} policy reference(s) point to named location IDs that no longer exist: ` +
        `${uniqueLocIds.join(", ")}. These stale references may cause the policy's location condition ` +
        `to behave unexpectedly — the missing location will never match, potentially blocking or ` +
        `allowing access in ways you don't intend.`,
      recommendation:
        "Update or remove the stale location references from the affected policies. " +
        "The location may have been deleted or the ID may have changed.",
    });
  }

  // No named locations at all but policies try to use them
  if (namedLocations.length === 0 && policiesUsingLocations > 0) {
    tenantWarnings.push({
      level: "high",
      title: "Policies use location conditions but no named locations are defined",
      detail:
        `${policiesUsingLocations} policy(ies) use location conditions, but no named locations ` +
        `are configured in the tenant. This likely means the policies reference "All trusted locations" ` +
        `with an empty trust set, which will never match — potentially blocking all users.`,
      recommendation:
        "Define named locations for your corporate networks, VPN exit points, and trusted countries, " +
        "then mark them as trusted.",
    });
  }

  // Sort locations: those with warnings first, then by name
  const locations = Array.from(analysisMap.values()).sort((a, b) => {
    if (a.warnings.length !== b.warnings.length)
      return b.warnings.length - a.warnings.length;
    return a.location.displayName.localeCompare(b.location.displayName);
  });

  return {
    locations,
    orphanedReferences,
    tenantWarnings,
    policiesUsingLocations,
  };
}

// ─── Helpers for UI ──────────────────────────────────────────────────────────

/** Human-readable location type */
export function getLocationType(loc: NamedLocation): string {
  switch (loc["@odata.type"]) {
    case "#microsoft.graph.ipNamedLocation":
      return "IP Range";
    case "#microsoft.graph.countryNamedLocation":
      return "Country";
    case "#microsoft.graph.compliantNetworkNamedLocation":
      return "Compliant Network";
    default:
      return "Unknown";
  }
}

/** Summary string for a location (countries or IP count) */
export function getLocationSummary(loc: NamedLocation): string {
  if (loc["@odata.type"] === "#microsoft.graph.countryNamedLocation") {
    const count = loc.countriesAndRegions?.length ?? 0;
    return count === 0
      ? "No countries defined"
      : `${count} ${count === 1 ? "country" : "countries"}: ${loc.countriesAndRegions!.join(", ")}`;
  }
  if (loc["@odata.type"] === "#microsoft.graph.ipNamedLocation") {
    const count = loc.ipRanges?.length ?? 0;
    return count === 0
      ? "No IP ranges defined"
      : `${count} IP range${count !== 1 ? "s" : ""}`;
  }
  if (loc["@odata.type"] === "#microsoft.graph.compliantNetworkNamedLocation") {
    return "Global Secure Access compliant network";
  }
  return "—";
}
