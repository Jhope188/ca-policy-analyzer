/**
 * Persona × Required-Control Coverage Analyzer (Phase 2)
 *
 * For each Zero Trust persona defined in src/lib/personas.ts, walks the
 * tenant's enabled CA policies and determines which of the persona's
 * expectedControls are actually implemented.
 *
 * Produces:
 *   - A coverage matrix (persona → control → status) for the Persona tab
 *   - High-severity findings for critical gaps (e.g. Admins missing MFA)
 *
 * Design notes:
 *   - We only count "enabled" policies. Report-only and disabled don't enforce.
 *   - A policy can satisfy multiple controls and multiple personas.
 *   - Persona membership is inferred from displayName (detectPersona) plus
 *     a few structural fallbacks (includeUsers=All -> global; includeRoles
 *     populated -> admins; includeGuestsOrExternalUsers -> externals).
 *   - Control detection is pragmatic, not exhaustive - it matches the
 *     shapes used by Kenneth's and Joey's baselines.
 */

import { ConditionalAccessPolicy, TenantContext } from "./graph-client";
import { policyUsesPhishingResistant } from "./phishing-resistant";
import {
  Persona,
  PersonaControl,
  PERSONA_META,
  PERSONA_ORDER,
  detectPersona,
} from "./personas";
import { Finding, Severity } from "./analyzer";

// ─── Types ───────────────────────────────────────────────────────────────────

export type ControlStatus = "present" | "partial" | "missing" | "n/a";

export interface ControlCoverage {
  control: PersonaControl;
  label: string;
  description: string;
  status: ControlStatus;
  /** Enabled policies that satisfy this control for this persona. */
  satisfyingPolicies: Array<{ id: string; displayName: string }>;
  /** If status === 'partial': enabled-for-reporting policies that would satisfy it. */
  reportOnlyPolicies: Array<{ id: string; displayName: string }>;
}

export interface PersonaCoverageRow {
  persona: Persona;
  /** Policies in the tenant assigned to this persona (any state). */
  assignedPolicies: Array<{
    id: string;
    displayName: string;
    state: ConditionalAccessPolicy["state"];
  }>;
  /** Number of enabled policies in this persona bucket. */
  enabledCount: number;
  controls: ControlCoverage[];
  /** present + (partial * 0.5) divided by total expected, ×100 (0–100). */
  score: number;
  /** Persona-level rollup status. */
  status: ControlStatus;
}

export interface PersonaCoverageResult {
  rows: PersonaCoverageRow[];
  /** Total controls expected across all personas (excluding unknown). */
  totalExpected: number;
  /** Sum of present + (partial × 0.5) across all personas. */
  totalCovered: number;
  /** Overall coverage score 0–100. */
  overallScore: number;
  /** High-severity gap findings to merge into the main findings list. */
  findings: Finding[];
}

// ─── Control labels ──────────────────────────────────────────────────────────

const CONTROL_LABELS: Record<PersonaControl, { label: string; description: string }> = {
  "block-legacy-auth": {
    label: "Block legacy authentication",
    description:
      "Policy with clientAppTypes 'exchangeActiveSync' / 'other' and a Block grant.",
  },
  "require-mfa": {
    label: "Require multi-factor authentication",
    description: "Grant controls require MFA (built-in MFA or auth strength).",
  },
  "require-compliant-device": {
    label: "Require compliant or hybrid-joined device",
    description: "Grant controls require compliantDevice or domainJoinedDevice.",
  },
  "sign-in-risk": {
    label: "Sign-in risk based access",
    description: "Conditions include one or more signInRiskLevels.",
  },
  "user-risk": {
    label: "User risk based access",
    description: "Conditions include one or more userRiskLevels.",
  },
  "session-sif": {
    label: "Sign-in frequency / session controls",
    description: "Session controls enforce signInFrequency or persistentBrowser.",
  },
  "block-countries": {
    label: "Country / location block",
    description:
      "Location condition combined with a Block grant (allow-list or deny-list).",
  },
  "phishing-resistant-mfa": {
    label: "Phishing-resistant MFA",
    description:
      "Authentication strength = phishing-resistant (FIDO2, Windows Hello, X.509).",
  },
  "block-non-corp-network": {
    label: "Restrict to corporate network / trusted locations",
    description:
      "Location condition that excludes trusted locations combined with Block.",
  },
  "block-high-risk-apps": {
    label: "Block high-risk applications",
    description: "Block grant scoped to specific high-risk applications.",
  },
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

function isEnabled(p: ConditionalAccessPolicy): boolean {
  return p.state === "enabled";
}
function isReportOnly(p: ConditionalAccessPolicy): boolean {
  return p.state === "enabledForReportingButNotEnforced";
}

function grantControls(p: ConditionalAccessPolicy): string[] {
  return p.grantControls?.builtInControls ?? [];
}

function hasGrantBlock(p: ConditionalAccessPolicy): boolean {
  return grantControls(p).includes("block");
}

function hasGrantMfa(p: ConditionalAccessPolicy): boolean {
  if (grantControls(p).includes("mfa")) return true;
  // Auth strength counts when it satisfies MFA - best effort: any auth strength
  // attached implies the admin meant to require MFA-equivalent auth.
  return Boolean(p.grantControls?.authenticationStrength?.id);
}

function hasGrantCompliantDevice(p: ConditionalAccessPolicy): boolean {
  const c = grantControls(p);
  return c.includes("compliantDevice") || c.includes("domainJoinedDevice");
}

function hasSignInRisk(p: ConditionalAccessPolicy): boolean {
  // Standard sign-in risk levels (all user types)
  if ((p.conditions.signInRiskLevels?.length ?? 0) > 0) return true;
  // Agent identity risk (Graph API preview field - agentIdRiskLevels is a
  // string like "high" rather than an array, set alongside
  // clientApplications.includeAgentIdServicePrincipals for agent CA policies).
  if (p.conditions.agentIdRiskLevels) return true;
  return false;
}

function hasUserRisk(p: ConditionalAccessPolicy): boolean {
  return (p.conditions.userRiskLevels?.length ?? 0) > 0;
}

function hasSessionSif(p: ConditionalAccessPolicy): boolean {
  return Boolean(
    p.sessionControls?.signInFrequency?.isEnabled ||
      p.sessionControls?.persistentBrowser?.isEnabled
  );
}

function hasLegacyAuthBlock(p: ConditionalAccessPolicy): boolean {
  const types = p.conditions.clientAppTypes ?? [];
  const targetsLegacy =
    types.includes("exchangeActiveSync") || types.includes("other");
  return targetsLegacy && hasGrantBlock(p);
}

function hasLocationCondition(p: ConditionalAccessPolicy): boolean {
  const loc = p.conditions.locations;
  if (!loc) return false;
  return (
    (loc.includeLocations?.length ?? 0) > 0 ||
    (loc.excludeLocations?.length ?? 0) > 0
  );
}

function hasCountryBlock(p: ConditionalAccessPolicy): boolean {
  return hasLocationCondition(p) && hasGrantBlock(p);
}

function hasNonCorpNetworkBlock(
  p: ConditionalAccessPolicy,
  ctx?: TenantContext
): boolean {
  // Heuristic: location condition that restricts to known/trusted locations
  // combined with a Block grant.
  const loc = p.conditions.locations;
  if (!loc) return false;
  if (!hasGrantBlock(p)) return false;

  const excludeIds = loc.excludeLocations ?? [];
  const includeIds = loc.includeLocations ?? [];

  // 1. Explicit "AllTrusted" sentinel or any ID whose display name contains
  //    "trusted" (covers tenants that name their location "Trusted IPs" etc.)
  const excludesTrustedSentinel = excludeIds.some(
    (l) => l === "AllTrusted" || l.toLowerCase().includes("trusted")
  );
  if (excludesTrustedSentinel) return true;

  // 2. Check against actual named locations in the tenant that are marked
  //    isTrusted - covers policies that exclude a trusted location by GUID.
  if (ctx?.namedLocations) {
    const trustedIds = new Set(
      ctx.namedLocations
        .filter((nl) => nl.isTrusted)
        .map((nl) => nl.id)
    );
    if (excludeIds.some((id) => trustedIds.has(id))) return true;
  }

  // 3. "All locations" include + any non-empty exclude + Block is a network
  //    restriction pattern (e.g. include All, exclude a specific named location
  //    like a corp IP range - inverse allow-list).
  if (includeIds.includes("All") && excludeIds.length > 0) return true;

  return false;
}

// Phishing-resistant detection lives in src/lib/phishing-resistant.ts so the
// scorecard, persona coverage, and the per-policy analyzer all share a single
// authoritative implementation that inspects allowedCombinations from the
// tenant authentication-strength catalog.
const hasPhishingResistantMfa = policyUsesPhishingResistant;

function hasHighRiskAppBlock(p: ConditionalAccessPolicy): boolean {
  if (!hasGrantBlock(p)) return false;
  const includeApps = p.conditions.applications.includeApplications ?? [];
  // If it scopes to specific apps (not "All") and blocks, count it.
  return includeApps.length > 0 && !includeApps.includes("All");
}

const CONTROL_DETECTORS: Record<
  PersonaControl,
  (p: ConditionalAccessPolicy, ctx?: TenantContext) => boolean
> = {
  "block-legacy-auth": hasLegacyAuthBlock,
  "require-mfa": hasGrantMfa,
  "require-compliant-device": hasGrantCompliantDevice,
  "sign-in-risk": hasSignInRisk,
  "user-risk": hasUserRisk,
  "session-sif": hasSessionSif,
  "block-countries": hasCountryBlock,
  "phishing-resistant-mfa": hasPhishingResistantMfa,
  "block-non-corp-network": hasNonCorpNetworkBlock,
  "block-high-risk-apps": hasHighRiskAppBlock,
};

// ─── Persona assignment ──────────────────────────────────────────────────────

/**
 * Decide which personas a policy belongs to. A policy can target multiple
 * personas (e.g. a global MFA policy targets "global" but also indirectly
 * covers "internals" if it targets All users).
 */
function policyPersonas(p: ConditionalAccessPolicy): Set<Persona> {
  const out = new Set<Persona>();
  const named = detectPersona(p.displayName);
  if (named !== "unknown") out.add(named);
  // A general service-account policy (corpserviceaccounts) also covers the
  // Microsoft 365 Service Accounts persona - both need the same network
  // restriction control and a single "ServiceAccounts" policy satisfies both.
  if (named === "corpserviceaccounts") out.add("microsoft365serviceaccounts");

  const users = p.conditions.users;
  const includesAllUsers = users.includeUsers.includes("All");
  if (includesAllUsers) {
    // A policy targeting all users enforces on every internal human persona:
    // Global, Internals (employees), and also Admins and Developers - those are
    // users too, so a tenant-wide control genuinely covers them. Crediting them
    // here prevents a baseline control (e.g. All-Users MFA) from being falsely
    // reported as a per-persona gap for admins/developers.
    out.add("global");
    out.add("internals");
    out.add("admins");
    out.add("developers");
  }
  if ((users.includeRoles?.length ?? 0) > 0) out.add("admins");
  // Guests / external users. Guest Admins are a subset of external users, so a
  // guest-targeting policy also covers them for baseline controls (e.g. MFA).
  const targetsGuests =
    users.includeGuestsOrExternalUsers != null ||
    users.includeUsers.includes("GuestsOrExternalUsers");
  if (targetsGuests) {
    out.add("externals");
    out.add("guestadmins");
  }

  // If we still have nothing, default to "unknown" so the policy at least
  // appears somewhere.
  if (out.size === 0) out.add("unknown");
  return out;
}

// ─── Main ────────────────────────────────────────────────────────────────────

let coverageFindingCounter = 0;
function nextCoverageFindingId(): string {
  return `PC-${String(++coverageFindingCounter).padStart(3, "0")}`;
}

/**
 * Severity heuristic per missing control. Admins missing MFA is critical;
 * Internals missing user-risk is high; cosmetic ones are medium.
 */
function severityForGap(
  persona: Persona,
  control: PersonaControl
): Severity {
  if (persona === "admins") {
    if (control === "require-mfa" || control === "phishing-resistant-mfa")
      return "critical";
    return "high";
  }
  if (persona === "internals") {
    if (control === "require-mfa") return "critical";
    if (control === "block-legacy-auth") return "high";
    return "medium";
  }
  if (persona === "global") {
    if (control === "block-legacy-auth") return "high";
    return "medium";
  }
  if (persona === "externals" && control === "require-mfa") return "high";
  return "medium";
}

export function analyzePersonaCoverage(
  context: TenantContext
): PersonaCoverageResult {
  coverageFindingCounter = 0;

  // Bucket all tenant policies by persona once.
  const buckets: Record<Persona, ConditionalAccessPolicy[]> = Object.fromEntries(
    PERSONA_ORDER.map((p) => [p, [] as ConditionalAccessPolicy[]])
  ) as unknown as Record<Persona, ConditionalAccessPolicy[]>;

  for (const p of context.policies) {
    for (const persona of policyPersonas(p)) buckets[persona].push(p);
  }

  const rows: PersonaCoverageRow[] = [];
  const findings: Finding[] = [];
  let totalExpected = 0;
  let totalCovered = 0;

  for (const persona of PERSONA_ORDER) {
    if (persona === "unknown") continue;
    const meta = PERSONA_META[persona];
    const assigned = buckets[persona];

    const assignedPolicies = assigned.map((p) => ({
      id: p.id,
      displayName: p.displayName,
      state: p.state,
    }));
    const enabledCount = assigned.filter(isEnabled).length;

    const controls: ControlCoverage[] = [];
    let presentCount = 0;
    let partialCount = 0;

    for (const control of meta.expectedControls) {
      const detector = CONTROL_DETECTORS[control];
      const enabledHits = assigned
        .filter((p) => isEnabled(p) && detector(p, context))
        .map((p) => ({ id: p.id, displayName: p.displayName }));
      const reportOnlyHits = assigned
        .filter((p) => isReportOnly(p) && detector(p, context))
        .map((p) => ({ id: p.id, displayName: p.displayName }));

      let status: ControlStatus;
      if (enabledHits.length > 0) {
        status = "present";
        presentCount++;
      } else if (reportOnlyHits.length > 0) {
        status = "partial";
        partialCount++;
      } else {
        status = "missing";
      }

      controls.push({
        control,
        label: CONTROL_LABELS[control].label,
        description: CONTROL_LABELS[control].description,
        status,
        satisfyingPolicies: enabledHits,
        reportOnlyPolicies: reportOnlyHits,
      });

      if (status === "missing") {
        const sev = severityForGap(persona, control);
        findings.push({
          id: nextCoverageFindingId(),
          policyId: "tenant-wide",
          policyName: `Persona coverage: ${meta.label}`,
          severity: sev,
          category: "Persona Coverage",
          title: `${meta.label}: missing ${CONTROL_LABELS[control].label}`,
          description:
            `No enabled policy in the ${meta.label} persona implements "${CONTROL_LABELS[control].label}". ` +
            CONTROL_LABELS[control].description,
          recommendation:
            persona === "admins"
              ? `Deploy a dedicated ${meta.label} policy that requires this control. Reference baselines: Kenneth van Surksum or Joey Verlinden.`
              : `Add this control to an existing ${meta.label} policy or deploy a new one. Compare your tenant against a community baseline (Templates tab).`,
        });
      }
    }

    const expected = meta.expectedControls.length;
    totalExpected += expected;
    totalCovered += presentCount + partialCount * 0.5;

    const score =
      expected === 0 ? 100 : Math.round(((presentCount + partialCount * 0.5) / expected) * 100);

    let rowStatus: ControlStatus;
    if (expected === 0) rowStatus = "n/a";
    else if (presentCount === expected) rowStatus = "present";
    else if (presentCount + partialCount === 0) rowStatus = "missing";
    else rowStatus = "partial";

    rows.push({
      persona,
      assignedPolicies,
      enabledCount,
      controls,
      score,
      status: rowStatus,
    });
  }

  const overallScore =
    totalExpected === 0 ? 100 : Math.round((totalCovered / totalExpected) * 100);

  return { rows, totalExpected, totalCovered, overallScore, findings };
}
