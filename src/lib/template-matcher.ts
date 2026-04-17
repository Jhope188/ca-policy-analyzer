/**
 * Template Matching Engine
 *
 * Compares a tenant's existing CA policies against the recommended
 * policy templates to determine which are present, missing, or partially matched.
 */

import { ConditionalAccessPolicy, TenantContext, isLicensed } from "@/lib/graph-client";
import {
  PolicyTemplate,
  TemplateFingerprint,
  POLICY_TEMPLATES,
  TemplateCategory,
  TemplatePriority,
  ADMIN_ROLE_IDS,
} from "@/data/policy-templates";
import { ROLE_NAME_MAP } from "@/lib/role-names";

// ─── Types ───────────────────────────────────────────────────────────────────

export type MatchStatus = "present" | "partial" | "missing" | "not-applicable";

export interface TemplateMatch {
  template: PolicyTemplate;
  status: MatchStatus;
  /** Confidence 0-100 that the tenant has this policy */
  confidence: number;
  /** The tenant policy(ies) that best match this template */
  matchingPolicies: MatchedPolicy[];
  /** Differences between the template and the best match */
  differences: string[];
  /** Actionable gaps explaining how to reach 100 % */
  gaps: string[];
}

export interface MatchedPolicy {
  policy: ConditionalAccessPolicy;
  similarity: number; // 0-100
  differences: string[]; // per-policy gaps
}

export interface TemplateAnalysisResult {
  matches: TemplateMatch[];
  presentCount: number;
  partialCount: number;
  missingCount: number;
  notApplicableCount: number;
  totalTemplates: number;
  coverageScore: number; // 0-100
  byCategoryScore: Record<TemplateCategory, number>;
}

// ─── Matching Logic ──────────────────────────────────────────────────────────

/**
 * Scores how well a single tenant policy matches a template fingerprint.
 * Returns 0-100 similarity score.
 */
function scorePolicyMatch(
  policy: ConditionalAccessPolicy,
  fingerprint: TemplateFingerprint
): { score: number; differences: string[] } {
  let totalWeight = 0;
  let matchedWeight = 0;
  const differences: string[] = [];

  const apps = policy.conditions.applications;
  const users = policy.conditions.users;
  const grant = policy.grantControls;
  const session = policy.sessionControls;

  // ── App targeting (weight: 25) ──────────────────────────────────────
  if (fingerprint.includeApps.length > 0) {
    totalWeight += 25;
    const fpApps = new Set(fingerprint.includeApps.map((a) => a.toLowerCase()));
    const policyApps = new Set(
      apps.includeApplications.map((a) => a.toLowerCase())
    );

    if (setsOverlap(fpApps, policyApps)) {
      matchedWeight += 25;
    } else {
      differences.push(
        `Apps: template targets [${fingerprint.includeApps.join(", ")}], policy targets [${apps.includeApplications.join(", ")}]`
      );
    }
  }

  // ── User actions (weight: 25 if defined) ───────────────────────────
  if (
    fingerprint.includeUserActions &&
    fingerprint.includeUserActions.length > 0
  ) {
    totalWeight += 25;
    const fpActions = new Set(fingerprint.includeUserActions.map((a) => a.toLowerCase()));
    const policyActions = new Set((apps.includeUserActions ?? []).map((a) => a.toLowerCase()));

    if (setsOverlap(fpActions, policyActions)) {
      matchedWeight += 25;
    } else {
      differences.push(
        `User actions: template requires [${fingerprint.includeUserActions.join(", ")}], not found in policy`
      );
    }
  }

  // ── Grant controls (weight: 25) ────────────────────────────────────
  if (fingerprint.grantControls && fingerprint.grantControls.length > 0) {
    totalWeight += 25;
    const policyControls = new Set((grant?.builtInControls ?? []).map((c) => c.toLowerCase()));
    const templateControls = new Set(fingerprint.grantControls.map((c) => c.toLowerCase()));

    // Authentication strengths satisfy (and exceed) an "mfa" grant control requirement
    const hasAuthStrength = grant?.authenticationStrength != null;
    const templateRequiresMfa = templateControls.has("mfa");

    if (hasAuthStrength && templateRequiresMfa) {
      // Auth strengths are a superset of MFA — full credit
      matchedWeight += 25;
    } else {
      const overlap = [...templateControls].filter((c) => policyControls.has(c));

      if (overlap.length === templateControls.size) {
        matchedWeight += 25;
      } else if (overlap.length > 0) {
        matchedWeight += 12;
        differences.push(
          `Grant controls: template requires [${fingerprint.grantControls.join(", ")}], policy has [${[...policyControls].join(", ")}]`
        );
      } else {
        differences.push(
          `Grant controls: template requires [${fingerprint.grantControls.join(", ")}], policy has [${[...policyControls].join(", ")}]`
        );
      }
    }
  }

  // ── User targeting (weight: 15) ────────────────────────────────────
  if (fingerprint.targetsAllUsers) {
    totalWeight += 15;
    if (users.includeUsers.includes("All")) {
      matchedWeight += 15;
    } else {
      differences.push("Users: template targets All Users, policy does not");
    }
  }

  if (fingerprint.targetRoles && fingerprint.targetRoles.length > 0) {
    totalWeight += 15;
    const policyRoles = new Set(
      users.includeRoles.map((r) => r.toLowerCase())
    );
    const templateRoles = new Set(
      fingerprint.targetRoles.map((r) => r.toLowerCase())
    );
    const overlap = [...templateRoles].filter((r) => policyRoles.has(r));
    const missing = [...templateRoles].filter((r) => !policyRoles.has(r));
    const ratio = overlap.length / templateRoles.size;

    if (ratio >= 0.5) {
      matchedWeight += Math.round(15 * ratio);
      if (missing.length > 0) {
        const missingNames = missing.map(
          (id) => ROLE_NAME_MAP[id] ?? id
        );
        differences.push(
          `Roles: missing ${missing.length} of ${templateRoles.size} admin roles — ${missingNames.join(", ")}`
        );
      }
    } else {
      const missingNames = missing.map(
        (id) => ROLE_NAME_MAP[id] ?? id
      );
      differences.push(
        `Roles: policy only includes ${policyRoles.size} of ${templateRoles.size} required admin roles — missing ${missingNames.join(", ")}`
      );
    }
  }

  if (fingerprint.targetsGuests) {
    totalWeight += 15;
    const hasGuestCondition =
      users.includeGuestsOrExternalUsers != null ||
      users.includeUsers.includes("GuestsOrExternalUsers");
    if (hasGuestCondition) {
      matchedWeight += 15;
    } else if (users.includeUsers.includes("All")) {
      matchedWeight += 10; // All users includes guests implicitly
      differences.push(
        "Users: template targets guests specifically, policy targets All Users (implicit coverage)"
      );
    } else {
      differences.push(
        "Users: template targets guest/external users, not found in policy"
      );
    }
  }

  // ── Client app types (weight: 10) ──────────────────────────────────
  if (fingerprint.clientAppTypes && fingerprint.clientAppTypes.length > 0) {
    totalWeight += 10;
    const policyTypes = new Set(policy.conditions.clientAppTypes.map((t) => t.toLowerCase()));
    const templateTypes = new Set(fingerprint.clientAppTypes.map((t) => t.toLowerCase()));
    const overlap = [...templateTypes].filter((t) => policyTypes.has(t));

    if (overlap.length > 0) {
      matchedWeight += 10;
    } else {
      differences.push(
        `Client apps: template requires [${fingerprint.clientAppTypes.join(", ")}], policy uses [${policy.conditions.clientAppTypes.join(", ")}]`
      );
    }
  }

  // ── Risk levels (weight: 20) ───────────────────────────────────────
  if (fingerprint.signInRiskLevels && fingerprint.signInRiskLevels.length > 0) {
    totalWeight += 20;
    const policyRisk = new Set((policy.conditions.signInRiskLevels ?? []).map((r) => r.toLowerCase()));
    const templateRisk = new Set(fingerprint.signInRiskLevels.map((r) => r.toLowerCase()));
    const overlap = [...templateRisk].filter((r) => policyRisk.has(r));

    if (overlap.length > 0) {
      matchedWeight += 20;
    } else {
      differences.push(
        `Sign-in risk: template requires [${fingerprint.signInRiskLevels.join(", ")}], not configured`
      );
    }
  }

  if (fingerprint.userRiskLevels && fingerprint.userRiskLevels.length > 0) {
    totalWeight += 20;
    const policyRisk = new Set((policy.conditions.userRiskLevels ?? []).map((r) => r.toLowerCase()));
    const templateRisk = new Set(fingerprint.userRiskLevels.map((r) => r.toLowerCase()));
    const overlap = [...templateRisk].filter((r) => policyRisk.has(r));

    if (overlap.length > 0) {
      matchedWeight += 20;
    } else {
      differences.push(
        `User risk: template requires [${fingerprint.userRiskLevels.join(", ")}], not configured`
      );
    }
  }

  // ── Location condition (weight: 10) ────────────────────────────────
  if (fingerprint.usesLocationCondition) {
    totalWeight += 10;
    if (
      policy.conditions.locations &&
      (policy.conditions.locations.includeLocations.length > 0 ||
        policy.conditions.locations.excludeLocations.length > 0)
    ) {
      matchedWeight += 10;
    } else {
      differences.push("Locations: template requires location conditions, not configured");
    }
  }

  // ── Platform conditions (weight: 10) ───────────────────────────────
  if (fingerprint.platforms) {
    totalWeight += 10;
    const policyPlatforms = policy.conditions.platforms;
    if (policyPlatforms) {
      const fpInclude = new Set(fingerprint.platforms.include);
      const pInc = new Set(policyPlatforms.includePlatforms);
      if (setsOverlap(fpInclude, pInc)) {
        matchedWeight += 10;
      } else {
        differences.push("Platforms: platform targeting differs from template");
      }
    } else {
      differences.push("Platforms: template requires platform conditions, not configured");
    }
  }

  // ── Session controls (weight: 10) ──────────────────────────────────
  if (fingerprint.sessionSignInFrequency) {
    totalWeight += 10;
    if (session?.signInFrequency?.isEnabled) {
      matchedWeight += 10;
    } else {
      differences.push("Session: template requires sign-in frequency, not configured");
    }
  }

  if (fingerprint.sessionPersistentBrowser) {
    totalWeight += 5;
    if (session?.persistentBrowser?.isEnabled) {
      matchedWeight += 5;
    } else {
      differences.push("Session: template requires persistent browser control, not configured");
    }
  }

  if (fingerprint.sessionCloudAppSecurity) {
    totalWeight += 15;
    if (session?.cloudAppSecurity?.isEnabled) {
      matchedWeight += 15;
    } else {
      differences.push("Session: template requires Conditional Access App Control (block downloads), not configured");
    }
  }

  // ── Authentication flows (weight: 15) ──────────────────────────────
  if (
    fingerprint.authenticationFlows &&
    fingerprint.authenticationFlows.length > 0
  ) {
    totalWeight += 15;
    const authFlows = (policy.conditions as Record<string, unknown>)
      .authenticationFlows as
      | { transferMethods?: string }
      | null
      | undefined;
    if (authFlows?.transferMethods) {
      matchedWeight += 15;
    } else {
      differences.push(
        "Auth flows: template blocks authentication transfer, not configured"
      );
    }
  }

  const score = totalWeight > 0 ? Math.round((matchedWeight / totalWeight) * 100) : 0;
  return { score, differences };
}

function setsOverlap(a: Set<string>, b: Set<string>): boolean {
  for (const item of a) {
    if (b.has(item)) return true;
  }
  return false;
}

// ─── Main Analysis ───────────────────────────────────────────────────────────

export function analyzeTemplates(
  context: TenantContext,
  customTemplates?: PolicyTemplate[]
): TemplateAnalysisResult {
  const activePolicies = context.policies.filter(
    (p) => p.state !== "disabled"
  );
  const allPolicies = context.policies;

  const templates = customTemplates ?? POLICY_TEMPLATES;

  const matches: TemplateMatch[] = templates.map((template) => {
    // License-aware: if the template requires a license the tenant doesn't have,
    // mark it not-applicable so it doesn't penalise the coverage score.
    if (
      template.licenseRequirement &&
      !isLicensed(context.licenses, template.licenseRequirement)
    ) {
      return {
        template,
        status: "not-applicable" as MatchStatus,
        confidence: 0,
        matchingPolicies: [],
        differences: [],
        gaps: [],
      };
    }

    // Score every policy against this template
    const scored = allPolicies.map((policy) => {
      const { score, differences } = scorePolicyMatch(
        policy,
        template.fingerprint
      );
      return { policy, similarity: score, differences };
    });

    // Sort by similarity descending, then prefer active (enabled/report-only) over disabled
    scored.sort((a, b) => {
      if (b.similarity !== a.similarity) return b.similarity - a.similarity;
      const aActive = a.policy.state !== "disabled" ? 1 : 0;
      const bActive = b.policy.state !== "disabled" ? 1 : 0;
      return bActive - aActive;
    });

    const topMatches = scored
      .filter((s) => s.similarity >= 40)
      .slice(0, 5);

    // Separate active vs disabled/report-only best matches
    const bestActiveMatch = scored.find((s) =>
      activePolicies.some((p) => p.id === s.policy.id)
    );
    const bestAnyMatch = scored[0];

    // Determine status — prioritize active matches
    let status: MatchStatus = "missing";
    let confidence = 0;
    const gaps: string[] = [];

    if (bestActiveMatch && bestActiveMatch.similarity >= 70) {
      // Good active match exists
      if (bestActiveMatch.similarity >= 85) {
        status = "present";
      } else {
        status = "partial";
      }
      confidence = bestActiveMatch.similarity;

      // Check if it's report-only
      if (
        bestActiveMatch.policy.state ===
        "enabledForReportingButNotEnforced"
      ) {
        gaps.push(
          `Policy "${bestActiveMatch.policy.displayName}" is in report-only mode — switch to "On" to enforce`
        );
      }
    } else if (bestAnyMatch && bestAnyMatch.similarity >= 70) {
      // Good structural match but only in disabled/report-only policies
      status = "partial";
      confidence = bestAnyMatch.similarity;

      if (bestAnyMatch.policy.state === "disabled") {
        gaps.push(
          `Policy "${bestAnyMatch.policy.displayName}" matches at ${bestAnyMatch.similarity}% but is disabled — enable it to satisfy this template`
        );
      } else if (
        bestAnyMatch.policy.state === "enabledForReportingButNotEnforced"
      ) {
        gaps.push(
          `Policy "${bestAnyMatch.policy.displayName}" matches at ${bestAnyMatch.similarity}% but is report-only — switch to "On" to enforce`
        );
      }
    } else if (bestAnyMatch && bestAnyMatch.similarity >= 40) {
      status = "partial";
      confidence = bestAnyMatch.similarity;
    }

    // Generate actionable gaps from the best match's differences
    const bestDiffs =
      (bestActiveMatch && bestActiveMatch.similarity >= 40
        ? bestActiveMatch
        : bestAnyMatch
      )?.differences ?? [];

    for (const diff of bestDiffs) {
      if (diff.startsWith("Roles: missing")) {
        gaps.push(`Add the missing admin roles to your policy: ${diff.replace("Roles: missing ", "").split(" — ")[1] ?? diff}`);
      } else if (diff.startsWith("Roles: policy only")) {
        gaps.push(`Add the required admin roles: ${diff.split(" — missing ")[1] ?? diff}`);
      } else if (diff.startsWith("Users: template targets All Users")) {
        gaps.push("Change user targeting to 'All Users' instead of specific groups/roles");
      } else if (diff.startsWith("Users: template targets guest")) {
        gaps.push("Add guest/external user targeting to the policy conditions");
      } else if (diff.startsWith("Grant controls:")) {
        const needed = diff.match(/template requires \[(.+?)\]/)?.[1];
        gaps.push(`Set grant controls to require: ${needed ?? "the template controls"}`);
      } else if (diff.startsWith("Apps:")) {
        gaps.push("Update application targeting to match the template scope");
      } else if (diff.startsWith("Sign-in risk:")) {
        const levels = diff.match(/requires \[(.+?)\]/)?.[1];
        gaps.push(`Configure sign-in risk levels: ${levels ?? "as specified"}`);
      } else if (diff.startsWith("User risk:")) {
        const levels = diff.match(/requires \[(.+?)\]/)?.[1];
        gaps.push(`Configure user risk levels: ${levels ?? "as specified"}`);
      } else if (diff.startsWith("Locations:")) {
        gaps.push("Add named location conditions to the policy");
      } else if (diff.startsWith("Platforms:")) {
        gaps.push("Configure platform targeting to match the template");
      } else if (diff.startsWith("Session:")) {
        gaps.push(diff.replace("Session: template requires ", "Enable ").replace(", not configured", ""));
      } else if (diff.startsWith("Auth flows:")) {
        gaps.push("Block authentication transfer flows in the policy conditions");
      } else if (diff.startsWith("Client apps:")) {
        gaps.push("Update client app type targeting to match the template");
      } else if (diff.startsWith("User actions:")) {
        gaps.push("Add the required user actions (e.g., register security info) to the policy");
      }
    }

    return {
      template,
      status,
      confidence,
      matchingPolicies: topMatches.map((m) => ({
        policy: m.policy,
        similarity: m.similarity,
        differences: m.differences,
      })),
      differences: bestDiffs,
      gaps,
    };
  });

  const presentCount = matches.filter((m) => m.status === "present").length;
  const partialCount = matches.filter((m) => m.status === "partial").length;
  const missingCount = matches.filter((m) => m.status === "missing").length;
  const notApplicableCount = matches.filter(
    (m) => m.status === "not-applicable"
  ).length;

  // Weighted coverage score (critical templates count more)
  // Not-applicable templates are excluded from the denominator
  const priorityWeights: Record<TemplatePriority, number> = {
    critical: 3,
    recommended: 2,
    optional: 1,
  };

  let totalWeight = 0;
  let earnedWeight = 0;
  for (const match of matches) {
    if (match.status === "not-applicable") continue; // skip unlicensed
    const w = priorityWeights[match.template.priority];
    totalWeight += w;
    if (match.status === "present") earnedWeight += w;
    else if (match.status === "partial") earnedWeight += w * 0.5;
  }

  const coverageScore =
    totalWeight > 0 ? Math.round((earnedWeight / totalWeight) * 100) : 0;

  // Per-category score
  const categories = [
    ...new Set(templates.map((t) => t.category)),
  ] as TemplateCategory[];

  const byCategoryScore = {} as Record<TemplateCategory, number>;
  for (const cat of categories) {
    const catMatches = matches.filter(
      (m) => m.template.category === cat && m.status !== "not-applicable"
    );
    const catPresent = catMatches.filter((m) => m.status === "present").length;
    const catPartial = catMatches.filter((m) => m.status === "partial").length;
    byCategoryScore[cat] =
      catMatches.length > 0
        ? Math.round(
            ((catPresent + catPartial * 0.5) / catMatches.length) * 100
          )
        : 0;
  }

  return {
    matches,
    presentCount,
    partialCount,
    missingCount,
    notApplicableCount,
    totalTemplates: templates.length,
    coverageScore,
    byCategoryScore,
  };
}
