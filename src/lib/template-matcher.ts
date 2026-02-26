/**
 * Template Matching Engine
 *
 * Compares a tenant's existing CA policies against the recommended
 * policy templates to determine which are present, missing, or partially matched.
 */

import { ConditionalAccessPolicy, TenantContext } from "@/lib/graph-client";
import {
  PolicyTemplate,
  TemplateFingerprint,
  POLICY_TEMPLATES,
  TemplateCategory,
  TemplatePriority,
} from "@/data/policy-templates";

// ─── Types ───────────────────────────────────────────────────────────────────

export type MatchStatus = "present" | "partial" | "missing";

export interface TemplateMatch {
  template: PolicyTemplate;
  status: MatchStatus;
  /** Confidence 0-100 that the tenant has this policy */
  confidence: number;
  /** The tenant policy(ies) that best match this template */
  matchingPolicies: MatchedPolicy[];
  /** Differences between the template and the best match */
  differences: string[];
}

export interface MatchedPolicy {
  policy: ConditionalAccessPolicy;
  similarity: number; // 0-100
}

export interface TemplateAnalysisResult {
  matches: TemplateMatch[];
  presentCount: number;
  partialCount: number;
  missingCount: number;
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
    const fpActions = new Set(fingerprint.includeUserActions);
    const policyActions = new Set(apps.includeUserActions ?? []);

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
    const policyControls = new Set(grant?.builtInControls ?? []);
    const templateControls = new Set(fingerprint.grantControls);
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
    const ratio = overlap.length / templateRoles.size;

    if (ratio >= 0.5) {
      matchedWeight += Math.round(15 * ratio);
    } else {
      differences.push(
        `Roles: template targets ${templateRoles.size} admin roles, policy includes ${policyRoles.size}`
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
    const policyTypes = new Set(policy.conditions.clientAppTypes);
    const templateTypes = new Set(fingerprint.clientAppTypes);
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
    const policyRisk = new Set(policy.conditions.signInRiskLevels ?? []);
    const templateRisk = new Set(fingerprint.signInRiskLevels);
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
    const policyRisk = new Set(policy.conditions.userRiskLevels ?? []);
    const templateRisk = new Set(fingerprint.userRiskLevels);
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
  context: TenantContext
): TemplateAnalysisResult {
  const activePolicies = context.policies.filter(
    (p) => p.state !== "disabled"
  );
  const allPolicies = context.policies;

  const matches: TemplateMatch[] = POLICY_TEMPLATES.map((template) => {
    // Score every policy against this template
    const scored = allPolicies.map((policy) => {
      const { score, differences } = scorePolicyMatch(
        policy,
        template.fingerprint
      );
      return { policy, similarity: score, differences };
    });

    // Sort by similarity descending
    scored.sort((a, b) => b.similarity - a.similarity);

    const bestMatch = scored[0];
    const topMatches = scored
      .filter((s) => s.similarity >= 40)
      .slice(0, 3);

    // Determine status
    let status: MatchStatus = "missing";
    let confidence = 0;

    if (bestMatch && bestMatch.similarity >= 70) {
      // Check if the matching policy is active
      const isActive = activePolicies.some(
        (p) => p.id === bestMatch.policy.id
      );
      if (isActive) {
        status = bestMatch.similarity >= 85 ? "present" : "partial";
        confidence = bestMatch.similarity;
      } else {
        // Policy exists but disabled
        status = "partial";
        confidence = Math.round(bestMatch.similarity * 0.7);
      }
    } else if (bestMatch && bestMatch.similarity >= 40) {
      status = "partial";
      confidence = bestMatch.similarity;
    }

    return {
      template,
      status,
      confidence,
      matchingPolicies: topMatches.map((m) => ({
        policy: m.policy,
        similarity: m.similarity,
      })),
      differences: bestMatch?.differences ?? [],
    };
  });

  const presentCount = matches.filter((m) => m.status === "present").length;
  const partialCount = matches.filter((m) => m.status === "partial").length;
  const missingCount = matches.filter((m) => m.status === "missing").length;

  // Weighted coverage score (critical templates count more)
  const priorityWeights: Record<TemplatePriority, number> = {
    critical: 3,
    recommended: 2,
    optional: 1,
  };

  let totalWeight = 0;
  let earnedWeight = 0;
  for (const match of matches) {
    const w = priorityWeights[match.template.priority];
    totalWeight += w;
    if (match.status === "present") earnedWeight += w;
    else if (match.status === "partial") earnedWeight += w * 0.5;
  }

  const coverageScore =
    totalWeight > 0 ? Math.round((earnedWeight / totalWeight) * 100) : 0;

  // Per-category score
  const categories = [
    ...new Set(POLICY_TEMPLATES.map((t) => t.category)),
  ] as TemplateCategory[];

  const byCategoryScore = {} as Record<TemplateCategory, number>;
  for (const cat of categories) {
    const catMatches = matches.filter((m) => m.template.category === cat);
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
    totalTemplates: POLICY_TEMPLATES.length,
    coverageScore,
    byCategoryScore,
  };
}
