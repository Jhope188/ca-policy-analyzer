/**
 * Conditional Access Policy Plans (preview) - rule/policy conflict detector.
 *
 * The single biggest migration hurdle teams hit with policy plans: migrating
 * a policy into a plan does **not** touch the original standalone policy.
 * Per Microsoft Learn's migration guide, "Your original policies aren't
 * changed by the migration. They remain in their previous state ... and
 * continue to evaluate independently," and the recommended last step is to
 * "Decommission the original policies" once the plan rule is validated and
 * turned on:
 * https://learn.microsoft.com/entra/identity/conditional-access/how-to-migrate-conditional-access-policy-plan#decommission-the-original-policies
 *
 * Because every applicable policy *and* every applicable plan rule must be
 * satisfied for access to be granted, leaving the original policy on
 * (enabled or report-only) after its rule has been turned on means both are
 * evaluated side by side - at best redundant, at worst a genuine conflict if
 * the two have drifted apart since migration.
 *
 * The Graph API doesn't expose a link from a `conditionalAccessPolicyRule`
 * back to the policy it was migrated from (see the beta resource reference -
 * no `sourcePolicyId` or similar property), so this module matches rules to
 * policies heuristically:
 *   1. Exact (normalized) display name match - the migration experience maps
 *      one selected policy to one rule, and admins overwhelmingly keep the
 *      same name for traceability, so this is treated as strong evidence.
 *   2. Otherwise, a structural similarity score across targeted users/apps,
 *      grant controls, and locations (the plan's shared conditions merged
 *      with the rule's own conditions) - only treated as a match above a
 *      high threshold, since name drift without any other signal is a guess.
 */

import {
  ConditionalAccessConditionSet,
  ConditionalAccessPolicy,
  ConditionalAccessPolicyPlanWithRules,
  ConditionalAccessPolicyRule,
  ConditionalAccessPolicyRuleControls,
} from "./graph-client";
import { PLAN_RULE_STATE_LABEL } from "./policy-plan-visualizer";
import { Severity } from "./analyzer";

export type PlanRulePolicyMatchType = "exact-name" | "structural";

export interface PlanRulePolicyConflict {
  planId: string;
  planDisplayName: string;
  ruleId: string;
  ruleDisplayName: string;
  ruleState: ConditionalAccessPolicyRule["state"];
  matchedPolicyId: string;
  matchedPolicyDisplayName: string;
  matchedPolicyState: ConditionalAccessPolicy["state"];
  matchType: PlanRulePolicyMatchType;
  /** 0-100 confidence that `matchedPolicy` is the policy this rule was migrated from. */
  confidence: number;
  severity: Severity;
  title: string;
  description: string;
  recommendation: string;
}

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const NAME_MATCH_CONFIDENCE = 92;
const STRUCTURAL_MATCH_THRESHOLD = 75;

const DECOMMISSION_DOC_URL =
  "https://learn.microsoft.com/entra/identity/conditional-access/how-to-migrate-conditional-access-policy-plan#decommission-the-original-policies";

function normalizeName(name: string): string {
  return name.trim().toLowerCase().replace(/\s+/g, " ");
}

/**
 * Field-by-field merge of a plan's shared conditions and a rule's own
 * conditions - the rule's value wins when present, otherwise the plan's
 * shared value applies. Mirrors how the UI treats an unset rule field as
 * "inherited from plan" (see policy-plans-view.tsx).
 */
function effectiveRuleConditions(
  shared: ConditionalAccessConditionSet | undefined,
  own: ConditionalAccessConditionSet | undefined
): ConditionalAccessConditionSet {
  return {
    users: own?.users ?? shared?.users,
    applications: own?.applications ?? shared?.applications,
    clientAppTypes: own?.clientAppTypes ?? shared?.clientAppTypes,
    platforms: own?.platforms ?? shared?.platforms,
    locations: own?.locations ?? shared?.locations,
    userRiskLevels: own?.userRiskLevels ?? shared?.userRiskLevels,
    signInRiskLevels: own?.signInRiskLevels ?? shared?.signInRiskLevels,
    servicePrincipalRiskLevels: own?.servicePrincipalRiskLevels ?? shared?.servicePrincipalRiskLevels,
    devices: own?.devices ?? shared?.devices,
    clientApplications: own?.clientApplications ?? shared?.clientApplications,
    agentIdRiskLevels: own?.agentIdRiskLevels ?? shared?.agentIdRiskLevels,
    insiderRiskLevels: own?.insiderRiskLevels ?? shared?.insiderRiskLevels,
    authenticationFlows: own?.authenticationFlows ?? shared?.authenticationFlows,
  };
}

function usersKeySet(users: ConditionalAccessConditionSet["users"]): Set<string> {
  const s = new Set<string>();
  users?.includeUsers?.forEach((u) => s.add(`u:${u.toLowerCase()}`));
  users?.includeGroups?.forEach((g) => s.add(`g:${g.toLowerCase()}`));
  users?.includeRoles?.forEach((r) => s.add(`r:${r.toLowerCase()}`));
  return s;
}

function appsKeySet(apps: ConditionalAccessConditionSet["applications"]): Set<string> {
  const s = new Set<string>();
  apps?.includeApplications?.forEach((a) => s.add(a.toLowerCase()));
  return s;
}

function controlsKeySet(controls: ConditionalAccessPolicy["grantControls"]): Set<string> {
  const s = new Set<string>();
  controls?.builtInControls.forEach((c) => s.add(c.toLowerCase()));
  if (controls?.authenticationStrength?.id) {
    s.add(`authstrength:${controls.authenticationStrength.id.toLowerCase()}`);
  }
  return s;
}

function jaccard(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 && b.size === 0) return 1;
  const intersection = [...a].filter((x) => b.has(x)).length;
  const union = new Set([...a, ...b]).size;
  return union === 0 ? 1 : intersection / union;
}

/** Jaccard similarity, but a lone "all"/"All" on one side is treated as a plausible (not zero) partial match. */
function setSimilarityWithAllHandling(a: Set<string>, b: Set<string>): number {
  const aAll = a.has("all");
  const bAll = b.has("all");
  if (aAll && bAll) return 1;
  if (aAll !== bAll) return 0.6;
  return jaccard(a, b);
}

function scoreStructuralMatch(
  effectiveConditions: ConditionalAccessConditionSet,
  ruleControls: ConditionalAccessPolicyRuleControls | undefined,
  policy: ConditionalAccessPolicy
): number {
  let totalWeight = 0;
  let matchedWeight = 0;

  if (effectiveConditions.users) {
    totalWeight += 30;
    matchedWeight +=
      30 * setSimilarityWithAllHandling(usersKeySet(effectiveConditions.users), usersKeySet(policy.conditions.users));
  }

  if (effectiveConditions.applications) {
    totalWeight += 30;
    matchedWeight +=
      30 *
      setSimilarityWithAllHandling(
        appsKeySet(effectiveConditions.applications),
        appsKeySet(policy.conditions.applications)
      );
  }

  if (ruleControls?.grantControls) {
    totalWeight += 25;
    matchedWeight += 25 * jaccard(controlsKeySet(ruleControls.grantControls), controlsKeySet(policy.grantControls));
  }

  if (effectiveConditions.locations?.includeLocations?.length) {
    totalWeight += 15;
    const ruleLocs = new Set(effectiveConditions.locations.includeLocations.map((l) => l.toLowerCase()));
    const policyLocs = new Set((policy.conditions.locations?.includeLocations ?? []).map((l) => l.toLowerCase()));
    matchedWeight += 15 * jaccard(ruleLocs, policyLocs);
  }

  if (totalWeight === 0) return 0;
  return Math.round((matchedWeight / totalWeight) * 100);
}

/** Whether a policy/rule state actively does something (as opposed to "disabled", which is inert). */
function isActive(state: ConditionalAccessPolicy["state"]): boolean {
  return state !== "disabled";
}

function buildConflict(
  plan: ConditionalAccessPolicyPlanWithRules,
  rule: ConditionalAccessPolicyRule,
  match: { policy: ConditionalAccessPolicy; confidence: number; matchType: PlanRulePolicyMatchType }
): PlanRulePolicyConflict {
  const { policy, confidence, matchType } = match;
  const ruleLabel = PLAN_RULE_STATE_LABEL[rule.state] ?? rule.state;
  const policyLabel = PLAN_RULE_STATE_LABEL[policy.state] ?? policy.state;

  let severity: Severity;
  let title: string;
  if (rule.state === "enabled" && policy.state === "enabled") {
    severity = "high";
    title = "Rule is On and the original policy is still On";
  } else if (rule.state === "enabled" && policy.state === "enabledForReportingButNotEnforced") {
    severity = "medium";
    title = "Rule is On but the original policy is still active (Report-only)";
  } else if (rule.state === "enabledForReportingButNotEnforced" && policy.state === "enabled") {
    severity = "medium";
    title = "Original policy is still enforcing access while the rule is in Report-only";
  } else if (rule.state === "enabledForReportingButNotEnforced") {
    severity = "low";
    title = "Rule and original policy are both active in Report-only mode";
  } else {
    // rule.state === "disabled" - the rule isn't acting yet, so this is informational only.
    severity = "info";
    title = "Original policy for this (currently Off) rule is still active";
  }

  const description =
    `Rule "${rule.displayName}" in plan "${plan.displayName}" (${ruleLabel}) ` +
    `${matchType === "exact-name" ? "matches" : "likely matches"} the standalone policy ` +
    `"${policy.displayName}" (${policyLabel}), ${
      matchType === "exact-name" ? "which has the same name" : "based on overlapping users, apps, and controls"
    }. ` +
    `Because every applicable policy and every applicable plan rule must be satisfied for access to be granted, ` +
    `both are still evaluated independently during sign-in.`;

  const recommendation =
    rule.state === "enabled"
      ? `Turn off (or delete, per your retention policy) the original "${policy.displayName}" policy now that its plan rule is On - see Microsoft Learn's "Decommission the original policies" guidance.`
      : `Before turning this rule On, validate it in Report-only, then turn off the original "${policy.displayName}" policy so the plan rule is the sole source of enforcement.`;

  return {
    planId: plan.id,
    planDisplayName: plan.displayName,
    ruleId: rule.id,
    ruleDisplayName: rule.displayName,
    ruleState: rule.state,
    matchedPolicyId: policy.id,
    matchedPolicyDisplayName: policy.displayName,
    matchedPolicyState: policy.state,
    matchType,
    confidence,
    severity,
    title,
    description,
    recommendation,
  };
}

/**
 * For every rule in every plan, finds the standalone policy it was most
 * likely migrated from (if any) and reports a conflict when that original
 * policy is still active (enabled or report-only) instead of turned off.
 * Policies already disabled are considered decommissioned and are skipped.
 */
export function detectPlanRulePolicyConflicts(
  plans: ConditionalAccessPolicyPlanWithRules[],
  policies: ConditionalAccessPolicy[]
): PlanRulePolicyConflict[] {
  const conflicts: PlanRulePolicyConflict[] = [];

  for (const plan of plans) {
    for (const rule of plan.rules) {
      const effectiveConditions = effectiveRuleConditions(plan.sharedConditions, rule.conditions);
      const normalizedRuleName = normalizeName(rule.displayName);

      let best: { policy: ConditionalAccessPolicy; confidence: number; matchType: PlanRulePolicyMatchType } | null =
        null;

      for (const policy of policies) {
        if (normalizeName(policy.displayName) === normalizedRuleName) {
          // An exact name match is strong evidence of common origin - keep the most "active" one if several match.
          if (!best || best.matchType !== "exact-name" || isActive(policy.state)) {
            best = { policy, confidence: NAME_MATCH_CONFIDENCE, matchType: "exact-name" };
          }
          continue;
        }
        if (best?.matchType === "exact-name") continue; // never downgrade an exact-name match to a structural guess
        const score = scoreStructuralMatch(effectiveConditions, rule.controls, policy);
        if (score >= STRUCTURAL_MATCH_THRESHOLD && (!best || score > best.confidence)) {
          best = { policy, confidence: score, matchType: "structural" };
        }
      }

      if (!best || !isActive(best.policy.state)) continue; // no match, or already decommissioned - nothing to report
      conflicts.push(buildConflict(plan, rule, best));
    }
  }

  return conflicts.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
}

export { DECOMMISSION_DOC_URL };
