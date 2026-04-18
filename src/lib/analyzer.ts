/**
 * Conditional Access Policy Analyzer Engine
 *
 * Evaluates CA policies against best practices derived from:
 *   - Fabian Bader's "Conditional Access bypasses" research
 *   - EntraScopes.com FOCI family data
 *   - Microsoft documentation
 *   - Swiss-cheese defense model principles
 */

import {
  ConditionalAccessPolicy,
  NamedLocation,
  ServicePrincipal,
  TenantContext,
} from "./graph-client";
import { CISAlignmentResult } from "@/data/cis-benchmarks";
import { TemplateAnalysisResult } from "./template-matcher";
import { isFociApp, getFociApp, getFociFamily } from "@/data/foci-families";
import {
  CA_IMMUNE_RESOURCE_MAP,
  RESOURCE_EXCLUSION_BYPASSES,
  DEVICE_REGISTRATION_RESOURCE,
  WELL_KNOWN_APP_MAP,
  CA_BYPASS_APPS,
} from "@/data/ca-bypass-database";
import { APP_DESCRIPTION_MAP } from "@/data/app-descriptions";
import {
  checkPolicyExclusions,
  ExclusionFinding,
} from "@/data/known-exclusions";
import { ADMIN_ROLE_IDS } from "@/data/policy-templates";

// ─── Finding Types ───────────────────────────────────────────────────────────

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface ExcludedAppDetail {
  appId: string;
  displayName: string;
  purpose: string;
  exclusionReason: string;
  risk: string;
}

export interface Finding {
  id: string;
  policyId: string;
  policyName: string;
  severity: Severity;
  category: string;
  title: string;
  description: string;
  recommendation: string;
  /** Optional list of related app/resource IDs for cross-referencing */
  relatedIds?: string[];
  /** Detailed per-app info for consolidated exclusion findings */
  excludedApps?: ExcludedAppDetail[];
}

export interface AnalysisResult {
  tenantSummary: TenantSummary;
  policyResults: PolicyResult[];
  findings: Finding[];
  exclusionFindings: ExclusionFinding[];
  overallScore: number; // 0-100
}

export interface TenantSummary {
  totalPolicies: number;
  enabledPolicies: number;
  reportOnlyPolicies: number;
  disabledPolicies: number;
  totalFindings: number;
  criticalFindings: number;
  highFindings: number;
  mediumFindings: number;
  lowFindings: number;
  infoFindings: number;
}

export interface PolicyResult {
  policy: ConditionalAccessPolicy;
  findings: Finding[];
  visualization: PolicyVisualization;
}

// ─── Composite Score ─────────────────────────────────────────────────────────

export interface CompositeScoreResult {
  /** Overall 0-100 score */
  overall: number;
  /** CIS alignment component */
  cisScore: number;
  cisMax: number;
  /** Template coverage component */
  templateScore: number;
  templateMax: number;
  /** Configuration quality component (finding deductions) */
  configScore: number;
  configMax: number;
  /** Human-readable letter grade */
  grade: string;
}

// ─── Visualization Model ─────────────────────────────────────────────────────

export interface PolicyVisualization {
  targetUsers: string;
  targetApps: string;
  conditions: string[];
  grantControls: string[];
  sessionControls: string[];
  state: string;
}

// ─── Main Analyzer ───────────────────────────────────────────────────────────

let findingCounter = 0;
function nextFindingId(): string {
  return `F-${String(++findingCounter).padStart(4, "0")}`;
}

export function analyzeAllPolicies(context: TenantContext): AnalysisResult {
  findingCounter = 0;
  const findings: Finding[] = [];
  const policyResults: PolicyResult[] = [];

  // Identify break-glass candidate once for use in per-policy checks
  const breakGlass = identifyBreakGlass(context);

  for (const policy of context.policies) {
    const policyFindings: Finding[] = [];

    // Run all checks
    policyFindings.push(
      ...checkFociExclusions(policy, context),
      ...checkResourceExclusion(policy, context),
      ...checkCAImmuneResources(policy),
      ...checkGrantControlOperator(policy),
      ...checkDeviceRegistrationBypass(policy),
      ...checkServicePrincipalExclusions(policy, context),
      ...checkMissingMFA(policy),
      ...checkAllUsersAllApps(policy),
      ...checkReportOnlyState(policy),
      ...checkSessionControls(policy),
      ...checkLocationConditions(policy, context),
      ...checkLegacyAuth(policy),
      ...checkCABypassApps(policy, context),
      ...checkUserAgentBypass(policy),
      ...checkMicrosoftManagedPolicy(policy),
      ...checkPrivilegedRoleExclusions(policy, context),
      ...checkGuestExternalUserExclusions(policy, context),
      ...checkCredentialRegistrationConstraints(policy, context),
      ...checkGuestAuthenticationStrength(policy),
      ...checkProtectedActions(policy),
      ...checkBreakGlassPerPolicy(policy, breakGlass, context)
    );

    findings.push(...policyFindings);

    policyResults.push({
      policy,
      findings: policyFindings,
      visualization: buildVisualization(policy, context),
    });
  }

  // Tenant-wide checks
  findings.push(...checkTenantWideGaps(context));

  // MS Learn documented exclusion checks
  const exclusionFindings: ExclusionFinding[] = context.policies.flatMap((p) =>
    checkPolicyExclusions(p, context.authStrengthPolicies)
  );

  // Convert critical/high exclusion findings into the main findings list too
  for (const ef of exclusionFindings) {
    if (ef.exclusion.severity === "critical" || ef.exclusion.severity === "high") {
      findings.push({
        id: nextFindingId(),
        policyId: ef.policyId,
        policyName: ef.policyName,
        severity: ef.exclusion.severity,
        category: "MS Learn: Documented Exclusion",
        title: ef.exclusion.title,
        description: ef.result.detail,
        recommendation: ef.exclusion.remediation,
        relatedIds: ef.result.impactedResources,
      });
    }
  }

  const summary = buildSummary(context, findings);
  const overallScore = calculateScore(summary);

  return { tenantSummary: summary, policyResults, findings, exclusionFindings, overallScore };
}

// ─── Check: FOCI Family Exclusions ───────────────────────────────────────────

function checkFociExclusions(
  policy: ConditionalAccessPolicy,
  context: TenantContext
): Finding[] {
  const findings: Finding[] = [];
  const excluded = policy.conditions.applications.excludeApplications;

  for (const appId of excluded) {
    if (isFociApp(appId)) {
      const app = getFociApp(appId)!;
      const family = getFociFamily(appId);
      const familyNames = family.map((f) => f.displayName).slice(0, 8);

      findings.push({
        id: nextFindingId(),
        policyId: policy.id,
        policyName: policy.displayName,
        severity: "critical",
        category: "FOCI Token Sharing",
        title: `Excluded FOCI app "${app.displayName}" shares tokens with ${family.length} other apps`,
        description:
          `"${app.displayName}" (${appId}) is excluded from this policy and belongs to the FOCI (Family of Client IDs) family. ` +
          `FOCI apps share refresh tokens, meaning any FOCI app can obtain an access token for any other FOCI family member. ` +
          `Excluding one effectively excludes ALL: ${familyNames.join(", ")}${family.length > 8 ? "…" : ""}.`,
        recommendation:
          "Remove the exclusion or accept that ALL 45+ FOCI family apps are effectively excluded. " +
          "Consider targeting specific apps in a separate policy instead of excluding from a broad policy.",
        relatedIds: family.map((f) => f.appId),
      });
    }
  }

  return findings;
}

// ─── Check: Resource Exclusion — Low-Privilege Scope Enforcement (March 2026) ─

function checkResourceExclusion(
  policy: ConditionalAccessPolicy,
  _context: TenantContext
): Finding[] {
  const findings: Finding[] = [];
  const apps = policy.conditions.applications;
  const includesAll = apps.includeApplications.includes("All");
  const hasExclusions = apps.excludeApplications.length > 0;

  if (!includesAll || !hasExclusions) return findings;

  // ── Finding 1: Enforcement change awareness ──
  // Microsoft is rolling out CA enforcement for low-privilege scopes (March-June 2026).
  // Previously excluded scopes are now mapped to Azure AD Graph for enforcement.
  // This may cause apps that ONLY request these scopes to receive CA challenges.
  
  const nativeClientScopes = RESOURCE_EXCLUSION_BYPASSES.map(b =>
    `**${b.resourceName}**: ${b.bypassedScopes.join(", ")}`
  ).join("\n");
  
  const confidentialClientScopes = RESOURCE_EXCLUSION_BYPASSES
    .filter(b => b.confidentialClientScopes && b.confidentialClientScopes.length > b.bypassedScopes.length)
    .map(b => {
      const extraScopes = b.confidentialClientScopes!.filter(s => !b.bypassedScopes.includes(s));
      return `**${b.resourceName}** (additional): ${extraScopes.join(", ")}`;
    }).join("\n");

  findings.push({
    id: nextFindingId(),
    policyId: policy.id,
    policyName: policy.displayName,
    severity: "medium",
    category: "Resource Exclusion Bypass",
    title: `${apps.excludeApplications.length} app(s) excluded from "All resources" — verify low-privilege scope enforcement rollout`,
    description:
      `This policy targets "All resources" but excludes ${apps.excludeApplications.length} app(s). ` +
      `**Microsoft is actively changing how this works (March-June 2026 rollout).**\n\n` +
      `**Legacy behavior (before March 2026):**\n` +
      `When ANY resource was excluded, these low-privilege scopes were automatically exempt from CA enforcement, ` +
      `allowing users to access basic directory data without meeting the policy's controls:\n\n` +
      `*Native clients & SPAs:*\n${nativeClientScopes}\n\n` +
      `*Confidential clients had a BROADER leak:*\n${confidentialClientScopes}\n\n` +
      `**New behavior (rolling out March-June 2026):**\n` +
      `These scopes are now evaluated as directory access and mapped to **Azure AD Graph** ` +
      `(Windows Azure Active Directory, ID: 00000002-0000-0000-c000-000000000000) as the enforcement audience. ` +
      `CA policies targeting "All resources" — even with exclusions — will now enforce on these scopes.\n\n` +
      `**⚠️ Impact of this change:**\n` +
      `- Apps that only request \`User.Read\`, \`openid\`, or \`profile\` may now prompt users for MFA or device compliance\n` +
      `- Confidential client apps that were excluded and relied on \`User.Read.All\`, \`GroupMember.Read.All\`, ` +
      `or \`Member.Read.Hidden\` will now face CA enforcement\n` +
      `- Directory enumeration that previously bypassed CA (even for excluded apps) is now blocked\n` +
      `- Custom apps not designed to handle CA challenges may break`,
    recommendation:
      `**Action Required:**\n\n` +
      `1. **Check your tenant's rollout status**: The change is rolling out in phases. Sign in with a test account ` +
      `and check if low-privilege scope requests now trigger CA challenges.\n\n` +
      `2. **Review impacted apps**: Use the Usage & Insights report in Microsoft Entra Admin Center ` +
      `(Entra ID → Monitoring & health → Usage & insights) to identify apps requesting only low-privilege scopes.\n\n` +
      `3. **Review sign-in logs**: Filter by resource "Windows Azure Active Directory" ` +
      `(00000002-0000-0000-c000-000000000000) to see which apps are now being evaluated.\n\n` +
      `4. **Update custom apps**: Applications that only request scopes like \`openid\`, \`profile\`, \`User.Read\` ` +
      `and are not designed to handle CA claims challenges must be updated per the ` +
      `[Conditional Access developer guidance](https://learn.microsoft.com/entra/identity-platform/v2-conditional-access-dev-guide).\n\n` +
      `5. **Best practice**: Remove resource exclusions entirely and use Microsoft's recommended baseline: ` +
      `"All resources" with no exclusions. Create separate less-restrictive policies for apps that need exemptions.\n\n` +
      `**Previously leaked confidential client scopes (now being enforced):**\n` +
      `These scopes were especially dangerous because they allowed directory enumeration ` +
      `without CA enforcement for excluded confidential client apps:\n` +
      `- \`User.Read.All\` / \`User.ReadBasic.All\` — enumerate all users in the directory\n` +
      `- \`People.Read.All\` — read organizational relationships\n` +
      `- \`GroupMember.Read.All\` — enumerate group memberships including security groups\n` +
      `- \`Member.Read.Hidden\` — read hidden group memberships\n\n` +
      `**Learn More:**\n` +
      `- [CA behavior change for All resources policies](https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-cloud-apps#new-conditional-access-behavior-when-an-all-resources-policy-has-a-resource-exclusion)\n` +
      `- [Legacy CA behavior with exclusions](https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-cloud-apps#legacy-conditional-access-behavior-when-an-all-resources-policy-has-a-resource-exclusion)\n` +
      `- [Recommended baseline MFA policy](https://learn.microsoft.com/entra/identity/conditional-access/policy-all-users-mfa-strength)`,
    relatedIds: RESOURCE_EXCLUSION_BYPASSES.map((b) => b.resourceId),
  });

  return findings;
}

// ─── Check: CA-Immune Resources ──────────────────────────────────────────────
// Moved to tenant-wide check — no longer fires per-policy

function checkCAImmuneResources(
  _policy: ConditionalAccessPolicy
): Finding[] {
  return [];
}

// ─── Check: Grant Control Operator (AND vs OR) ──────────────────────────────

function checkGrantControlOperator(
  policy: ConditionalAccessPolicy
): Finding[] {
  const findings: Finding[] = [];
  const grant = policy.grantControls;

  if (!grant || grant.builtInControls.length <= 1) return findings;

  if (grant.operator === "OR") {
    findings.push({
      id: nextFindingId(),
      policyId: policy.id,
      policyName: policy.displayName,
      severity: "high",
      category: "Swiss Cheese Model",
      title: 'Grant controls use "OR" — weakest control is effective',
      description:
        `This policy requires ${grant.builtInControls.join(" OR ")}. ` +
        `With the OR operator, only the WEAKEST control needs to be satisfied. ` +
        `This contradicts the Swiss cheese model of layered security.`,
      recommendation:
        'Change the operator to "AND" so ALL controls must be satisfied, or ' +
        "split into separate policies each requiring a single control. " +
        "Per Fabian Bader: use AND, not OR, for grant controls.",
    });
  }

  return findings;
}

// ─── Check: Device Registration Bypass ───────────────────────────────────────

function checkDeviceRegistrationBypass(
  policy: ConditionalAccessPolicy
): Finding[] {
  const findings: Finding[] = [];
  const apps = policy.conditions.applications;
  const grant = policy.grantControls;
  const locations = policy.conditions.locations;

  const targetsDRS =
    apps.includeApplications.includes(DEVICE_REGISTRATION_RESOURCE.resourceId) ||
    apps.includeApplications.includes("All");

  const usesLocationCondition = locations &&
    (locations.includeLocations.length > 0 || locations.excludeLocations.length > 0);

  const requiresCompliantDevice =
    grant?.builtInControls.includes("compliantDevice") ||
    grant?.builtInControls.includes("domainJoinedDevice");

  if (targetsDRS && (usesLocationCondition || requiresCompliantDevice)) {
    const issues: string[] = [];
    if (usesLocationCondition) issues.push("location-based conditions");
    if (requiresCompliantDevice) issues.push("compliant/hybrid-joined device requirement");

    findings.push({
      id: nextFindingId(),
      policyId: policy.id,
      policyName: policy.displayName,
      severity: "high",
      category: "Device Registration Bypass",
      title: `Device Registration Service bypasses ${issues.join(" and ")}`,
      description:
        `This policy uses ${issues.join(" and ")}, but the Device Registration Service ` +
        `(${DEVICE_REGISTRATION_RESOURCE.resourceId}) can ONLY be protected by MFA grant controls. ` +
        `Location conditions and device compliance requirements are ignored for device registration. ` +
        `(MSRC VULN-153600 — confirmed by-design by Microsoft)`,
      recommendation:
        "Ensure you have a separate policy requiring MFA for the Device Registration Service. " +
        "Do not rely solely on location or device compliance to protect device enrollment.",
      relatedIds: [DEVICE_REGISTRATION_RESOURCE.resourceId],
    });
  }

  return findings;
}

// ─── Check: Service Principal Exclusions ─────────────────────────────────────

function checkServicePrincipalExclusions(
  policy: ConditionalAccessPolicy,
  context: TenantContext
): Finding[] {
  const excluded = policy.conditions.applications.excludeApplications;
  const appDetails: ExcludedAppDetail[] = [];
  let hasHighRisk = false;

  for (const appId of excluded) {
    if (isFociApp(appId)) continue; // Already handled in FOCI check

    const sp = context.servicePrincipals.get(appId.toLowerCase());
    const bypassApp = CA_BYPASS_APPS.find(
      (a) => a.appId.toLowerCase() === appId.toLowerCase()
    );
    const appDesc = APP_DESCRIPTION_MAP.get(appId.toLowerCase());

    if (sp || bypassApp || appDesc) {
      const name = appDesc?.displayName ?? sp?.displayName ?? bypassApp?.displayName ?? appId;
      const purpose = appDesc?.purpose ?? bypassApp?.description ?? `Service principal: ${sp?.servicePrincipalType ?? "Application"}`;
      const reason = appDesc?.commonExclusionReason ?? "No documented exclusion reason. Review whether this exclusion is necessary.";
      const risk = appDesc?.exclusionRisk ?? (bypassApp ? "high" : "medium");

      if (risk === "critical" || risk === "high" || bypassApp) hasHighRisk = true;

      appDetails.push({
        appId,
        displayName: name,
        purpose,
        exclusionReason: reason,
        risk,
      });
    }
  }

  if (appDetails.length === 0) return [];

  const highRiskApps = appDetails.filter((a) => a.risk === "critical" || a.risk === "high");
  const appNames = appDetails.map((a) => a.displayName).join(", ");

  return [{
    id: nextFindingId(),
    policyId: policy.id,
    policyName: policy.displayName,
    severity: hasHighRisk ? "high" : "medium",
    category: "App Exclusion",
    title: `${appDetails.length} app(s) excluded from this policy${highRiskApps.length > 0 ? ` (${highRiskApps.length} high-risk)` : ""}`,
    description:
      `This policy excludes: ${appNames}. ` +
      `Each excluded app bypasses the policy's controls. ` +
      (highRiskApps.length > 0
        ? `High-risk exclusions: ${highRiskApps.map((a) => a.displayName).join(", ")}.`
        : "All exclusions are low/medium risk — expand for details on each app."),
    recommendation:
      "Review each exclusion and ensure it has a documented business justification. " +
      "Consider using separate targeted policies with reduced controls instead of excluding apps.",
    relatedIds: appDetails.map((a) => a.appId),
    excludedApps: appDetails,
  }];
}

// ─── Check: Missing MFA ─────────────────────────────────────────────────────

function checkMissingMFA(policy: ConditionalAccessPolicy): Finding[] {
  const findings: Finding[] = [];
  const grant = policy.grantControls;
  if (policy.state === "disabled") return findings;

  const requiresMfa =
    grant?.builtInControls.includes("mfa") ||
    grant?.authenticationStrength != null;

  if (!requiresMfa && grant && grant.builtInControls.length > 0 && !grant.builtInControls.includes("block")) {
    findings.push({
      id: nextFindingId(),
      policyId: policy.id,
      policyName: policy.displayName,
      severity: "medium",
      category: "Swiss Cheese Model",
      title: "Policy does not require MFA",
      description:
        `This policy grants access with: ${grant.builtInControls.join(", ")} but does not require MFA. ` +
        `Per the Swiss cheese model, MFA should be the bare minimum requirement layered under everything else.`,
      recommendation:
        "Add MFA as a grant control requirement. MFA should be the baseline layer of defense. " +
        "Consider using Authentication Strengths for phishing-resistant MFA.",
    });
  }

  return findings;
}

// ─── Check: All Users + All Apps Coverage ────────────────────────────────────

function checkAllUsersAllApps(
  policy: ConditionalAccessPolicy
): Finding[] {
  const findings: Finding[] = [];
  const { users, applications } = policy.conditions;

  const targetsAllUsers = users.includeUsers.includes("All");
  const targetsAllApps = applications.includeApplications.includes("All");

  if (targetsAllUsers && targetsAllApps && policy.state === "enabled") {
    const hasUserExclusions =
      users.excludeUsers.length > 0 ||
      users.excludeGroups.length > 0 ||
      users.excludeRoles.length > 0;
    const hasAppExclusions = applications.excludeApplications.length > 0;

    if (hasUserExclusions || hasAppExclusions) {
      findings.push({
        id: nextFindingId(),
        policyId: policy.id,
        policyName: policy.displayName,
        severity: "medium",
        category: "Policy Scope",
        title: "Broad policy with exclusions — review for gaps",
        description:
          `This policy targets All Users and All Cloud Apps but has exclusions. ` +
          `User exclusions: ${users.excludeUsers.length + users.excludeGroups.length + users.excludeRoles.length}, ` +
          `App exclusions: ${applications.excludeApplications.length}. ` +
          `Exclusions create potential bypass paths.`,
        recommendation:
          "Regularly audit exclusions. Use break-glass accounts sparingly. " +
          "Ensure every excluded entity is documented with a business justification.",
      });
    }
  }

  return findings;
}

// ─── Check: Report-Only Policies ─────────────────────────────────────────────

function checkReportOnlyState(
  policy: ConditionalAccessPolicy
): Finding[] {
  if (policy.state !== "enabledForReportingButNotEnforced") return [];

  return [
    {
      id: nextFindingId(),
      policyId: policy.id,
      policyName: policy.displayName,
      severity: "info",
      category: "Policy State",
      title: "Policy is in report-only mode",
      description:
        "This policy is enabled for reporting but NOT enforced. " +
        "It will log what WOULD happen but takes no action.",
      recommendation:
        "Review sign-in logs to validate the policy's impact, then enable enforcement when ready.",
    },
  ];
}

// ─── Check: Session Controls ─────────────────────────────────────────────────

function checkSessionControls(
  policy: ConditionalAccessPolicy
): Finding[] {
  const findings: Finding[] = [];
  const session = policy.sessionControls;
  if (!session || policy.state === "disabled") return findings;

  if (session.disableResilienceDefaults) {
    findings.push({
      id: nextFindingId(),
      policyId: policy.id,
      policyName: policy.displayName,
      severity: "medium",
      category: "Resilience",
      title: "Resilience defaults are disabled",
      description:
        "This policy disables resilience defaults, which means users may be blocked during an Entra ID outage.",
      recommendation:
        "Only disable resilience defaults if strict real-time policy evaluation is required. " +
        "For most organizations, keeping resilience defaults improves availability.",
    });
  }

  return findings;
}

// ─── Check: Location Conditions ──────────────────────────────────────────────

function checkLocationConditions(
  policy: ConditionalAccessPolicy,
  context: TenantContext
): Finding[] {
  const findings: Finding[] = [];
  const locations = policy.conditions.locations;
  if (!locations || policy.state === "disabled") return findings;

  const allInclude = locations.includeLocations;
  const allExclude = locations.excludeLocations;
  const usesAllTrusted = allInclude.includes("AllTrusted") || allExclude.includes("AllTrusted");

  // 1) Check for untrusted named locations directly referenced
  for (const locId of [...allInclude, ...allExclude]) {
    if (locId === "AllTrusted" || locId === "All") continue;
    const loc = context.namedLocations.find((l) => l.id === locId);
    if (loc && loc.isTrusted === false) {
      findings.push({
        id: nextFindingId(),
        policyId: policy.id,
        policyName: policy.displayName,
        severity: "medium",
        category: "Location Configuration",
        title: `Named location "${loc.displayName}" is not marked as trusted`,
        description:
          `The named location "${loc.displayName}" used in this policy is not marked as trusted. ` +
          `If this policy also references "All trusted locations", this location will NOT be included ` +
          `in the trusted set and users from this location may be unexpectedly blocked or challenged.`,
        recommendation:
          `Mark "${loc.displayName}" as trusted in Entra ID if it represents a known-good network, ` +
          `or ensure the policy logic handles untrusted locations as intended.`,
      });
    }
  }

  // 2) Policy uses "AllTrustedLocations" but some named locations are not trusted
  if (usesAllTrusted) {
    const untrusted = context.namedLocations.filter((l) => !l.isTrusted);
    if (untrusted.length > 0) {
      const names = untrusted.map((l) => l.displayName).join(", ");
      findings.push({
        id: nextFindingId(),
        policyId: policy.id,
        policyName: policy.displayName,
        severity: "high",
        category: "Location Configuration",
        title: `Policy uses "All trusted locations" but ${untrusted.length} location(s) are NOT trusted`,
        description:
          `This policy conditions on "All trusted locations" but the following named location(s) ` +
          `are not marked as trusted and will be EXCLUDED from the trusted set: ${names}. ` +
          `Users signing in from these locations will not be recognized as coming from a trusted ` +
          `location, which may cause accidental lockouts or unexpected MFA prompts.`,
        recommendation:
          "Review each untrusted named location in Entra ID → Protection → Conditional Access → Named locations. " +
          "Mark locations as trusted if they represent corporate offices, VPNs, or other known-good networks. " +
          "If a location should not be trusted, ensure this policy's behavior is correct for non-trusted traffic.",
      });
    }
  }

  // 3) Orphaned location reference — policy references a location ID that doesn't exist
  for (const locId of [...allInclude, ...allExclude]) {
    if (locId === "AllTrusted" || locId === "All") continue;
    const exists = context.namedLocations.some((l) => l.id === locId);
    if (!exists) {
      findings.push({
        id: nextFindingId(),
        policyId: policy.id,
        policyName: policy.displayName,
        severity: "medium",
        category: "Location Configuration",
        title: `Policy references a deleted or missing named location`,
        description:
          `This policy references named location ID "${locId}" which does not exist. ` +
          `The location may have been deleted. This stale reference will never match any traffic, ` +
          `which could silently change the policy's effective behavior — potentially blocking or ` +
          `allowing access unintentionally.`,
        recommendation:
          "Remove the stale location reference from this policy and replace it with a valid named location if needed.",
      });
    }
  }

  // 4) Country-based location with no countries — will never match
  for (const locId of [...allInclude, ...allExclude]) {
    if (locId === "AllTrusted" || locId === "All") continue;
    const loc = context.namedLocations.find((l) => l.id === locId);
    if (
      loc &&
      loc["@odata.type"] === "#microsoft.graph.countryNamedLocation" &&
      (!loc.countriesAndRegions || loc.countriesAndRegions.length === 0)
    ) {
      findings.push({
        id: nextFindingId(),
        policyId: policy.id,
        policyName: policy.displayName,
        severity: "high",
        category: "Location Configuration",
        title: `Country location "${loc.displayName}" has no countries defined`,
        description:
          `This policy references the country-based named location "${loc.displayName}" which has ` +
          `zero countries configured. The location condition will never match any traffic, which ` +
          `could create a security gap (if used as an include condition) or make the exclude ` +
          `condition meaningless.`,
        recommendation:
          "Add the intended countries to this named location, or remove it from this policy.",
      });
    }
  }

  return findings;
}

// ─── Check: Legacy Authentication ────────────────────────────────────────────

function checkLegacyAuth(policy: ConditionalAccessPolicy): Finding[] {
  const findings: Finding[] = [];
  const clientAppTypes = policy.conditions.clientAppTypes;

  if (
    clientAppTypes.includes("exchangeActiveSync") ||
    clientAppTypes.includes("other")
  ) {
    const grant = policy.grantControls;
    const blocks = grant?.builtInControls.includes("block");

    if (!blocks) {
      findings.push({
        id: nextFindingId(),
        policyId: policy.id,
        policyName: policy.displayName,
        severity: "high",
        category: "Legacy Authentication",
        title: "Legacy auth clients targeted but NOT blocked",
        description:
          "This policy targets legacy authentication clients (Exchange ActiveSync / Other) " +
          "but does not block them. Legacy auth cannot support MFA.",
        recommendation:
          "Block legacy authentication. Legacy auth protocols cannot perform MFA and are a " +
          "common attack vector for password spray and credential stuffing attacks.",
      });
    }
  }

  return findings;
}

// ─── Check: Known CA Bypass Apps ─────────────────────────────────────────────

// checkCABypassApps is now consolidated into checkServicePrincipalExclusions
function checkCABypassApps(
  _policy: ConditionalAccessPolicy,
  _context: TenantContext
): Finding[] {
  return []; // Bypass app info is now included in the consolidated App Exclusion finding
}

// ─── Check: User-Agent / Platform Bypass (MFASweep-style) ────────────────────
// Tools like MFASweep enumerate user-agent strings to find gaps where
// platform-specific CA policies can be bypassed by spoofing the UA.

function checkUserAgentBypass(
  policy: ConditionalAccessPolicy
): Finding[] {
  const findings: Finding[] = [];
  if (policy.state === "disabled") return findings;

  const platforms = policy.conditions.platforms;
  const grant = policy.grantControls;
  const clientAppTypes = policy.conditions.clientAppTypes;

  // 1) Platform-specific policies that don't cover all platforms
  if (platforms && platforms.includePlatforms.length > 0) {
    const includesAll = platforms.includePlatforms.includes("all");

    if (!includesAll) {
      const targeted = platforms.includePlatforms;
      const requiresMfa =
        grant?.builtInControls.includes("mfa") ||
        grant?.authenticationStrength != null;
      const requiresCompliance =
        grant?.builtInControls.includes("compliantDevice") ||
        grant?.builtInControls.includes("domainJoinedDevice");

      if (requiresMfa || requiresCompliance) {
        findings.push({
          id: nextFindingId(),
          policyId: policy.id,
          policyName: policy.displayName,
          severity: "high",
          category: "User-Agent Bypass",
          title: `Platform condition only targets ${targeted.join(", ")} — user-agent spoofing risk`,
          description:
            `This policy enforces controls only for platforms: ${targeted.join(", ")}. ` +
            `An attacker can spoof their user-agent string to appear as an unrecognized platform ` +
            `(e.g. Linux, ChromeOS, or a custom UA) to bypass this policy entirely. ` +
            `Tools like MFASweep actively exploit this gap by enumerating user-agent strings.`,
          recommendation:
            "Change the platform condition to target \"All platforms\" instead of specific platforms, or " +
            "create a companion policy that blocks access from unknown/unsupported device platforms " +
            "(CIS 5.3.11). This eliminates the user-agent spoofing bypass path.",
        });
      }
    }
  }

  // 2) Client app type coverage gaps
  const hasClientFilter = clientAppTypes.length > 0 && !clientAppTypes.includes("all");
  if (hasClientFilter) {
    const hasBrowser = clientAppTypes.includes("browser");
    const hasMobile = clientAppTypes.includes("mobileAppsAndDesktopClients");
    const requiresMfa =
      grant?.builtInControls.includes("mfa") ||
      grant?.authenticationStrength != null;

    if (requiresMfa && (!hasBrowser || !hasMobile)) {
      const missing: string[] = [];
      if (!hasBrowser) missing.push("browser");
      if (!hasMobile) missing.push("mobileAppsAndDesktopClients");

      findings.push({
        id: nextFindingId(),
        policyId: policy.id,
        policyName: policy.displayName,
        severity: "medium",
        category: "User-Agent Bypass",
        title: `MFA policy does not cover client app type(s): ${missing.join(", ")}`,
        description:
          `This policy requires MFA but only targets client app types: ${clientAppTypes.join(", ")}. ` +
          `Missing coverage for: ${missing.join(", ")}. An attacker can use a client matching ` +
          `the uncovered app type to bypass MFA. MFASweep tests both browser and desktop/mobile ` +
          `client types to find these gaps.`,
        recommendation:
          "Ensure MFA policies cover all modern client app types: both \"browser\" and " +
          "\"mobileAppsAndDesktopClients\". Use a separate policy to block legacy auth " +
          "(exchangeActiveSync + other).",
      });
    }
  }

  return findings;
}

// ─── Check: Privileged Role Exclusions ────────────────────────────────────────
// Flags when highly privileged Entra ID roles (Global Admin, Privileged Role
// Admin, etc.) are excluded from CA policies, creating a gap that attackers
// can exploit after compromising a privileged account.

/** Roles considered high-privilege — excluding these from CA is a critical gap */
const HIGH_PRIVILEGE_ROLE_IDS: Record<string, string> = {
  [ADMIN_ROLE_IDS.globalAdmin]: "Global Administrator",
  [ADMIN_ROLE_IDS.privilegedRoleAdmin]: "Privileged Role Administrator",
  [ADMIN_ROLE_IDS.privilegedAuthAdmin]: "Privileged Authentication Administrator",
  [ADMIN_ROLE_IDS.securityAdmin]: "Security Administrator",
  [ADMIN_ROLE_IDS.conditionalAccessAdmin]: "Conditional Access Administrator",
  [ADMIN_ROLE_IDS.applicationAdmin]: "Application Administrator",
  [ADMIN_ROLE_IDS.cloudAppAdmin]: "Cloud Application Administrator",
  [ADMIN_ROLE_IDS.exchangeAdmin]: "Exchange Administrator",
  [ADMIN_ROLE_IDS.sharePointAdmin]: "SharePoint Administrator",
  [ADMIN_ROLE_IDS.userAdmin]: "User Administrator",
  [ADMIN_ROLE_IDS.authenticationAdmin]: "Authentication Administrator",
  [ADMIN_ROLE_IDS.authenticationPolicyAdmin]: "Authentication Policy Administrator",
  [ADMIN_ROLE_IDS.hybridIdentityAdmin]: "Hybrid Identity Administrator",
  [ADMIN_ROLE_IDS.intunAdmin]: "Intune Administrator",
};

/** Subset that is ultra-critical — Global Admin + Privileged Role Admin */
const CRITICAL_ROLE_IDS = new Set([
  ADMIN_ROLE_IDS.globalAdmin.toLowerCase(),
  ADMIN_ROLE_IDS.privilegedRoleAdmin.toLowerCase(),
  ADMIN_ROLE_IDS.privilegedAuthAdmin.toLowerCase(),
  ADMIN_ROLE_IDS.conditionalAccessAdmin.toLowerCase(),
]);

function checkPrivilegedRoleExclusions(
  policy: ConditionalAccessPolicy,
  context: TenantContext
): Finding[] {
  const findings: Finding[] = [];

  const excludedRoles = policy.conditions.users.excludeRoles;
  if (excludedRoles.length === 0) return findings;

  const excludedHighPriv: { id: string; name: string; critical: boolean }[] = [];

  for (const roleId of excludedRoles) {
    const lower = roleId.toLowerCase();
    const name = HIGH_PRIVILEGE_ROLE_IDS[roleId] ?? HIGH_PRIVILEGE_ROLE_IDS[lower];
    if (name) {
      excludedHighPriv.push({
        id: roleId,
        name,
        critical: CRITICAL_ROLE_IDS.has(lower),
      });
    }
  }

  if (excludedHighPriv.length === 0) return findings;

  const hasCritical = excludedHighPriv.some((r) => r.critical);
  const criticalNames = excludedHighPriv.filter((r) => r.critical).map((r) => r.name);
  const allNames = excludedHighPriv.map((r) => r.name);

  // Check if excluded admin roles are covered by a separate dedicated policy
  const excludedRoleIdsLower = new Set(excludedHighPriv.map((r) => r.id.toLowerCase()));
  const coveringPolicy = context.policies.find((p) => {
    if (p.id === policy.id || p.state === "disabled") return false;
    const pu = p.conditions.users;
    const pg = p.grantControls;
    // Policy must enforce MFA or auth strength
    const enforcesMfa =
      pg?.builtInControls.includes("mfa") ||
      pg?.authenticationStrength != null;
    if (!enforcesMfa) return false;
    // Policy must include the excluded roles (via includeRoles or All Users without re-excluding them)
    const includesViaRoles = [...excludedRoleIdsLower].every((rid) =>
      pu.includeRoles.some((ir) => ir.toLowerCase() === rid)
    );
    const includesViaAllUsers =
      pu.includeUsers.includes("All") &&
      ![...excludedRoleIdsLower].some((rid) =>
        pu.excludeRoles.some((er) => er.toLowerCase() === rid)
      );
    return includesViaRoles || includesViaAllUsers;
  });

  // Determine what grant controls the policy enforces
  const grant = policy.grantControls;
  const requiresMfa =
    grant?.builtInControls.includes("mfa") ||
    grant?.authenticationStrength != null;
  const requiresCompliance =
    grant?.builtInControls.includes("compliantDevice") ||
    grant?.builtInControls.includes("domainJoinedDevice");
  const blocks = grant?.builtInControls.includes("block");

  // Targeting security info registration is especially dangerous
  const targetsSecurityRegistration = policy.conditions.applications
    .includeUserActions?.includes("urn:user:registersecurityinfo");
  const targetsAllApps = policy.conditions.applications.includeApplications.includes("All");

  let severity: Severity = hasCritical ? "critical" : "high";
  let attackScenario = "";

  if (targetsSecurityRegistration) {
    attackScenario =
      `This policy protects security info registration but excludes ${criticalNames.length > 0 ? criticalNames.join(", ") : allNames.join(", ")}. ` +
      `An attacker who compromises one of these admin accounts can register their own MFA methods ` +
      `(phone, authenticator app) from ANY location or device with NO controls. This gives them ` +
      `persistent access that survives a password reset.`;
    severity = "critical";
  } else if (blocks) {
    attackScenario =
      `This policy blocks access but excludes privileged role(s): ${allNames.join(", ")}. ` +
      `These admin accounts bypass the block entirely, creating a privileged access path.`;
  } else if (requiresMfa && targetsAllApps) {
    attackScenario =
      `This policy requires MFA for all apps but excludes: ${allNames.join(", ")}. ` +
      `These admins can access all cloud apps without MFA — the highest-value accounts ` +
      `have the weakest protection.`;
  } else {
    attackScenario =
      `This policy excludes ${excludedHighPriv.length} privileged role(s): ${allNames.join(", ")}. ` +
      `Privileged accounts should have EQUAL or STRICTER controls, not exemptions.`;
  }

  // Downgrade severity if a compensating policy covers the excluded roles
  if (coveringPolicy) {
    severity = "info";
  }

  const coveredNote = coveringPolicy
    ? ` However, these roles appear to be covered by a separate policy: **${coveringPolicy.displayName}**` +
      ` (${coveringPolicy.state === "enabledForReportingButNotEnforced" ? "report-only" : "enabled"}).` +
      ` Verify that policy enforces equivalent or stricter controls for these admin roles.`
    : ` No separate policy was found that covers these excluded admin roles with MFA or authentication strength.` +
      ` Per Microsoft Zero Trust and CIS benchmarks, privileged roles should be the FIRST` +
      ` users subject to strong controls, not excluded from them.`;

  findings.push({
    id: nextFindingId(),
    policyId: policy.id,
    policyName: policy.displayName,
    severity,
    category: "Privileged Role Exclusion",
    title: `${excludedHighPriv.length} privileged role(s) excluded${hasCritical ? " — includes critical admin roles" : ""}${coveringPolicy ? " (covered by separate policy)" : ""}`,
    description: attackScenario + coveredNote,
    recommendation: coveringPolicy
      ? `The excluded admin roles appear covered by **${coveringPolicy.displayName}**. ` +
        `Confirm that policy enforces equivalent controls (MFA, authentication strength, device compliance). ` +
        `Break-glass accounts should still be excluded by specific user ID, never by role.`
      : `Remove ${allNames.join(", ")} from the excluded roles. ` +
        `If you need emergency access, exclude 1-2 dedicated break-glass accounts by user ID ` +
        `(in excludeUsers) instead of excluding an entire admin role. ` +
        `Break-glass accounts should have complex passwords, be cloud-only, and be monitored with alerts.`,
    relatedIds: excludedHighPriv.map((r) => r.id),
  });

  return findings;
}

// ─── Check: Guest / External User Exclusions ─────────────────────────────────
// Flags when policies broadly exclude guests or external users, creating a
// gap unless a separate dedicated policy covers those user types.

/** Guest/external user type flags from MS Graph */
const GUEST_TYPE_LABELS: Record<string, string> = {
  internalGuest: "Internal guest users",
  b2bCollaborationGuest: "B2B collaboration guest users",
  b2bCollaborationMember: "B2B collaboration member users",
  b2bDirectConnectUser: "B2B direct connect users",
  otherExternalUser: "Other external users",
  serviceProvider: "Service provider users",
};

function checkGuestExternalUserExclusions(
  policy: ConditionalAccessPolicy,
  context: TenantContext
): Finding[] {
  const findings: Finding[] = [];

  const users = policy.conditions.users;
  const targetsAllUsers = users.includeUsers.includes("All");
  if (!targetsAllUsers) return findings;

  // Check 1: Simple "GuestsOrExternalUsers" in excludeUsers
  const excludesGuestsSimple = users.excludeUsers.includes("GuestsOrExternalUsers");

  // Check 2: Structured excludeGuestsOrExternalUsers object
  const excludeGuestsObj = users.excludeGuestsOrExternalUsers as {
    guestOrExternalUserTypes?: string;
    externalTenants?: {
      "@odata.type"?: string;
      membershipKind?: string;
    };
  } | null | undefined;

  const hasStructuredGuestExclusion = excludeGuestsObj?.guestOrExternalUserTypes != null;
  const hasAnyGuestExclusion = excludesGuestsSimple || hasStructuredGuestExclusion;

  if (!hasAnyGuestExclusion) return findings;

  // Parse structured guest exclusion details
  let excludedGuestTypes: string[] = [];
  let externalTenantScope = "";

  if (hasStructuredGuestExclusion && excludeGuestsObj) {
    excludedGuestTypes = (excludeGuestsObj.guestOrExternalUserTypes ?? "")
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean);

    const tenants = excludeGuestsObj.externalTenants;
    if (tenants?.["@odata.type"]?.includes("AllExternalTenants") || tenants?.membershipKind === "all") {
      externalTenantScope = "all external organizations";
    } else if (tenants?.membershipKind === "enumerated") {
      externalTenantScope = "specific external organizations";
    }
  }

  const allKnownTypes = Object.keys(GUEST_TYPE_LABELS);
  const excludesAllTypes = excludesGuestsSimple ||
    allKnownTypes.every((t) => excludedGuestTypes.includes(t));

  // Determine what grant controls are bypassed
  const grant = policy.grantControls;
  const requiresMfa =
    grant?.builtInControls.includes("mfa") || grant?.authenticationStrength != null;
  const requiresCompliance =
    grant?.builtInControls.includes("compliantDevice") ||
    grant?.builtInControls.includes("domainJoinedDevice");
  const blocks = grant?.builtInControls.includes("block");

  const targetsSecurityRegistration = policy.conditions.applications
    .includeUserActions?.includes("urn:user:registersecurityinfo");
  const targetsAllApps = policy.conditions.applications.includeApplications.includes("All");

  // Check if there's a separate policy covering guests
  const hasGuestCoveragePolicy = context.policies.some((p) => {
    if (p.id === policy.id || p.state === "disabled") return false;
    const pu = p.conditions.users;
    // Policy that includes guests explicitly
    const includesGuests =
      pu.includeUsers.includes("GuestsOrExternalUsers") ||
      (pu.includeGuestsOrExternalUsers != null);
    // Or policy that targets All Users without guest exclusions
    const allWithoutGuestExcl =
      pu.includeUsers.includes("All") &&
      !pu.excludeUsers.includes("GuestsOrExternalUsers") &&
      pu.excludeGuestsOrExternalUsers == null;
    return includesGuests || allWithoutGuestExcl;
  });

  // Build human-readable description of excluded types
  let guestDescription = "";
  let excludedTypesList: string[] = [];
  
  if (excludesGuestsSimple) {
    guestDescription = "all guest and external users";
    excludedTypesList = Object.keys(GUEST_TYPE_LABELS);
  } else {
    const typeLabels = excludedGuestTypes
      .map((t) => GUEST_TYPE_LABELS[t] ?? t)
      .join(", ");
    guestDescription = typeLabels + (externalTenantScope ? ` from ${externalTenantScope}` : "");
    excludedTypesList = excludedGuestTypes;
  }

  // Categorize guest types by enforcement model
  const resourceTenantEnforceable = excludedTypesList.filter(t => 
    ["b2bCollaborationGuest", "b2bCollaborationMember", "internalGuest", "serviceProvider"].includes(t)
  );
  const homeTenantOnly = excludedTypesList.filter(t => t === "b2bDirectConnectUser");
  const otherTypes = excludedTypesList.filter(t => t === "otherExternalUser");

  // Build enforcement model explanation
  let enforcementDetail = "";
  if (resourceTenantEnforceable.length > 0) {
    const types = resourceTenantEnforceable.map(t => GUEST_TYPE_LABELS[t] ?? t).join(", ");
    enforcementDetail += `\n\n**Resource tenant enforceable (excluded from this policy):** ${types}. ` +
      `These guest types can be required to satisfy MFA in YOUR tenant if you enable MFA trust in Cross-Tenant Access Settings. ` +
      `The guest completes MFA in their home tenant, and you trust that MFA claim via inbound trust settings.`;
  }
  if (homeTenantOnly.length > 0) {
    enforcementDetail += `\n\n**Home tenant only (excluded from this policy):** ${GUEST_TYPE_LABELS["b2bDirectConnectUser"]}. ` +
      `These users authenticate entirely in their home tenant — your CA policies are NOT enforced. ` +
      `You cannot directly require MFA for B2B Direct Connect users, but you can require their home tenant has equivalent policies via trust settings.`;
  }
  if (otherTypes.length > 0) {
    enforcementDetail += `\n\n**Other external users (excluded from this policy):** ${GUEST_TYPE_LABELS["otherExternalUser"]}. ` +
      `External identities not covered by B2B collaboration or direct connect.`;
  }

  // Severity depends on scope and whether compensating policy exists
  let severity: Severity;
  let context_detail = "";

  if (targetsSecurityRegistration) {
    severity = hasGuestCoveragePolicy ? "medium" : "high";
    context_detail =
      `This policy protects security info registration but excludes ${guestDescription}. ` +
      `A compromised B2B guest account could register attacker-controlled MFA methods from ` +
      `any location without any controls.`;
  } else if (blocks && targetsAllApps) {
    severity = hasGuestCoveragePolicy ? "medium" : "high";
    context_detail =
      `This policy blocks access for all apps but excludes ${guestDescription}. ` +
      `These external users bypass the block entirely.`;
  } else if (requiresMfa && targetsAllApps) {
    severity = hasGuestCoveragePolicy ? "medium" : "high";
    context_detail =
      `This policy requires MFA for all apps but excludes ${guestDescription}. ` +
      `These external users can access resources without MFA.`;
  } else {
    severity = hasGuestCoveragePolicy ? "low" : "medium";
    context_detail =
      `This policy targets all users but excludes ${guestDescription}. ` +
      `External users bypass this policy's controls.`;
  }

  if (!hasGuestCoveragePolicy) {
    context_detail += ` No separate policy was found covering guest/external users for ` +
      `comparable controls — this creates an unprotected gap.`;
  }

  findings.push({
    id: nextFindingId(),
    policyId: policy.id,
    policyName: policy.displayName,
    severity,
    category: "Guest/External User Exclusion",
    title: `${excludesAllTypes ? "All" : excludedGuestTypes.length} guest/external user type(s) excluded${!hasGuestCoveragePolicy ? " — no compensating policy found" : ""}`,
    description:
      context_detail +
      (excludedGuestTypes.length > 0 && !excludesGuestsSimple
        ? ` **Excluded types:** ${excludedGuestTypes.map((t) => GUEST_TYPE_LABELS[t] ?? t).join(", ")}.`
        : excludesGuestsSimple
        ? ` **Excluded types:** All guest and external user types.`
        : "") +
      (externalTenantScope
        ? ` **Tenant scope:** ${externalTenantScope}.`
        : "") +
      enforcementDetail,
    recommendation:
      hasGuestCoveragePolicy
        ? `A compensating policy was found, but verify it enforces equivalent controls for guest/external users. ` +
          `Ensure the guest policy covers the same apps and actions as this policy. ` +
          `**For B2B Collaboration guests (b2bCollaborationGuest, b2bCollaborationMember):** Enable MFA trust in ` +
          `Cross-Tenant Access Settings (Entra Admin Center → External Identities → Cross-tenant access settings → ` +
          `Inbound access settings → Trust settings → "Trust multi-factor authentication from Azure AD tenants"). ` +
          `**For B2B Direct Connect users:** Your CA policies do not apply — require equivalent policies in the partner tenant via trust settings.`
        : `Create a dedicated CA policy for guest/external users with appropriate controls, or ` +
          `remove the guest exclusion from this policy. Per CIS and Microsoft Zero Trust guidance, ` +
          `guest accounts should be subject to at least MFA and ideally session time restrictions. ` +
          `If guests must be excluded from this specific policy, create a companion policy like ` +
          `"GLOBAL - GRANT - MFA - GuestsExternal" to ensure coverage. ` +
          `**For B2B Collaboration guests (b2bCollaborationGuest, b2bCollaborationMember):** Enable MFA trust in ` +
          `Cross-Tenant Access Settings to require guests complete MFA in their home tenant before accessing your resources. ` +
          `**For B2B Direct Connect users:** These users authenticate in their home tenant only — your CA policies do NOT apply. ` +
          `Require the partner organization has equivalent policies via Cross-Tenant Access Settings trust configuration.`,
  });

  return findings;
}

// ─── Check: Credential Registration Constraints (May 2026) ────────────────────
// Starting May 2026, CA policies targeting "Register security info" will now
// be evaluated during Windows Hello for Business and macOS Platform SSO
// credential provisioning. This check flags policies that may prevent users
// from setting up new devices due to strict device compliance or location
// requirements that cannot be satisfied during initial device setup.
//
// Reference: MC Post March 2026 - "Plan for change – Conditional Access 
// enforcement during credential registration for Windows Hello for Business 
// and macOS Platform SSO"

function checkCredentialRegistrationConstraints(
  policy: ConditionalAccessPolicy,
  context: TenantContext
): Finding[] {
  const findings: Finding[] = [];

  // Only check enabled policies targeting "Register security info" user action
  if (policy.state === "disabled") return findings;

  const targetsSecurityRegistration = policy.conditions.applications
    .includeUserActions?.includes("urn:user:registersecurityinfo");

  if (!targetsSecurityRegistration) return findings;

  const grant = policy.grantControls;
  const session = policy.sessionControls;
  const conditions = policy.conditions;

  // Check for constraints that may be problematic during initial device setup
  const requiresCompliance =
    grant?.builtInControls.includes("compliantDevice") ||
    grant?.builtInControls.includes("domainJoinedDevice");

  const requiresApprovedApp = grant?.builtInControls.includes("approvedApplication");
  const requiresAppProtection = grant?.builtInControls.includes("compliantApplication");

  const hasLocationConditions =
    (conditions.locations?.includeLocations?.length ?? 0) > 0 ||
    (conditions.locations?.excludeLocations?.length ?? 0) > 0;

  const hasDeviceFilter = conditions.devices?.deviceFilter?.rule != null;

  // Flag high-risk constraints
  const issues: string[] = [];

  if (requiresCompliance) {
    issues.push(
      "**Device compliance**: Users provisioning WHfB/Platform SSO on a NEW device cannot satisfy this requirement during initial setup (device isn't enrolled yet)"
    );
  }

  if (requiresApprovedApp || requiresAppProtection) {
    issues.push(
      "**Approved/protected app**: Users setting up credentials during device provisioning may not have approved apps installed yet"
    );
  }

  if (hasLocationConditions) {
    const includedLocs = conditions.locations?.includeLocations ?? [];
    const excludedLocs = conditions.locations?.excludeLocations ?? [];

    // If requiring trusted locations
    if (
      includedLocs.length > 0 &&
      !includedLocs.includes("All") &&
      !includedLocs.includes("AllTrusted")
    ) {
      const namedLocNames = includedLocs
        .map((id) => {
          if (id === "00000000-0000-0000-0000-000000000000") return "MFA Trusted IPs (legacy)";
          const loc = context.namedLocations.find((l) => l.id === id);
          return loc?.displayName ?? id;
        })
        .join(", ");

      issues.push(
        `**Trusted location requirement**: Policy requires access from: ${namedLocNames}. Users setting up credentials from home/remote locations (common for new device setup) will be blocked`
      );
    }

    // If blocking untrusted locations
    if (excludedLocs.includes("AllTrusted") && !includedLocs.includes("AllTrusted")) {
      issues.push(
        "**Untrusted location block**: Policy blocks access from untrusted locations. Users setting up new devices from home/public networks may be blocked"
      );
    }
  }

  if (hasDeviceFilter) {
    issues.push(
      "**Device filter**: Device filters may not evaluate correctly on devices during initial provisioning before they're fully enrolled/registered"
    );
  }

  if (issues.length === 0) return findings;

  // Determine severity based on how likely this is to block legitimate enrollment
  let severity: Severity = "medium";
  if (requiresCompliance || (hasLocationConditions && !conditions.locations?.includeLocations?.includes("All"))) {
    severity = "high";
  }

  findings.push({
    id: nextFindingId(),
    policyId: policy.id,
    policyName: policy.displayName,
    severity,
    category: "Credential Registration Constraints",
    title: "Policy may block Windows Hello / Platform SSO setup on new devices (May 2026 enforcement)",
    description:
      `**Starting May 2026**, this policy will be enforced during Windows Hello for Business and macOS Platform SSO ` +
      `credential registration (not just sign-in). This policy has the following constraints that may prevent ` +
      `users from completing device setup:\n\n` +
      issues.map((i) => `• ${i}`).join("\n") +
      `\n\n` +
      `When users provision WHfB on a new laptop or register macOS Platform SSO credentials for the first time, ` +
      `they may not be able to satisfy these requirements. This can block legitimate enrollment flows. ` +
      `Per Microsoft's Message Center post (MC March 2026), admins should review policies targeting "Register security info" ` +
      `before enforcement begins in late April 2026.`,
    recommendation:
      requiresCompliance
        ? `**High Priority**: Remove device compliance requirements from this policy or add exclusions for users ` +
          `during initial device provisioning. Consider one of these approaches:\n\n` +
          `1. **Separate policies**: Create one policy for sign-in (with compliance) and a second policy for ` +
          `registration (requiring only MFA + phishing-resistant authentication)\n\n` +
          `2. **Temporary Access Pass (TAP)**: Use TAP for new device enrollment flows, excluded from this policy\n\n` +
          `3. **Location bypass**: Allow registration from trusted corporate networks only (where IT can assist)\n\n` +
          `4. **Report-only mode**: Enable report-only mode BEFORE May 2026 to see impact without blocking users\n\n` +
          `Recommended grant controls for registration policies: MFA + authentication strength (phishing-resistant) ` +
          `— avoid device compliance/location requirements.`
        : hasLocationConditions
        ? `**Review Recommended**: If users commonly set up new devices from home/remote locations, consider:\n\n` +
          `1. Allow "All locations" for registration (even if blocking specific locations for sign-in)\n\n` +
          `2. Include "MFA Trusted IPs" or home office locations in allowed locations\n\n` +
          `3. Create a separate policy for registration with relaxed location requirements\n\n` +
          `4. Use report-only mode before May 2026 to identify affected users\n\n` +
          `Remember: MFA is still required by default for ALL passwordless credential registration (WHfB, ` +
          `Platform SSO, passkeys) even without CA policies.`
        : `Review this policy's device filter and app requirements to ensure they don't block legitimate ` +
          `credential registration flows. Test with report-only mode before May 2026 enforcement. ` +
          `Per Microsoft guidance: ensure users setting up new devices can satisfy policy requirements, ` +
          `or add exclusions/adjust conditions for the registration flow.`,
  });

  return findings;
}

// ─── Microsoft-Managed Policy Check (per-policy) ─────────────────────────────

const MANAGED_POLICY_KEYWORDS = [
  "block legacy authentication",
  "block device code flow",
  "multifactor authentication for admins",
  "multifactor authentication for all users",
  "multifactor authentication for per-user",
  "reauthentication for risky sign-ins",
  "block access for high-risk users",
  "block all high risk agents",
];

function checkMicrosoftManagedPolicy(
  policy: ConditionalAccessPolicy
): Finding[] {
  const findings: Finding[] = [];
  const name = policy.displayName.toLowerCase();

  const isManaged = MANAGED_POLICY_KEYWORDS.some((kw) => name.includes(kw));
  if (!isManaged || policy.state !== "disabled") return findings;

  findings.push({
    id: nextFindingId(),
    policyId: policy.id,
    policyName: policy.displayName,
    severity: "info",
    category: "Microsoft-Managed Policies",
    title: "MC1246002: Disabled managed policy — possible Baseline Security Mode phantom draft",
    description:
      "Between Nov 2025 and Feb 2026, Baseline Security Mode accidentally created " +
      "disabled draft CA policies in some tenants (MC1246002). These phantom policies are not a " +
      "security risk — Microsoft is removing unintended drafts automatically. If you did not " +
      "intentionally disable this managed policy, this is likely the cause.",
    recommendation:
      "No action required if this was created by Baseline Security Mode. Microsoft will clean up " +
      "phantom drafts. If you intentionally disabled this managed policy, consider enabling it in " +
      "report-only mode to evaluate its impact. " +
      "See: https://learn.microsoft.com/entra/identity/conditional-access/managed-policies",
  });

  return findings;
}

// ─── Check: Guest Users with Authentication Strength Requirements ──────────────

/**
 * Check: Guest Users Requiring Authentication Strength (MFA Trust)
 * 
 * Detects policies requiring authentication strength (especially phishing-resistant MFA)
 * for guest users. Guest users authenticate in their home tenant, so the resource tenant
 * must trust inbound MFA claims via Cross-Tenant Access Settings.
 * 
 * Reference: https://learn.microsoft.com/entra/external-id/cross-tenant-access-settings-b2b-collaboration
 * Reference: https://learn.microsoft.com/entra/external-id/authentication-conditional-access
 */
function checkGuestAuthenticationStrength(
  policy: ConditionalAccessPolicy
): Finding[] {
  const findings: Finding[] = [];

  // Only check enabled policies
  if (policy.state === "disabled") return findings;

  const users = policy.conditions.users;
  const grant = policy.grantControls;

  // Check if policy targets guest/external users
  const targetsGuests =
    users.includeUsers.includes("GuestsOrExternalUsers") ||
    users.includeGuestsOrExternalUsers != null;

  // Check if policy requires authentication strength
  const requiresAuthStrength = grant?.authenticationStrength != null;

  // Check if policy requires MFA (which may include authentication strength)
  const requiresMFA = grant?.builtInControls.includes("mfa");

  if (!targetsGuests || (!requiresAuthStrength && !requiresMFA)) {
    return findings;
  }

  // Determine severity and messaging based on authentication strength type
  let severity: Severity = "high";
  let strengthType = "MFA";
  let requiresCrossTenantTrust = true;

  if (requiresAuthStrength) {
    const authStrengthId = grant.authenticationStrength?.id || "";
    const authStrengthName = grant.authenticationStrength?.displayName || "Unknown";
    
    // Check if it's phishing-resistant (most restrictive)
    if (
      authStrengthName.toLowerCase().includes("phishing-resistant") ||
      authStrengthName.toLowerCase().includes("phishing resistant")
    ) {
      severity = "high";
      strengthType = "Phishing-resistant MFA";
    } else {
      severity = "medium";
      strengthType = `Authentication strength: ${authStrengthName}`;
    }
  }

  // Determine guest user types being targeted
  const guestTypes: string[] = [];
  if (users.includeGuestsOrExternalUsers) {
    const guestConfig = users.includeGuestsOrExternalUsers as any;
    const guestTypeString = guestConfig.guestOrExternalUserTypes || "";
    
    if (guestTypeString.includes("b2bCollaborationGuest")) {
      guestTypes.push("B2B Collaboration guests");
    }
    if (guestTypeString.includes("b2bCollaborationMember")) {
      guestTypes.push("B2B Collaboration members");
    }
    if (guestTypeString.includes("b2bDirectConnectUser")) {
      guestTypes.push("B2B Direct Connect users");
    }
    if (guestTypeString.includes("internalGuest")) {
      guestTypes.push("Internal guests");
    }
    if (guestTypeString.includes("serviceProvider")) {
      guestTypes.push("Service provider users");
    }
  }

  const guestTypeText =
    guestTypes.length > 0
      ? guestTypes.join(", ")
      : "All guest/external users";

  findings.push({
    id: nextFindingId(),
    policyId: policy.id,
    policyName: policy.displayName,
    severity: severity,
    category: "Guest Authentication Requirements",
    title: `Guest users required to satisfy ${strengthType} — may need Cross-Tenant Access Settings`,
    description:
      `This policy requires **${strengthType}** for **${guestTypeText}**. ` +
      `\n\n**Important:** Guest users authenticate in their **home tenant**, not in your resource tenant. ` +
      `For guests to satisfy this policy requirement, you must:\n\n` +
      `1. **Enable MFA trust in Cross-Tenant Access Settings** for the guest's home tenant\n` +
      `2. The guest must have already completed MFA in their home tenant\n` +
      `3. The home tenant must present an MFA claim that satisfies your authentication strength requirement\n\n` +
      `**B2B Collaboration guests** can satisfy MFA requirements if their home tenant presents MFA claims ` +
      `AND you trust those claims in Cross-Tenant Access Settings.\n\n` +
      `**B2B Direct Connect users** authenticate entirely in their home tenant — your policy requirements ` +
      `are not directly enforced, but you can require that their home tenant has equivalent policies.\n\n` +
      `${
        requiresAuthStrength && strengthType.includes("Phishing-resistant")
          ? `**Phishing-resistant MFA note:** Very few tenants have phishing-resistant MFA deployed. ` +
            `If you require phishing-resistant MFA for guests, ensure their home tenant supports FIDO2, ` +
            `Windows Hello for Business, or Certificate-Based Authentication, AND that you trust those ` +
            `MFA claims inbound.\n\n`
          : ""
      }` +
      `Without Cross-Tenant Access MFA trust enabled, guest users will be **blocked** even if they ` +
      `completed MFA in their home tenant.`,
    recommendation:
      `**Action Required:**\n\n` +
      `1. **Review Cross-Tenant Access Settings**: Navigate to **Entra Admin Center → External Identities → ` +
      `Cross-tenant access settings → Inbound access settings**\n\n` +
      `2. **Enable MFA trust** for each organization whose guests need access:\n` +
      `   - **Default settings**: Apply to all external organizations (broadest)\n` +
      `   - **Organization-specific settings**: Apply to specific partner tenants only (most secure)\n\n` +
      `3. **Configure B2B collaboration trust settings**:\n` +
      `   - Check "Trust multi-factor authentication from Azure AD tenants"\n` +
      `   - Optionally: "Trust compliant devices" and "Trust hybrid Azure AD joined devices"\n\n` +
      `4. **Validate guest sign-in flow**: Test with a guest user from a trusted tenant to confirm MFA claims ` +
      `are honored\n\n` +
      `5. **Consider scoping**: If only specific guest users need ${strengthType}, use the ` +
      `\`includeGuestsOrExternalUsers\` condition to target specific guest types rather than all guests\n\n` +
      `6. **Use report-only mode first**: Enable this policy in report-only mode and review sign-in logs ` +
      `to identify which guests would be blocked before enforcing\n\n` +
      `**Learn more:**\n` +
      `- [Configure Cross-Tenant Access Settings](https://learn.microsoft.com/entra/external-id/cross-tenant-access-settings-b2b-collaboration)\n` +
      `- [B2B Collaboration MFA](https://learn.microsoft.com/entra/external-id/authentication-conditional-access#mfa-for-azure-ad-external-users)\n` +
      `- [Authentication strength for external users](https://learn.microsoft.com/entra/identity/authentication/concept-authentication-strengths#external-users)\n` +
      `- [B2B Direct Connect](https://learn.microsoft.com/entra/external-id/b2b-direct-connect-overview)`,
  });

  return findings;
}

// ─── Check: Protected Actions Configuration ──────────────────────────────────

/**
 * Check: Protected Actions Best Practices
 * 
 * Protected Actions require additional authentication for sensitive admin operations
 * like deleting CA policies, modifying PIM roles, etc. This check identifies
 * common misconfigurations and best practices.
 * 
 * Reference: https://learn.microsoft.com/entra/identity/conditional-access/how-to-policy-protected-actions
 */
function checkProtectedActions(
  policy: ConditionalAccessPolicy
): Finding[] {
  const findings: Finding[] = [];

  const userActions = policy.conditions.applications.includeUserActions;
  
  // Not a protected actions policy if no user actions
  if (userActions.length === 0) return findings;

  // Check if this is targeting protected actions (starts with microsoft.directory)
  const protectedActions = userActions.filter(action => 
    action.startsWith("microsoft.directory")
  );

  if (protectedActions.length === 0) return findings;

  const grant = policy.grantControls;
  const users = policy.conditions.users;

  // CRITICAL: Protected Actions must use authentication strength, not basic MFA
  const usesBasicMFA = grant?.builtInControls.includes("mfa") && !grant?.authenticationStrength;
  const usesAuthStrength = grant?.authenticationStrength != null;

  if (usesBasicMFA) {
    findings.push({
      id: nextFindingId(),
      policyId: policy.id,
      policyName: policy.displayName,
      severity: "high",
      category: "Protected Actions Configuration",
      title: "Protected Actions policy uses basic MFA instead of authentication strength",
      description:
        `This policy targets protected actions (${protectedActions.join(", ")}) but uses the basic "Require MFA" ` +
        `grant control instead of an authentication strength. **Protected Actions policies MUST use authentication strength** ` +
        `to function correctly.\n\n` +
        `When using basic MFA:\n` +
        `- The policy may not enforce correctly during the protected action\n` +
        `- Users may bypass the additional authentication requirement\n` +
        `- Microsoft's recommendation is always authentication strength for Protected Actions\n\n` +
        `Protected Actions are sensitive operations like:\n` +
        `- \`microsoft.directory.conditionalAccessPolicies.delete\` - Deleting CA policies\n` +
        `- \`microsoft.directory.conditionalAccessPolicies.update\` - Modifying CA policies\n` +
        `- \`microsoft.directory.roleManagement.update\` - Changing role assignments\n` +
        `- \`microsoft.directory.applications.update\` - Modifying app registrations\n\n` +
        `These require phishing-resistant or strong authentication to prevent privilege escalation attacks.`,
      recommendation:
        `**Action Required:**\n\n` +
        `1. **Replace the grant control**: Remove "Require multifactor authentication" and add an authentication strength:\n` +
        `   - Recommended: "Phishing-resistant MFA" strength for maximum security\n` +
        `   - Minimum: "Multifactor authentication" strength (allows broader MFA methods)\n\n` +
        `2. **Navigate to**: Entra Admin Center → Protection → Conditional Access → [This Policy] → Grant\n` +
        `3. **Select**: "Require authentication strength" → Choose your strength policy\n` +
        `4. **Verify admin registration**: Ensure all targeted admins have registered the required auth methods before enforcing\n\n` +
        `5. **Use report-only mode first**: Enable report-only to validate that admins can satisfy the strength requirement\n\n` +
        `**Learn more:**\n` +
        `- [Protected Actions for CA](https://learn.microsoft.com/entra/identity/conditional-access/how-to-policy-protected-actions)\n` +
        `- [Authentication Strengths](https://learn.microsoft.com/entra/identity/authentication/concept-authentication-strengths)`,
    });
  }

  // BEST PRACTICE: Protected Actions should target admins, not all users
  const targetsAllUsers = users.includeUsers.includes("All");
  const targetsAdminRoles = users.includeRoles && users.includeRoles.length > 0;

  if (targetsAllUsers && !targetsAdminRoles) {
    findings.push({
      id: nextFindingId(),
      policyId: policy.id,
      policyName: policy.displayName,
      severity: "medium",
      category: "Protected Actions Configuration",
      title: "Protected Actions policy targets 'All users' instead of specific admin roles",
      description:
        `This policy targets protected actions (${protectedActions.join(", ")}) and applies to **All users**. ` +
        `\n\nProtected Actions are typically administrative operations that only admins can perform. Targeting "All users" ` +
        `creates unnecessary auth prompts for non-admin users who wouldn't be able to perform these actions anyway.\n\n` +
        `**Best practice:** Target only the specific admin roles that perform these protected actions:\n` +
        `- For CA policy changes: Conditional Access Administrator, Security Administrator\n` +
        `- For role management: Privileged Role Administrator, Global Administrator\n` +
        `- For app registration changes: Application Administrator, Cloud Application Administrator\n\n` +
        `This improves user experience and reduces support burden from unnecessary MFA prompts.`,
      recommendation:
        `**Review Recommended:**\n\n` +
        `1. **Determine which roles perform these actions** in your environment\n` +
        `2. **Update the policy**: Change from "All users" to specific directory roles\n` +
        `3. **Exclude break-glass accounts**: Ensure emergency access accounts can bypass if needed\n\n` +
        `Example role assignments:\n` +
        `- Delete/Update CA policies → Conditional Access Administrator, Security Administrator\n` +
        `- Role management → Privileged Role Administrator\n` +
        `- App registrations → Application Administrator, Cloud Application Administrator\n\n` +
        `**Learn more:**\n` +
        `- [Protected Actions Scoping](https://learn.microsoft.com/entra/identity/conditional-access/how-to-policy-protected-actions#scope-the-policy)`,
    });
  }

  // CHECK: Phishing-resistant MFA recommendation for Protected Actions
  if (usesAuthStrength && grant?.authenticationStrength) {
    const authStrengthName = grant.authenticationStrength.displayName || "";
    const isPhishingResistant = 
      authStrengthName.toLowerCase().includes("phishing-resistant") ||
      authStrengthName.toLowerCase().includes("phishing resistant");

    if (!isPhishingResistant) {
      findings.push({
        id: nextFindingId(),
        policyId: policy.id,
        policyName: policy.displayName,
        severity: "info",
        category: "Protected Actions Configuration",
        title: `Protected Actions using "${authStrengthName}" — consider phishing-resistant MFA`,
        description:
          `This policy protects sensitive admin actions (${protectedActions.join(", ")}) using the ` +
          `"${authStrengthName}" authentication strength.\n\n` +
          `**Microsoft's recommendation:** Use **phishing-resistant MFA** for Protected Actions to prevent ` +
          `privilege escalation attacks. Standard MFA methods (SMS, TOTP, push notifications) can be defeated ` +
          `by adversary-in-the-middle (AiTM) phishing attacks.\n\n` +
          `Protected Actions are high-value targets:\n` +
          `- Attackers who compromise an admin account want to delete CA policies to remove security controls\n` +
          `- Modifying role assignments enables persistent access\n` +
          `- Changing app registrations can grant broad API permissions\n\n` +
          `Phishing-resistant methods include:\n` +
          `- FIDO2 security keys\n` +
          `- Windows Hello for Business\n` +
          `- Certificate-Based Authentication\n` +
          `- Passkeys in Microsoft Authenticator`,
        recommendation:
          `**Consider Upgrading:**\n\n` +
          `1. **Deploy phishing-resistant credentials** to admins who perform protected actions\n` +
          `2. **Update this policy** to use the "Phishing-resistant MFA" authentication strength\n` +
          `3. **Use Temporary Access Pass (TAP)** to bootstrap phishing-resistant credential registration\n\n` +
          `This is informational only — your current configuration meets minimum requirements. ` +
          `Upgrading to phishing-resistant provides defense-in-depth against sophisticated attacks.\n\n` +
          `**Learn more:**\n` +
          `- [Phishing-resistant authentication methods](https://learn.microsoft.com/entra/identity/authentication/concept-authentication-strengths#built-in-authentication-strengths)\n` +
          `- [Deploy phishing-resistant auth](https://learn.microsoft.com/entra/identity/authentication/how-to-mfa-number-match)`,
      });
    }
  }

  // CHECK: Report-only mode for Protected Actions (best practice for initial deployment)
  if (policy.state === "enabledForReportingButNotEnforced") {
    findings.push({
      id: nextFindingId(),
      policyId: policy.id,
      policyName: policy.displayName,
      severity: "info",
      category: "Protected Actions Configuration",
      title: "Protected Actions policy in report-only mode — consider enabling for enforcement",
      description:
        `This Protected Actions policy is currently in **report-only mode**. While this is the recommended ` +
        `initial deployment state, once you've validated that admins can satisfy the requirements, the policy ` +
        `should be enabled for enforcement.\n\n` +
        `In report-only mode:\n` +
        `- The additional authentication is NOT required\n` +
        `- Sign-in logs show what WOULD have happened\n` +
        `- Admins can still perform protected actions without the additional verification\n\n` +
        `This means your protected actions are currently NOT protected. Report-only should be a temporary ` +
        `validation phase, not a permanent state.`,
      recommendation:
        `**Next Steps:**\n\n` +
        `1. **Review sign-in logs**: Check if admins successfully satisfy the authentication strength in report-only\n` +
        `2. **Validate admin readiness**: Confirm all targeted admins have registered required credentials\n` +
        `3. **Enable enforcement**: Change policy state from "Report-only" to "On"\n` +
        `4. **Monitor for issues**: Watch for authentication failures in the first 24-48 hours\n\n` +
        `Recommendation: Enable enforcement after 1-2 weeks of successful report-only validation.\n\n` +
        `**Learn more:**\n` +
        `- [Deploy Protected Actions](https://learn.microsoft.com/entra/identity/conditional-access/how-to-policy-protected-actions#test-the-policy)`,
    });
  }

  // CHECK: Break-glass account exclusions
  const hasExclusions = users.excludeUsers && users.excludeUsers.length > 0;
  if (!hasExclusions && policy.state === "enabled") {
    findings.push({
      id: nextFindingId(),
      policyId: policy.id,
      policyName: policy.displayName,
      severity: "medium",
      category: "Protected Actions Configuration",
      title: "Protected Actions policy has no user exclusions — ensure break-glass access",
      description:
        `This policy protects sensitive admin actions but does not exclude any users (such as break-glass accounts). ` +
        `\n\n**Risk:** If the authentication strength requirement fails (e.g., FIDO2 not working, auth service outage), ` +
        `admins may be unable to perform critical operations like:\n` +
        `- Disabling a misconfigured CA policy that locks out users\n` +
        `- Modifying role assignments to restore access\n` +
        `- Responding to security incidents that require CA policy changes\n\n` +
        `Break-glass accounts should be excluded from Protected Actions policies to ensure emergency access to ` +
        `critical admin operations.`,
      recommendation:
        `**Review Recommended:**\n\n` +
        `1. **Identify break-glass accounts**: Typically 2 emergency access accounts with permanent Global Admin\n` +
        `2. **Exclude from this policy**: Add break-glass accounts to the "Exclude users" list\n` +
        `3. **Compensating controls**: Ensure break-glass accounts are:\n` +
        `   - Cloud-only (not synced from AD)\n` +
        `   - Monitored with alerts for any sign-in activity\n` +
        `   - Excluded from ALL CA policies that could block emergency access\n` +
        `   - Using strong, randomly generated passwords stored in a secure physical location\n\n` +
        `Protected Actions policies should allow break-glass bypass to prevent self-inflicted lockouts.\n\n` +
        `**Learn more:**\n` +
        `- [Manage emergency access accounts](https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access)`,
    });
  }

  return findings;
}

// ─── Break-Glass Identification Helper ────────────────────────────────────────

interface BreakGlassCandidate {
  id: string;
  count: number;
  policies: string[];
  type: "user" | "group";
}

/**
 * Identifies the most likely break-glass account or group by analyzing exclusion
 * patterns across all enabled "All Users" policies.
 */
function identifyBreakGlass(context: TenantContext): BreakGlassCandidate | null {
  const enabled = context.policies.filter(
    (p) => p.state === "enabled" || p.state === "enabledForReportingButNotEnforced"
  );

  const candidates = new Map<string, { count: number; policies: string[]; type: "user" | "group" }>();

  for (const p of enabled) {
    if (!p.conditions.users.includeUsers.includes("All")) continue;

    for (const userId of p.conditions.users.excludeUsers) {
      if (userId === "GuestsOrExternalUsers") continue;
      if (!candidates.has(userId)) {
        candidates.set(userId, { count: 0, policies: [], type: "user" });
      }
      const c = candidates.get(userId)!;
      c.count++;
      c.policies.push(p.displayName);
    }

    for (const groupId of p.conditions.users.excludeGroups) {
      if (!candidates.has(groupId)) {
        candidates.set(groupId, { count: 0, policies: [], type: "group" });
      }
      const c = candidates.get(groupId)!;
      c.count++;
      c.policies.push(p.displayName);
    }
  }

  let primary: BreakGlassCandidate | null = null;
  for (const [id, data] of candidates.entries()) {
    if (!primary || data.count > primary.count) {
      primary = { id, ...data };
    }
  }
  return primary;
}

// ─── Per-Policy Break-Glass Exclusion Check ──────────────────────────────────

function checkBreakGlassPerPolicy(
  policy: ConditionalAccessPolicy,
  breakGlass: BreakGlassCandidate | null,
  context: TenantContext
): Finding[] {
  if (!breakGlass) return []; // Tenant-wide finding handles this case

  const label = breakGlass.type === "user" ? "break-glass account" : "break-glass group";
  const displayName =
    breakGlass.type === "user"
      ? context.directoryObjects.get(breakGlass.id)?.displayName ?? `ID: ${breakGlass.id.substring(0, 8)}…`
      : context.directoryObjects.get(breakGlass.id)?.displayName ?? `ID: ${breakGlass.id.substring(0, 8)}…`;

  const excluded =
    breakGlass.type === "user"
      ? policy.conditions.users.excludeUsers.includes(breakGlass.id)
      : policy.conditions.users.excludeGroups.includes(breakGlass.id);

  // Determine if this policy actually targets users (skip workload-identity-only policies)
  const targetsUsers =
    policy.conditions.users.includeUsers.length > 0 ||
    policy.conditions.users.includeGroups.length > 0 ||
    policy.conditions.users.includeRoles.length > 0;
  if (!targetsUsers) return [];

  if (excluded) {
    return [
      {
        id: nextFindingId(),
        policyId: policy.id,
        policyName: policy.displayName,
        severity: "info",
        category: "Break-Glass",
        title: `Break-glass ${breakGlass.type} excluded ✓`,
        description:
          `The ${label} **${displayName}** is excluded from this policy. ` +
          `This ensures emergency access is preserved if this policy causes a lockout.`,
        recommendation:
          `No action required. Verify the ${label} periodically to ensure it is still valid ` +
          `and monitored for sign-in activity.`,
      },
    ];
  } else {
    // Determine severity based on policy characteristics
    const grant = policy.grantControls;
    const blocks = grant?.builtInControls.includes("block");
    const requiresMfa =
      grant?.builtInControls.includes("mfa") || grant?.authenticationStrength != null;
    const requiresCompliance =
      grant?.builtInControls.includes("compliantDevice") ||
      grant?.builtInControls.includes("domainJoinedDevice");
    const targetsAllUsers = policy.conditions.users.includeUsers.includes("All");
    const targetsAllApps =
      policy.conditions.applications.includeApplications.includes("All");

    // Critical: blocks all users + all apps without break-glass
    // High: MFA/compliance for all users without break-glass
    // Medium: other policies without break-glass
    let severity: Severity = "low";
    if (blocks && targetsAllUsers && targetsAllApps) {
      severity = "high";
    } else if ((requiresMfa || requiresCompliance) && targetsAllUsers) {
      severity = "medium";
    } else if (blocks && targetsAllUsers) {
      severity = "medium";
    }

    // Microsoft managed & disabled — just informational
    const isMicrosoftManaged =
      policy.displayName.toLowerCase().includes("microsoft managed") || policy.templateId != null;
    if (isMicrosoftManaged && policy.state === "disabled") {
      return [
        {
          id: nextFindingId(),
          policyId: policy.id,
          policyName: policy.displayName,
          severity: "info",
          category: "Break-Glass",
          title: `Break-glass ${breakGlass.type} not excluded (disabled Microsoft managed policy)`,
          description:
            `The ${label} **${displayName}** is not excluded from this policy, but the policy is ` +
            `disabled and Microsoft managed. No risk while disabled.`,
          recommendation:
            `If you enable this policy, add the ${label} **${displayName}** to the exclusions first ` +
            `to prevent emergency access lockout.`,
        },
      ];
    }

    // Report-only — medium: will block break-glass once switched to enabled
    if (policy.state === "enabledForReportingButNotEnforced") {
      return [
        {
          id: nextFindingId(),
          policyId: policy.id,
          policyName: policy.displayName,
          severity: "medium",
          category: "Break-Glass",
          title: `Break-glass ${breakGlass.type} not excluded (report-only policy)`,
          description:
            `The ${label} **${displayName}** is not excluded from this policy. ` +
            `This policy is currently in report-only mode so there is no enforcement risk, ` +
            `but the ${label} should be added before switching to enabled.`,
          recommendation:
            `Add the ${label} **${displayName}** to the user/group exclusions before ` +
            `enabling enforcement on this policy.`,
        },
      ];
    }

    // Disabled non-managed — low: will block break-glass if enabled without adding exclusion
    if (policy.state === "disabled") {
      return [
        {
          id: nextFindingId(),
          policyId: policy.id,
          policyName: policy.displayName,
          severity: "low",
          category: "Break-Glass",
          title: `Break-glass ${breakGlass.type} not excluded (disabled policy)`,
          description:
            `The ${label} **${displayName}** is not excluded from this policy. ` +
            `This policy is currently disabled so there is no enforcement risk.`,
          recommendation:
            `Add the ${label} **${displayName}** to the exclusions before enabling this policy.`,
        },
      ];
    }

    return [
      {
        id: nextFindingId(),
        policyId: policy.id,
        policyName: policy.displayName,
        severity,
        category: "Break-Glass",
        title: `Break-glass ${breakGlass.type} NOT excluded ⚠`,
        description:
          `The ${label} **${displayName}** is NOT excluded from this enabled policy. ` +
          `If this policy causes a lockout (e.g. misconfigured MFA, compliance, or block rule), ` +
          `the ${label} will also be blocked and cannot be used for emergency access.`,
        recommendation:
          `Add the ${label} **${displayName}** to the ${breakGlass.type === "user" ? "excluded users" : "excluded groups"} ` +
          `for this policy to preserve emergency access.\n\n` +
          `**Steps:**\n` +
          `1. Edit this policy in the Entra admin center\n` +
          `2. Under Users → Exclude → ${breakGlass.type === "user" ? "Select excluded users" : "Select excluded groups"}\n` +
          `3. Add **${displayName}**\n` +
          `4. Save the policy`,
      },
    ];
  }
}

// ─── Tenant-Wide Gap Analysis ────────────────────────────────────────────────

function checkTenantWideGaps(context: TenantContext): Finding[] {
  const findings: Finding[] = [];
  const enabled = context.policies.filter((p) => p.state === "enabled");

  // Check if any policy requires MFA for all users
  const hasMfaForAll = enabled.some((p) => {
    const users = p.conditions.users;
    const grant = p.grantControls;
    return (
      users.includeUsers.includes("All") &&
      (grant?.builtInControls.includes("mfa") ||
        grant?.authenticationStrength != null)
    );
  });

  if (!hasMfaForAll) {
    findings.push({
      id: nextFindingId(),
      policyId: "tenant-wide",
      policyName: "Tenant-Wide Analysis",
      severity: "critical",
      category: "MFA Coverage",
      title: "No policy requires MFA for All Users",
      description:
        "No enabled policy was found that requires MFA (or authentication strength) for All Users. " +
        "This means there may be users who can authenticate without MFA.",
      recommendation:
        "Create a baseline policy requiring MFA for All Users and All Cloud Apps. " +
        "This is the foundation of the Swiss cheese model — MFA is the bare minimum.",
    });
  }

  // Check for legacy auth blocking
  const blocksLegacy = enabled.some((p) => {
    const types = p.conditions.clientAppTypes;
    const grant = p.grantControls;
    return (
      (types.includes("exchangeActiveSync") || types.includes("other")) &&
      grant?.builtInControls.includes("block")
    );
  });

  if (!blocksLegacy) {
    findings.push({
      id: nextFindingId(),
      policyId: "tenant-wide",
      policyName: "Tenant-Wide Analysis",
      severity: "critical",
      category: "Legacy Auth",
      title: "No policy blocks legacy authentication",
      description:
        "No enabled policy was found that blocks legacy authentication protocols. " +
        "Legacy auth cannot support MFA and is a top attack vector.",
      recommendation:
        "Create a policy that blocks Exchange ActiveSync and Other client types for All Users.",
    });
  }

  // ─── Comprehensive Break-Glass Account Review (Tenant-Wide Summary) ─────────
  // Uses the identifyBreakGlass() helper (same candidate used by per-policy checks)
  // to generate a tenant-wide summary showing total policy coverage.

  const primaryBreakGlass = identifyBreakGlass(context);

  // Count break-glass coverage across ALL policies (not just critical ones)
  const allPolicies = context.policies;
  const totalPolicyCount = allPolicies.length;
  const userTargetingPolicies = allPolicies.filter(p => {
    const u = p.conditions.users;
    return u.includeUsers.length > 0 || u.includeGroups.length > 0 || u.includeRoles.length > 0;
  });

  let policiesWithBreakGlass = 0;
  let policiesWithoutBreakGlass = 0;
  const withoutNames: string[] = [];
  const withNames: string[] = [];

  if (primaryBreakGlass) {
    for (const p of userTargetingPolicies) {
      const excluded =
        primaryBreakGlass.type === "user"
          ? p.conditions.users.excludeUsers.includes(primaryBreakGlass.id)
          : p.conditions.users.excludeGroups.includes(primaryBreakGlass.id);
      if (excluded) {
        policiesWithBreakGlass++;
        withNames.push(p.displayName);
      } else {
        policiesWithoutBreakGlass++;
        withoutNames.push(p.displayName);
      }
    }
  }

  if (primaryBreakGlass) {
    const breakGlassLabel = primaryBreakGlass.type === "user" ? "Break-glass account" : "Break-glass group";
    const bgDisplayName =
      primaryBreakGlass.type === "user"
        ? context.directoryObjects.get(primaryBreakGlass.id)?.displayName ?? `ID: ${primaryBreakGlass.id.substring(0, 8)}…`
        : context.directoryObjects.get(primaryBreakGlass.id)?.displayName ?? `ID: ${primaryBreakGlass.id.substring(0, 8)}…`;

    if (policiesWithoutBreakGlass > 0) {
      // Some policies missing break-glass
      const enabledWithout = withoutNames.filter(name => {
        const p = allPolicies.find(pol => pol.displayName === name);
        return p && p.state === "enabled";
      });
      const severity = enabledWithout.length > 0 ? "high" as const : "medium" as const;

      findings.push({
        id: nextFindingId(),
        policyId: "tenant-wide",
        policyName: "Tenant-Wide Analysis",
        severity,
        category: "Break-Glass",
        title: `${breakGlassLabel} coverage: ${policiesWithBreakGlass} of ${userTargetingPolicies.length} policies (${totalPolicyCount} total in tenant)`,
        description:
          `**${breakGlassLabel}:** ${bgDisplayName}\n\n` +
          `**Tenant overview:**\n` +
          `- **Total policies in tenant:** ${totalPolicyCount}\n` +
          `- **Policies targeting users:** ${userTargetingPolicies.length}\n` +
          `- **With break-glass excluded:** ${policiesWithBreakGlass} ✓\n` +
          `- **Without break-glass excluded:** ${policiesWithoutBreakGlass} ⚠\n\n` +
          `The ${breakGlassLabel.toLowerCase()} **${bgDisplayName}** was detected by analyzing exclusion patterns across your policies. ` +
          `${policiesWithoutBreakGlass} user-targeting policy(ies) do NOT exclude this ${breakGlassLabel.toLowerCase()}.\n\n` +
          `**Why this matters:**\n` +
          `Without break-glass exclusions, a misconfigured CA policy can lock out ALL administrators. ` +
          `Microsoft recommends excluding break-glass accounts from every Conditional Access policy to ensure emergency access.\n\n` +
          `**Policies WITHOUT break-glass exclusion:** ${withoutNames.slice(0, 10).join(", ")}` +
          (withoutNames.length > 10 ? ` and ${withoutNames.length - 10} more...` : ""),
        recommendation:
          `**Add break-glass exclusions to all policies:**\n\n` +
          `1. **Review all ${policiesWithoutBreakGlass} policies** listed above\n` +
          `2. Edit each policy → Users → Exclude → ${primaryBreakGlass.type === "user" ? "Select excluded users" : "Select excluded groups"}\n` +
          `3. Add **${bgDisplayName}**\n` +
          `4. Save each policy\n\n` +
          `**Best Practices:**\n` +
          `- Exclude break-glass from ALL CA policies, not just critical ones\n` +
          `- Use cloud-only accounts with 16+ char passwords stored in a physical safe\n` +
          `- No mailbox assigned (prevents phishing)\n` +
          `- Set up Azure Monitor alerts for ANY break-glass sign-in\n` +
          `- Test quarterly to verify emergency access still works\n\n` +
          `**Learn More:**\n` +
          `- [Manage emergency access accounts](https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access)`,
      });
    } else {
      // All policies have break-glass - positive finding
      findings.push({
        id: nextFindingId(),
        policyId: "tenant-wide",
        policyName: "Tenant-Wide Analysis",
        severity: "info",
        category: "Break-Glass",
        title: `${breakGlassLabel} excluded from all ${userTargetingPolicies.length} user-targeting policies ✓ (${totalPolicyCount} total in tenant)`,
        description:
          `**${breakGlassLabel}:** ${bgDisplayName}\n\n` +
          `**Tenant overview:**\n` +
          `- **Total policies in tenant:** ${totalPolicyCount}\n` +
          `- **Policies targeting users:** ${userTargetingPolicies.length}\n` +
          `- **With break-glass excluded:** ${policiesWithBreakGlass} ✓\n` +
          `- **Without break-glass excluded:** 0\n\n` +
          `The ${breakGlassLabel.toLowerCase()} **${bgDisplayName}** is correctly excluded from all user-targeting Conditional Access policies. ` +
          `This ensures emergency access is preserved across your entire tenant.\n\n` +
          `**Break-glass accounts** are cloud-only emergency access accounts with permanent Global Admin privileges that ` +
          `are excluded from all CA policies to prevent administrative lockout.`,
        recommendation:
          `**Ongoing Maintenance:**\n\n` +
          `1. **Verify this is your intended break-glass ${primaryBreakGlass.type}**: Confirm **${bgDisplayName}** is correct\n` +
          `2. **Monitor for sign-in activity**: Set up Azure Monitor alerts for ANY activity on this ${primaryBreakGlass.type}\n` +
          `3. **Test quarterly**: Verify emergency access works every 3 months\n` +
          `4. **Review new policies**: Ensure any new CA policies also exclude this ${primaryBreakGlass.type}\n` +
          `5. **Maintain 2 break-glass accounts**: If this is a single account, create a second for redundancy\n\n` +
          `**Learn More:**\n` +
          `- [Manage emergency access accounts](https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access)`,
      });
    }
  } else {
    // No break-glass candidate detected at all
    const criticalPolicies = enabled.filter(p => {
      const targetsAllUsers = p.conditions.users.includeUsers.includes("All");
      if (!targetsAllUsers) return false;
      const grant = p.grantControls;
      return grant?.builtInControls.includes("mfa") || grant?.authenticationStrength != null ||
             grant?.builtInControls.includes("block") || grant?.builtInControls.includes("compliantDevice");
    });

    const criticalList = criticalPolicies.slice(0, 10).map(p => "- " + p.displayName).join("\n");
    const criticalOverflow = criticalPolicies.length > 10 ? "\n...and " + (criticalPolicies.length - 10) + " more" : "";

    findings.push({
      id: nextFindingId(),
      policyId: "tenant-wide",
      policyName: "Tenant-Wide Analysis",
      severity: "critical",
      category: "Break-Glass",
      title: `No break-glass account or group detected across ${totalPolicyCount} policies`,
      description:
        `No consistent user or group exclusions were found across your ${totalPolicyCount} Conditional Access policies that would indicate ` +
        `a break-glass (emergency access) account or group.\n\n` +
        `**Tenant overview:**\n` +
        `- **Total policies in tenant:** ${totalPolicyCount}\n` +
        `- **Policies targeting users:** ${userTargetingPolicies.length}\n` +
        `- **Break-glass exclusions found:** 0 ❌\n\n` +
        `**Why this is critical:**\n` +
        `Without break-glass accounts excluded from CA policies, a misconfiguration can lock out ALL administrators, ` +
        `including Global Admins. Microsoft Support intervention may be required, causing extended downtime.\n\n` +
        `**Critical policies that need break-glass exclusions:**\n` +
        criticalList + criticalOverflow,
      recommendation:
        `**IMMEDIATE ACTION REQUIRED:**\n\n` +
        `1. **Create 2 break-glass accounts**: Cloud-only, Global Admin, 16+ char passwords, no mailbox\n` +
        `2. **Exclude from ALL ${totalPolicyCount} CA policies**: Edit each policy → Users → Exclude → Add both accounts\n` +
        `3. **Set up Azure Monitor alerts**: Alert on ANY break-glass sign-in\n` +
        `4. **Test quarterly**: Verify emergency access works\n\n` +
        `**Learn More:**\n` +
        `- [Manage emergency access accounts](https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access)\n` +
        `- [Plan for CA lockout prevention](https://learn.microsoft.com/entra/identity/conditional-access/howto-conditional-access-best-practices#break-glass-accounts)`,
    });
  }

  // Check for user-agent / platform spoofing coverage (MFASweep-style)
  const blocksUnknownPlatforms = enabled.some((p) => {
    const platforms = p.conditions.platforms;
    if (!platforms) return false;
    return (
      platforms.includePlatforms.includes("all") &&
      platforms.excludePlatforms.length > 0 &&
      p.grantControls?.builtInControls.includes("block")
    );
  });

  const mfaPoliciesUseSpecificPlatforms = enabled.some((p) => {
    const platforms = p.conditions.platforms;
    if (!platforms || platforms.includePlatforms.length === 0) return false;
    const requiresMfa =
      p.grantControls?.builtInControls.includes("mfa") ||
      p.grantControls?.authenticationStrength != null;
    return (
      requiresMfa &&
      !platforms.includePlatforms.includes("all") &&
      platforms.includePlatforms.length > 0
    );
  });

  if (mfaPoliciesUseSpecificPlatforms && !blocksUnknownPlatforms) {
    findings.push({
      id: nextFindingId(),
      policyId: "tenant-wide",
      policyName: "Tenant-Wide Analysis",
      severity: "high",
      category: "User-Agent Bypass",
      title: "MFA policies use platform-specific conditions without blocking unknown platforms",
      description:
        "One or more MFA policies target specific device platforms (e.g. iOS, Android, Windows) " +
        "instead of all platforms, AND no policy blocks unknown or unsupported device platforms. " +
        "This creates a gap exploitable by tools like MFASweep, which enumerate user-agent strings " +
        "to find platforms where MFA is not enforced. An attacker can spoof a Linux, ChromeOS, or " +
        "unrecognized user-agent to bypass MFA entirely.",
      recommendation:
        "Either change all MFA policies to target 'All platforms' (recommended), or create a " +
        "companion policy that blocks access from unknown/unsupported device platforms per CIS 5.3.11. " +
        "This closes the user-agent spoofing bypass path that MFASweep exploits.",
    });
  }

  // Check for guest/external user coverage gaps at the tenant level
  const guestExcludingPolicies = enabled.filter((p) => {
    const users = p.conditions.users;
    if (!users.includeUsers.includes("All")) return false;
    const excludesGuestsSimple = users.excludeUsers.includes("GuestsOrExternalUsers");
    const excludeGuestsObj = users.excludeGuestsOrExternalUsers as {
      guestOrExternalUserTypes?: string;
    } | null | undefined;
    return excludesGuestsSimple || excludeGuestsObj?.guestOrExternalUserTypes != null;
  });

  const hasGuestSpecificMfa = enabled.some((p) => {
    const users = p.conditions.users;
    const includesGuests =
      users.includeUsers.includes("GuestsOrExternalUsers") ||
      users.includeGuestsOrExternalUsers != null;
    const requiresMfa =
      p.grantControls?.builtInControls.includes("mfa") ||
      p.grantControls?.authenticationStrength != null;
    return includesGuests && requiresMfa;
  });

  if (guestExcludingPolicies.length > 0 && !hasGuestSpecificMfa && !hasMfaForAll) {
    findings.push({
      id: nextFindingId(),
      policyId: "tenant-wide",
      policyName: "Tenant-Wide Analysis",
      severity: "high",
      category: "Guest/External User Coverage",
      title: `${guestExcludingPolicies.length} policy(ies) exclude guests but no guest-specific MFA policy exists`,
      description:
        `${guestExcludingPolicies.length} enabled policy(ies) exclude guest/external users, and no dedicated ` +
        `policy was found requiring MFA specifically for guests. Guest accounts are a common lateral ` +
        `movement target — B2B collaboration accounts, external partners, and service providers should ` +
        `all be subject to at least MFA controls. Policies excluding guests: ` +
        `${guestExcludingPolicies.map((p) => p.displayName).join(", ")}.`,
      recommendation:
        "Create a dedicated CA policy requiring MFA for all guest/external users across all cloud apps. " +
        "Include session controls like sign-in frequency (e.g., 1 hour) for guests. " +
        "Consider requiring compliant devices or approved apps for guest access to sensitive resources.",
    });
  }

  // Check for privileged role exclusions across the tenant
  const critRoleIds = new Set([
    ADMIN_ROLE_IDS.globalAdmin.toLowerCase(),
    ADMIN_ROLE_IDS.privilegedRoleAdmin.toLowerCase(),
    ADMIN_ROLE_IDS.privilegedAuthAdmin.toLowerCase(),
    ADMIN_ROLE_IDS.conditionalAccessAdmin.toLowerCase(),
  ]);

  const policiesExcludingCritRoles = enabled.filter((p) => {
    return p.conditions.users.excludeRoles.some((r) => critRoleIds.has(r.toLowerCase()));
  });

  if (policiesExcludingCritRoles.length > 0) {
    const affectedNames = policiesExcludingCritRoles.map((p) => p.displayName);
    findings.push({
      id: nextFindingId(),
      policyId: "tenant-wide",
      policyName: "Tenant-Wide Analysis",
      severity: "critical",
      category: "Privileged Role Exclusion",
      title: `${policiesExcludingCritRoles.length} policy(ies) exclude critical admin roles (Global Admin, Privileged Role Admin, etc.)`,
      description:
        `${policiesExcludingCritRoles.length} enabled policy(ies) exclude one or more critical admin roles from ` +
        `their controls: ${affectedNames.join(", ")}. Global Administrators and Privileged Role Administrators ` +
        `are the highest-value targets for attackers. Excluding them from CA policies means these ` +
        `accounts have WEAKER protection than regular users — the opposite of Zero Trust principles. ` +
        `Break-glass access should use dedicated accounts excluded by user ID, not entire admin roles.`,
      recommendation:
        "Remove admin role exclusions from all CA policies. Instead: " +
        "1) Create 2 cloud-only break-glass accounts with complex passwords, " +
        "2) Exclude them by user ID (not role) from MFA policies, " +
        "3) Set up Azure Monitor alerts for any break-glass sign-in, " +
        "4) Ensure all admin roles are subject to phishing-resistant MFA (FIDO2 or certificate-based). " +
        "Per CIS 6.2.1 and Microsoft Zero Trust: admins should have equal or stricter controls.",
    });
  }

  // Check for Identity Protection / Risk-based Conditional Access
  const hasUserRiskPolicy = enabled.some((p) => {
    const conditions = p.conditions as any;
    return conditions.userRiskLevels && conditions.userRiskLevels.length > 0;
  });

  const hasSignInRiskPolicy = enabled.some((p) => {
    const conditions = p.conditions as any;
    return conditions.signInRiskLevels && conditions.signInRiskLevels.length > 0;
  });

  if (!hasUserRiskPolicy) {
    findings.push({
      id: nextFindingId(),
      policyId: "tenant-wide",
      policyName: "Tenant-Wide Analysis",
      severity: "high",
      category: "Identity Protection",
      title: "No policy enforces controls based on user risk level",
      description:
        `No enabled Conditional Access policy was found that uses **user risk levels** as a condition. ` +
        `Microsoft Entra ID Protection continuously evaluates user accounts for compromise indicators ` +
        `such as leaked credentials, anomalous behavior patterns, and threat intelligence signals.\n\n` +
        `**Without user risk policies:**\n` +
        `- Compromised accounts can operate undetected until manual discovery\n` +
        `- Attackers with stolen credentials gain persistent access\n` +
        `- No automated response to credential leaks or account takeovers\n` +
        `- You're not leveraging Microsoft's threat intelligence for proactive defense\n\n` +
        `User risk is calculated based on:\n` +
        `- Leaked credentials detected in dark web / paste sites\n` +
        `- Anomalous user activity patterns\n` +
        `- Impossible travel detection\n` +
        `- Anonymous IP usage from TOR/VPNs\n` +
        `- Malware-linked IP addresses\n\n` +
        `Microsoft recommends blocking high-risk users or requiring password change + MFA.`,
      recommendation:
        `**Action Required:**\n\n` +
        `1. **Enable Azure AD Premium P2** (required for Identity Protection)\n` +
        `2. **Create a user risk policy**:\n` +
        `   - Target: All users (exclude break-glass accounts)\n` +
        `   - Condition: User risk level = High\n` +
        `   - Grant: Require password change + MFA\n` +
        `   - Or: Block access for high-risk users\n\n` +
        `3. **Monitor User Risk Events**:\n` +
        `   - Review Entra Admin Center → Protection → Identity Protection → Risky Users\n` +
        `   - Investigate and remediate flagged accounts\n` +
        `   - Set up alerts for high-risk detections\n\n` +
        `4. **Start with report-only mode** to understand impact before enforcement\n\n` +
        `**Example policy configuration:**\n` +
        `- Users: All users (exclude 2 break-glass accounts)\n` +
        `- Conditions: User risk = High\n` +
        `- Grant: Require password change + Require MFA\n` +
        `- Session: Sign-in frequency = Every time\n\n` +
        `**Learn more:**\n` +
        `- [Identity Protection Overview](https://learn.microsoft.com/entra/id-protection/overview-identity-protection)\n` +
        `- [User Risk Policy](https://learn.microsoft.com/entra/id-protection/howto-identity-protection-configure-risk-policies#user-risk-policy)\n` +
        `- [Risk-based Conditional Access](https://learn.microsoft.com/entra/identity/conditional-access/howto-conditional-access-policy-risk-user)`,
    });
  }

  if (!hasSignInRiskPolicy) {
    findings.push({
      id: nextFindingId(),
      policyId: "tenant-wide",
      policyName: "Tenant-Wide Analysis",
      severity: "high",
      category: "Identity Protection",
      title: "No policy enforces controls based on sign-in risk level",
      description:
        `No enabled Conditional Access policy was found that uses **sign-in risk levels** as a condition. ` +
        `Microsoft Entra ID Protection analyzes each sign-in in real-time for risk indicators ` +
        `such as unfamiliar locations, anonymous IPs, malware-linked infrastructure, and atypical behavior.\n\n` +
        `**Without sign-in risk policies:**\n` +
        `- Attackers with valid credentials can sign in from anywhere without additional verification\n` +
        `- Credential stuffing attacks go undetected\n` +
        `- Sign-ins from TOR, VPNs, or known malicious IPs are allowed\n` +
        `- No automated response to suspicious sign-in patterns\n` +
        `- Adversary-in-the-middle (AiTM) phishing attacks may succeed\n\n` +
        `Sign-in risk is calculated in real-time based on:\n` +
        `- Anonymous IP addresses (TOR, proxy, VPN)\n` +
        `- Atypical travel patterns\n` +
        `- Malware-linked IP addresses\n` +
        `- Unfamiliar sign-in properties\n` +
        `- Password spray attacks\n` +
        `- Impossible travel\n` +
        `- Token anomalies\n\n` +
        `Microsoft recommends requiring MFA for medium/high-risk sign-ins or blocking high-risk sign-ins entirely.`,
      recommendation:
        `**Action Required:**\n\n` +
        `1. **Enable Azure AD Premium P2** (required for Identity Protection)\n` +
        `2. **Create a sign-in risk policy**:\n` +
        `   - Target: All users (exclude break-glass accounts)\n` +
        `   - Condition: Sign-in risk level = Medium and High\n` +
        `   - Grant: Require MFA (phishing-resistant recommended)\n\n` +
        `3. **Consider blocking high-risk sign-ins**:\n` +
        `   - Create a second policy for sign-in risk = High\n` +
        `   - Grant: Block access\n` +
        `   - This prevents account takeover attempts\n\n` +
        `4. **Monitor Sign-In Risk Events**:\n` +
        `   - Review Entra Admin Center → Protection → Identity Protection → Risky Sign-Ins\n` +
        `   - Investigate flagged sign-ins\n` +
        `   - Confirm legitimate users or dismiss false positives\n\n` +
        `5. **Start with report-only mode** to baseline risk detections\n\n` +
        `**Example policy configuration:**\n` +
        `Policy 1 - Require MFA for risky sign-ins:\n` +
        `- Users: All users (exclude break-glass)\n` +
        `- Conditions: Sign-in risk = Medium, High\n` +
        `- Grant: Require MFA\n\n` +
        `Policy 2 - Block high-risk sign-ins:\n` +
        `- Users: All users (exclude break-glass)\n` +
        `- Conditions: Sign-in risk = High\n` +
        `- Grant: Block access\n\n` +
        `**Learn more:**\n` +
        `- [Sign-in Risk Policy](https://learn.microsoft.com/entra/id-protection/howto-identity-protection-configure-risk-policies#sign-in-risk-policy)\n` +
        `- [Risk-based Conditional Access](https://learn.microsoft.com/entra/identity/conditional-access/howto-conditional-access-policy-risk)\n` +
        `- [Identity Protection Risk Events](https://learn.microsoft.com/entra/id-protection/concept-identity-protection-risks)`,
    });
  }

  // Check for high-value application coverage
  const HIGH_VALUE_APPS = {
    "797f4846-ba00-4fd7-ba43-dac1f8f63013": {
      name: "Azure Management",
      description: "Portal, ARM, PowerShell, CLI",
      risk: "critical",
    },
    "00000002-0000-0ff1-ce00-000000000000": {
      name: "Office 365 Exchange Online",
      description: "Email, calendar, contacts",
      risk: "high",
    },
    "00000003-0000-0ff1-ce00-000000000000": {
      name: "Office 365 SharePoint Online",
      description: "SharePoint, OneDrive",
      risk: "high",
    },
    "00000003-0000-0000-c000-000000000000": {
      name: "Microsoft Graph",
      description: "API access to M365 data",
      risk: "critical",
    },
    "c44b4083-3bb0-49c1-b47d-974e53cbdf3c": {
      name: "Azure Portal",
      description: "Web-based Azure management",
      risk: "critical",
    },
  };

  const unprotectedHighValueApps: Array<{ id: string; name: string; description: string; risk: string }> = [];

  for (const [appId, appInfo] of Object.entries(HIGH_VALUE_APPS)) {
    const isCovered = enabled.some((p) => {
      const apps = p.conditions.applications;
      const includesAll = apps.includeApplications.includes("All");
      const includesSpecific = apps.includeApplications.includes(appId);
      const isExcluded = apps.excludeApplications.includes(appId);
      const hasMfaOrBlock =
        p.grantControls?.builtInControls.includes("mfa") ||
        p.grantControls?.builtInControls.includes("block") ||
        p.grantControls?.authenticationStrength != null;

      return (includesAll || includesSpecific) && !isExcluded && hasMfaOrBlock;
    });

    if (!isCovered) {
      unprotectedHighValueApps.push({ id: appId, ...appInfo });
    }
  }

  if (unprotectedHighValueApps.length > 0) {
    const criticalApps = unprotectedHighValueApps.filter((a) => a.risk === "critical");
    const highApps = unprotectedHighValueApps.filter((a) => a.risk === "high");

    findings.push({
      id: nextFindingId(),
      policyId: "tenant-wide",
      policyName: "Tenant-Wide Analysis",
      severity: criticalApps.length > 0 ? "critical" : "high",
      category: "Application Coverage",
      title: `${unprotectedHighValueApps.length} high-value application(s) lack MFA/blocking policies${criticalApps.length > 0 ? ` (${criticalApps.length} critical)` : ""}`,
      description:
        `${unprotectedHighValueApps.length} high-value Microsoft application(s) do not have Conditional Access ` +
        `policies requiring MFA, authentication strength, or blocking access. These applications provide ` +
        `access to critical tenant resources and should have the strongest protection.\n\n` +
        `**Unprotected applications:**\n` +
        unprotectedHighValueApps
          .map(
            (app) =>
              `- **${app.name}** (${app.description}) - ${app.risk.toUpperCase()} RISK\n` +
              `  App ID: \`${app.id}\``
          )
          .join("\n") +
        `\n\n` +
        `**Risk by application:**\n` +
        `- **Azure Management / Azure Portal**: Full control over subscription resources, ability to create backdoors, exfiltrate data, deploy crypto miners\n` +
        `- **Microsoft Graph**: API access to all M365 data (mail, files, users, groups), can be used to escalate privileges\n` +
        `- **Exchange Online**: Access to corporate email, potential for business email compromise (BEC)\n` +
        `- **SharePoint/OneDrive**: Access to corporate documents, intellectual property theft risk\n\n` +
        `Without MFA/strong auth on these apps, a compromised password grants full access to your tenant's most sensitive resources.`,
      recommendation:
        `**Action Required:**\n\n` +
        `Create specific Conditional Access policies for high-value applications:\n\n` +
        `**For Azure Management / Azure Portal:**\n` +
        `1. Target: All users\n` +
        `2. Cloud apps: Select "Azure Management" (includes Portal, ARM, PowerShell, CLI)\n` +
        `3. Grant: Require phishing-resistant MFA (FIDO2 or certificate-based)\n` +
        `4. Session: Sign-in frequency = Every time (prevent token reuse)\n` +
        `5. Exclude: Break-glass accounts only\n\n` +
        `**For Office 365 (Exchange, SharePoint, Teams):**\n` +
        `1. Target: All users\n` +
        `2. Cloud apps: Select "Office 365"\n` +
        `3. Grant: Require MFA (standard or phishing-resistant)\n` +
        `4. Consider device compliance or approved client app requirements\n\n` +
        `**For Microsoft Graph API:**\n` +
        `1. Target: All users\n` +
        `2. Cloud apps: Select "Microsoft Graph"\n` +
        `3. Grant: Require MFA + compliant device\n` +
        `4. Session: Sign-in frequency = Every time\n\n` +
        `**Best practice:** Use "All cloud apps" policies for baseline MFA, then layer application-specific ` +
        `policies with stronger controls (phishing-resistant MFA, device compliance) for high-value resources.\n\n` +
        `**Learn more:**\n` +
        `- [Securing privileged access](https://learn.microsoft.com/entra/identity/role-based-access-control/security-planning)\n` +
        `- [Application-specific CA policies](https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-cloud-apps)\n` +
        `- [Phishing-resistant authentication](https://learn.microsoft.com/entra/identity/authentication/concept-authentication-strengths)`,
    });
  }

  // CA-Immune resources — single tenant-wide awareness finding
  const allAppsPolicies = context.policies.filter(
    (p) =>
      p.state !== "disabled" &&
      p.conditions.applications.includeApplications.includes("All")
  );
  if (allAppsPolicies.length > 0) {
    findings.push({
      id: nextFindingId(),
      policyId: "tenant-wide",
      policyName: "Tenant-Wide Analysis",
      severity: "info",
      category: "CA-Immune Resources",
      title: `6 Microsoft resources are always immune to Conditional Access`,
      description:
        `${allAppsPolicies.length} of your policies target "All cloud apps", but 6 Microsoft resources ` +
        `are always excluded from CA evaluation: Microsoft Intune Checkin, Windows Notification Service, ` +
        `Microsoft Mobile Application Management, Azure MFA Connector, OCaaS Client Interaction Service, ` +
        `and Authenticator App. These will show 'notApplied' in sign-in logs regardless of your policies.`,
      recommendation:
        "This is by-design and cannot be changed. Monitor sign-in logs for these resource IDs " +
        "as they can be used for password verification without triggering CA.",
    });
  }

  // Microsoft-managed CA policies awareness
  // Detect if tenant has policies matching known Microsoft-managed policy patterns
  const MANAGED_POLICY_PATTERNS = [
    { keyword: "block legacy authentication", category: "Legacy Auth Blocking" },
    { keyword: "block device code flow", category: "Device Code Flow" },
    { keyword: "multifactor authentication for admins", category: "Admin MFA" },
    { keyword: "multifactor authentication for all users", category: "MFA for All" },
    { keyword: "multifactor authentication for per-user", category: "Per-User MFA Migration" },
    { keyword: "reauthentication for risky sign-ins", category: "Risky Sign-In MFA" },
    { keyword: "block access for high-risk users", category: "High-Risk User Blocking" },
    { keyword: "block all high risk agents", category: "Agent Risk Blocking" },
  ];

  const managedPolicies = context.policies.filter((p) => {
    const name = p.displayName.toLowerCase();
    return MANAGED_POLICY_PATTERNS.some((pattern) =>
      name.includes(pattern.keyword)
    );
  });

  if (managedPolicies.length > 0) {
    const managedNames = managedPolicies.map((p) => p.displayName);
    const reportOnly = managedPolicies.filter(
      (p) => p.state === "enabledForReportingButNotEnforced"
    );
    const disabled = managedPolicies.filter((p) => p.state === "disabled");

    let detail =
      `Detected ${managedPolicies.length} Microsoft-managed Conditional Access policy(ies): ` +
      `${managedNames.join(", ")}. `;

    if (reportOnly.length > 0) {
      detail += `${reportOnly.length} are in report-only mode. `;
    }
    if (disabled.length > 0) {
      detail += `${disabled.length} are disabled. `;
    }

    detail +=
      "Microsoft-managed policies auto-adapt to tenant changes and cannot be renamed or deleted. " +
      "They may overlap with your custom policies — review for redundancy or conflicts. ";

    findings.push({
      id: nextFindingId(),
      policyId: "tenant-wide",
      policyName: "Tenant-Wide Analysis",
      severity: "info",
      category: "Microsoft-Managed Policies",
      title: `${managedPolicies.length} Microsoft-managed CA policy(ies) detected`,
      description: detail,
      recommendation:
        "Review Microsoft-managed policies alongside your custom policies for overlap. " +
        "Consider enabling managed policies that are in report-only mode for defense-in-depth. " +
        "You can exclude users from managed policies but cannot rename or delete them. " +
        "See: https://learn.microsoft.com/entra/identity/conditional-access/managed-policies",
    });
  }

  // ── Low-Privilege Scope Enforcement Change (March-June 2026) ──
  // Tenant-wide check: identify policies with resource exclusions that are
  // affected by Microsoft's enforcement change for low-privilege scopes.
  const policiesWithResourceExclusions = enabled.filter(p => {
    const apps = p.conditions.applications;
    return apps.includeApplications.includes("All") && apps.excludeApplications.length > 0;
  });

  if (policiesWithResourceExclusions.length > 0) {
    const policyNames = policiesWithResourceExclusions.map(p => p.displayName).join(", ");
    const totalExclusions = policiesWithResourceExclusions.reduce(
      (sum, p) => sum + p.conditions.applications.excludeApplications.length, 0
    );

    // Check if any policy explicitly targets Azure AD Graph (the new enforcement audience)
    const hasAzureADGraphPolicy = enabled.some(p => {
      const apps = p.conditions.applications;
      return apps.includeApplications.some(a => 
        a.toLowerCase() === "00000002-0000-0000-c000-000000000000"
      );
    });

    findings.push({
      id: nextFindingId(),
      policyId: "tenant-wide",
      policyName: "Tenant-Wide Analysis",
      severity: hasAzureADGraphPolicy ? "info" : "medium",
      category: "Low-Privilege Scope Enforcement",
      title: `${policiesWithResourceExclusions.length} "All resources" policy(ies) with exclusions — affected by March 2026 enforcement change`,
      description:
        `**${policiesWithResourceExclusions.length} enabled policy(ies) target "All resources" with a combined ` +
        `${totalExclusions} app exclusion(s):** ${policyNames}.\n\n` +
        `Microsoft is rolling out a behavioral change (March-June 2026) that affects these policies. Previously, ` +
        `low-privilege scopes (\`User.Read\`, \`openid\`, \`profile\`, \`email\`, \`offline_access\`, \`People.Read\`) ` +
        `were automatically exempt from CA enforcement when ANY resource was excluded. This created a bypass path ` +
        `where apps could read directory data without meeting policy controls.\n\n` +
        `**What's changing:**\n` +
        `These scopes are now mapped to **Azure AD Graph** (Windows Azure Active Directory, ` +
        `ID: 00000002-0000-0000-c000-000000000000) as the enforcement audience. ` +
        `Any "All resources" policy — even with exclusions — will enforce on these scopes.\n\n` +
        `**Confidential client impact:**\n` +
        `Confidential client apps (server-to-server) that were excluded from your policies and relied on ` +
        `low-privilege scopes had an even broader set of unprotected scopes:\n` +
        `- \`User.Read.All\`, \`User.ReadBasic.All\` — enumerate directory users\n` +
        `- \`People.Read.All\` — read organizational relationships\n` +
        `- \`GroupMember.Read.All\` — enumerate security group memberships\n` +
        `- \`Member.Read.Hidden\` — read hidden group memberships\n\n` +
        `These scopes will now also face CA enforcement, closing the directory enumeration bypass.` +
        (hasAzureADGraphPolicy
          ? `\n\n✅ **You have a policy explicitly targeting Azure AD Graph**, which provides coverage for the enforcement audience.`
          : `\n\n⚠️ **No policy explicitly targets Azure AD Graph.** If your "All resources" policies have exclusions ` +
            `but don't cover the Azure AD Graph resource, the enforcement change may cause unexpected CA challenges ` +
            `for apps that only request low-privilege scopes. Review and test before the rollout completes.`),
      recommendation:
        `**Recommended Actions:**\n\n` +
        `1. **Remove resource exclusions where possible**: Microsoft recommends "All resources" policies ` +
        `with NO exclusions as the baseline. Create separate, less-restrictive policies for apps that need exemptions.\n\n` +
        `2. **Test with report-only**: If you can't remove exclusions immediately, create a report-only policy ` +
        `targeting Azure AD Graph (00000002-0000-0000-c000-000000000000) with the same controls to preview impact.\n\n` +
        `3. **Review apps requesting only low-privilege scopes**:\n` +
        `   - Entra Admin Center → Entra ID → Monitoring & health → Usage & insights\n` +
        `   - Filter sign-in logs by resource "Windows Azure Active Directory"\n` +
        `   - Identify apps that may receive new CA challenges\n\n` +
        `4. **Update custom apps**: Applications only requesting \`openid\`, \`profile\`, \`User.Read\` ` +
        `that are not designed to handle CA claims challenges must be updated. See: ` +
        `[CA developer guidance](https://learn.microsoft.com/entra/identity-platform/v2-conditional-access-dev-guide)\n\n` +
        `5. **Consider explicit Azure AD Graph policy**: If you need granular control over directory scope enforcement, ` +
        `create a dedicated policy targeting the Azure AD Graph resource ` +
        `(see [Protect directory information](https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-cloud-apps#conditional-access-for-all-resources)).\n\n` +
        `**Learn More:**\n` +
        `- [Enforcement behavior change](https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-cloud-apps#new-conditional-access-behavior-when-an-all-resources-policy-has-a-resource-exclusion)\n` +
        `- [Legacy behavior reference](https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-cloud-apps#legacy-conditional-access-behavior-when-an-all-resources-policy-has-a-resource-exclusion)\n` +
        `- [Identify affected applications (PowerShell)](https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-cloud-apps#powershell)`,
    });
  }

  return findings;
}

// ─── Visualization Builder ───────────────────────────────────────────────────

function buildVisualization(
  policy: ConditionalAccessPolicy,
  context: TenantContext
): PolicyVisualization {
  const { users, applications, locations, platforms } = policy.conditions;

  // Users summary
  let targetUsers = "None";
  if (users.includeUsers.includes("All")) {
    const excCount = users.excludeUsers.length + users.excludeGroups.length + users.excludeRoles.length;
    targetUsers = excCount > 0 ? `All users (${excCount} exclusions)` : "All users";
  } else if (users.includeUsers.includes("GuestsOrExternalUsers")) {
    targetUsers = "Guests / External users";
  } else {
    const count = users.includeUsers.length + users.includeGroups.length + users.includeRoles.length;
    targetUsers = `${count} specific user/group/role targets`;
  }

  // Apps summary
  let targetApps = "None";
  if (applications.includeApplications.includes("All")) {
    const excCount = applications.excludeApplications.length;
    targetApps = excCount > 0 ? `All cloud apps (${excCount} exclusions)` : "All cloud apps";
  } else if (applications.includeUserActions.length > 0) {
    targetApps = `User actions: ${applications.includeUserActions.join(", ")}`;
  } else {
    const appNames = applications.includeApplications.map((id) => {
      const lower = id.toLowerCase();
      const known = WELL_KNOWN_APP_MAP.get(lower);
      if (known?.displayName) return known.displayName;
      const sp = context.servicePrincipals.get(lower);
      if (sp?.displayName) return sp.displayName;
      return id;
    });
    targetApps = appNames.join(", ");
  }

  // Conditions
  const conditions: string[] = [];
  if (locations && locations.includeLocations.length > 0) {
    const locNames = locations.includeLocations.map((id) => {
      if (id === "AllTrusted") return "All trusted locations";
      if (id === "All") return "All locations";
      const loc = context.namedLocations.find((l) => l.id === id);
      return loc ? loc.displayName : id;
    });
    conditions.push(`Locations: ${locNames.join(", ")}`);
    if (locations.excludeLocations.length > 0) {
      const exclNames = locations.excludeLocations.map((id) => {
        if (id === "AllTrusted") return "All trusted locations";
        if (id === "All") return "All locations";
        const loc = context.namedLocations.find((l) => l.id === id);
        return loc ? loc.displayName : id;
      });
      conditions.push(`Exclude locations: ${exclNames.join(", ")}`);
    }
  }
  if (platforms && platforms.includePlatforms.length > 0) {
    let platText = `Platforms: ${platforms.includePlatforms.join(", ")}`;
    if (platforms.excludePlatforms.length > 0) {
      platText += ` (exclude: ${platforms.excludePlatforms.join(", ")})`;
    }
    conditions.push(platText);
  }
  if (policy.conditions.userRiskLevels.length > 0) {
    conditions.push(`User risk: ${policy.conditions.userRiskLevels.join(", ")}`);
  }
  if (policy.conditions.signInRiskLevels.length > 0) {
    conditions.push(`Sign-in risk: ${policy.conditions.signInRiskLevels.join(", ")}`);
  }
  if (policy.conditions.clientAppTypes.length > 0) {
    conditions.push(`Client apps: ${policy.conditions.clientAppTypes.join(", ")}`);
  }
  if (policy.conditions.devices?.deviceFilter) {
    conditions.push(`Device filter: ${policy.conditions.devices.deviceFilter.rule}`);
  }

  // Grant controls
  const grantControls: string[] = [];
  if (policy.grantControls) {
    const g = policy.grantControls;
    if (g.builtInControls.includes("block")) {
      grantControls.push("🚫 Block access");
    } else {
      const controls = g.builtInControls.map((c) => {
        switch (c) {
          case "mfa": return "✅ Require MFA";
          case "compliantDevice": return "📱 Require compliant device";
          case "domainJoinedDevice": return "💻 Require hybrid Azure AD joined";
          case "approvedApplication": return "✅ Require approved app";
          case "compliantApplication": return "✅ Require app protection policy";
          case "passwordChange": return "🔑 Require password change";
          default: return c;
        }
      });
      if (g.authenticationStrength) {
        controls.push(`🛡️ Auth strength: ${g.authenticationStrength.displayName}`);
      }
      grantControls.push(`${controls.join(` ${g.operator} `)}`);
    }
  }

  // Session controls
  const sessionControls: string[] = [];
  if (policy.sessionControls) {
    const s = policy.sessionControls;
    if (s.signInFrequency?.isEnabled) {
      sessionControls.push(`Sign-in frequency: ${s.signInFrequency.value} ${s.signInFrequency.type}`);
    }
    if (s.persistentBrowser?.isEnabled) {
      sessionControls.push(`Persistent browser: ${s.persistentBrowser.mode}`);
    }
    if (s.cloudAppSecurity?.isEnabled) {
      sessionControls.push("Cloud App Security");
    }
    if (s.continuousAccessEvaluation) {
      sessionControls.push(`CAE: ${s.continuousAccessEvaluation.mode}`);
    }
    if (s.disableResilienceDefaults) {
      sessionControls.push("⚠️ Resilience defaults disabled");
    }
  }

  const stateMap: Record<string, string> = {
    enabled: "✅ Enabled",
    disabled: "⛔ Disabled",
    enabledForReportingButNotEnforced: "📊 Report-only",
  };

  return {
    targetUsers,
    targetApps,
    conditions,
    grantControls,
    sessionControls,
    state: stateMap[policy.state] ?? policy.state,
  };
}

// ─── Scoring ─────────────────────────────────────────────────────────────────

function buildSummary(context: TenantContext, findings: Finding[]): TenantSummary {
  return {
    totalPolicies: context.policies.length,
    enabledPolicies: context.policies.filter((p) => p.state === "enabled").length,
    reportOnlyPolicies: context.policies.filter(
      (p) => p.state === "enabledForReportingButNotEnforced"
    ).length,
    disabledPolicies: context.policies.filter((p) => p.state === "disabled").length,
    totalFindings: findings.length,
    criticalFindings: findings.filter((f) => f.severity === "critical").length,
    highFindings: findings.filter((f) => f.severity === "high").length,
    mediumFindings: findings.filter((f) => f.severity === "medium").length,
    lowFindings: findings.filter((f) => f.severity === "low").length,
    infoFindings: findings.filter((f) => f.severity === "info").length,
  };
}

function calculateScore(summary: TenantSummary): number {
  let score = 100;
  score -= summary.criticalFindings * 15;
  score -= summary.highFindings * 8;
  score -= summary.mediumFindings * 4;
  score -= summary.lowFindings * 1;
  return Math.max(0, Math.min(100, score));
}

// ─── Composite Scoring ──────────────────────────────────────────────────────
//
// Three-pillar model:
//   CIS Alignment    (50 pts) — weighted pass rate of CIS L1/L2 controls
//   Template Coverage (25 pts) — weighted best-practice template coverage
//   Config Quality    (25 pts) — finding-severity deductions with per-tier caps
//
// This ensures tenants that pass CIS checks and have matching policies always
// get credit, instead of the old model that only subtracted from 100.

export function calculateCompositeScore(
  analysis: AnalysisResult,
  cisResult: CISAlignmentResult,
  templateResult: TemplateAnalysisResult,
): CompositeScoreResult {
  // ── CIS Alignment (50 points max) ──
  // L1 (essential) controls carry 3× weight
  // L2 (defense-in-depth) controls carry 1× weight
  const CIS_MAX = 50;
  let cisWeightTotal = 0;
  let cisWeightEarned = 0;

  for (const cr of cisResult.controls) {
    const weight = cr.control.level === "L1" ? 3 : 1;
    if (cr.result.status === "not-applicable") continue;
    cisWeightTotal += weight;
    if (cr.result.status === "pass") {
      cisWeightEarned += weight;
    } else if (cr.result.status === "manual") {
      cisWeightEarned += weight * 0.5;
    }
  }

  const cisScore =
    cisWeightTotal > 0
      ? Math.round((cisWeightEarned / cisWeightTotal) * CIS_MAX)
      : 0;

  // ── Template Coverage (25 points max) ──
  // Uses the pre-computed priority-weighted coverage score
  const TEMPLATE_MAX = 25;
  const templateScore = Math.round((templateResult.coverageScore / 100) * TEMPLATE_MAX);

  // ── Configuration Quality (25 points max) ──
  // Deductions per severity, each capped to prevent a single tier
  // from consuming the entire budget
  const CONFIG_MAX = 25;
  const s = analysis.tenantSummary;

  const critPenalty = Math.min(s.criticalFindings * 5, 15);
  const highPenalty = Math.min(s.highFindings * 1.5, 10);
  const medPenalty = Math.min(s.mediumFindings * 0.5, 8);
  const lowPenalty = Math.min(s.lowFindings * 0.25, 3);
  const totalPenalty = Math.min(
    critPenalty + highPenalty + medPenalty + lowPenalty,
    CONFIG_MAX,
  );
  const configScore = Math.round(CONFIG_MAX - totalPenalty);

  const overall = Math.max(0, Math.min(100, cisScore + templateScore + configScore));

  const grade =
    overall >= 90
      ? "A"
      : overall >= 80
        ? "B"
        : overall >= 65
          ? "C"
          : overall >= 50
            ? "D"
            : "F";

  return {
    overall,
    cisScore,
    cisMax: CIS_MAX,
    templateScore,
    templateMax: TEMPLATE_MAX,
    configScore,
    configMax: CONFIG_MAX,
    grade,
  };
}
