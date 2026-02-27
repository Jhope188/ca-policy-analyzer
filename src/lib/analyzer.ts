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
      ...checkCABypassApps(policy, context)
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
    checkPolicyExclusions(p)
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

// ─── Check: Resource Exclusion Bypass (Basic Scopes Leak) ────────────────────

function checkResourceExclusion(
  policy: ConditionalAccessPolicy,
  _context: TenantContext
): Finding[] {
  const apps = policy.conditions.applications;
  const includesAll = apps.includeApplications.includes("All");
  const hasExclusions = apps.excludeApplications.length > 0;

  if (!includesAll || !hasExclusions) return [];

  const scopeLeaks = RESOURCE_EXCLUSION_BYPASSES.map((b) =>
    `${b.resourceName}: ${b.bypassedScopes.join(", ")}`
  ).join(" • ");

  return [{
    id: nextFindingId(),
    policyId: policy.id,
    policyName: policy.displayName,
    severity: "high",
    category: "Resource Exclusion Bypass",
    title: `Excluding apps from "All cloud apps" leaks Graph & Azure AD scopes`,
    description:
      `This policy targets "All cloud apps" but has ${apps.excludeApplications.length} excluded app(s). ` +
      `When ANY resource is excluded, these scopes become unprotected — ${scopeLeaks}. ` +
      `This allows reading basic user profile data without the policy's controls.`,
    recommendation:
      "Avoid excluding resources from 'All cloud apps' policies. " +
      "Instead, create a separate less-restrictive policy for the apps that need exemption " +
      "while keeping the base policy without exclusions.",
    relatedIds: RESOURCE_EXCLUSION_BYPASSES.map((b) => b.resourceId),
  }];
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

  if (!requiresMfa && grant && grant.builtInControls.length > 0) {
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

  // Check for untrusted named locations
  for (const locId of locations.includeLocations) {
    const loc = context.namedLocations.find((l) => l.id === locId);
    if (loc && loc.isTrusted === false) {
      findings.push({
        id: nextFindingId(),
        policyId: policy.id,
        policyName: policy.displayName,
        severity: "low",
        category: "Location Configuration",
        title: `Named location "${loc.displayName}" is not marked as trusted`,
        description:
          `The named location "${loc.displayName}" used in this policy is not marked as trusted.`,
        recommendation: "Review whether this location should be marked as trusted.",
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

  // Check for break-glass protection
  const hasBreakGlass = enabled.some((p) => {
    return (
      p.conditions.users.excludeUsers.length > 0 &&
      p.conditions.users.includeUsers.includes("All")
    );
  });

  if (!hasBreakGlass) {
    findings.push({
      id: nextFindingId(),
      policyId: "tenant-wide",
      policyName: "Tenant-Wide Analysis",
      severity: "info",
      category: "Break-Glass",
      title: "No break-glass account exclusion detected",
      description:
        "No policies with All Users targeting have user exclusions that could be break-glass accounts. " +
        "While exclusions should be minimized, at least 2 break-glass accounts should be excluded from MFA policies.",
      recommendation:
        "Ensure you have 2 break-glass accounts excluded from ALL CA policies. " +
        "These should have complex passwords and be monitored for use.",
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
      const known = WELL_KNOWN_APP_MAP.get(id.toLowerCase());
      return known?.displayName ?? id;
    });
    targetApps = appNames.join(", ");
  }

  // Conditions
  const conditions: string[] = [];
  if (locations && locations.includeLocations.length > 0) {
    conditions.push(`Locations: ${locations.includeLocations.length} included`);
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
