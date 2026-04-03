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
      ...checkPrivilegedRoleExclusions(policy),
      ...checkGuestExternalUserExclusions(policy, context)
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
  policy: ConditionalAccessPolicy
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

  findings.push({
    id: nextFindingId(),
    policyId: policy.id,
    policyName: policy.displayName,
    severity,
    category: "Privileged Role Exclusion",
    title: `${excludedHighPriv.length} privileged role(s) excluded${hasCritical ? " — includes critical admin roles" : ""}`,
    description:
      attackScenario +
      ` Per Microsoft Zero Trust and CIS benchmarks, privileged roles should be the FIRST ` +
      `users subject to strong controls, not excluded from them. Break-glass accounts should ` +
      `be excluded by specific user ID, never by role.`,
    recommendation:
      `Remove ${allNames.join(", ")} from the excluded roles. ` +
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
  if (excludesGuestsSimple) {
    guestDescription = "all guest and external users";
  } else {
    const typeLabels = excludedGuestTypes
      .map((t) => GUEST_TYPE_LABELS[t] ?? t)
      .join(", ");
    guestDescription = typeLabels + (externalTenantScope ? ` from ${externalTenantScope}` : "");
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
        ? ` Excluded types: ${excludedGuestTypes.map((t) => GUEST_TYPE_LABELS[t] ?? t).join(", ")}.`
        : "") +
      (externalTenantScope
        ? ` Tenant scope: ${externalTenantScope}.`
        : ""),
    recommendation:
      hasGuestCoveragePolicy
        ? `A compensating policy was found, but verify it enforces equivalent controls for guest/external users. ` +
          `Ensure the guest policy covers the same apps and actions as this policy.`
        : `Create a dedicated CA policy for guest/external users with appropriate controls, or ` +
          `remove the guest exclusion from this policy. Per CIS and Microsoft Zero Trust guidance, ` +
          `guest accounts should be subject to at least MFA and ideally session time restrictions. ` +
          `If guests must be excluded from this specific policy, create a companion policy like ` +
          `"GLOBAL - GRANT - MFA - GuestsExternal" to ensure coverage.`,
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
