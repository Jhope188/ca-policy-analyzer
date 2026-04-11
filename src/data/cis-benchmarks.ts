/**
 * CIS Microsoft 365 Foundations Benchmark — Conditional Access Controls
 *
 * Based on CIS Microsoft 365 Foundations Benchmark v6.0.0
 * Section 1.3: Session Timeout (idle session timeout CA policy)
 * Section 5.3: Conditional Access Policies
 * Section 5.4: Identity Protection & Device Controls
 *
 * v6.0 Changes from v4.0:
 *   - Section renumbered: 6.2/6.3 → 5.3/5.4
 *   - Sign-in risk and user risk promoted from L2 → L1
 *   - Added: Phishing-resistant MFA for admins (5.3.4)
 *   - Added: Token protection for sensitive apps (5.4.4)
 *   - Added: Continuous access evaluation not disabled (5.3.10)
 *   - Added: High-risk users/sign-ins blocking (5.4.1/5.4.2)
 *   - Added: App protection for mobile (5.4.5)
 *   - Added: Block unknown/unsupported platforms (5.3.11)
 *
 * Each control defines:
 *   - What to check in the tenant's CA policies
 *   - How to determine pass/fail
 *   - The CIS recommendation text
 */

import { ConditionalAccessPolicy, TenantContext, LicenseRequirement, isLicensed } from "@/lib/graph-client";

// ─── Types ───────────────────────────────────────────────────────────────────

export type CISLevel = "L1" | "L2";

export interface MSLearnReference {
  /** Short label for the link */
  label: string;
  /** Full MS Learn URL */
  url: string;
}

export interface Advisory {
  /** Advisory ID — M365 Message Center ID or custom */
  id: string;
  /** Short title */
  title: string;
  /** Plain-text summary of the impact */
  summary: string;
  /** Severity: info, warning, or critical */
  severity: "info" | "warning" | "critical";
  /** When the change takes effect (ISO date string or descriptive) */
  effectiveDate?: string;
  /** Link to full advisory details */
  url?: string;
}

export interface CISControl {
  /** CIS control ID, e.g. "5.3.1" */
  id: string;
  /** CIS section title */
  title: string;
  /** CIS level: L1 (essential) or L2 (defense-in-depth) */
  level: CISLevel;
  /** The CIS benchmark section */
  section: string;
  /** What this control requires */
  description: string;
  /** License required to evaluate this control (undefined = no special license needed) */
  licenseRequirement?: LicenseRequirement;
  /** Step-by-step policy creation guidance when the check fails */
  policyGuidance?: PolicyGuidance;
  /** MS Learn documentation references for this control */
  msLearnLinks?: MSLearnReference[];
  /** Active advisories from M365 Message Center / Roadmap that affect this control */
  advisories?: Advisory[];
  /** The check function — returns pass/fail + detail */
  check: (policies: ConditionalAccessPolicy[], context: TenantContext) => CISCheckResult;
}

export type CISStatus = "pass" | "fail" | "manual" | "not-applicable";

export interface NearMissPolicy {
  /** Policy display name */
  policyName: string;
  /** Current policy state */
  state: "enabled" | "enabledForReportingButNotEnforced" | "disabled";
  /** Criteria the policy satisfies */
  met: string[];
  /** Criteria the policy is missing — these need to be fixed */
  gaps: string[];
}

export interface CISCheckResult {
  status: CISStatus;
  /** Short result description */
  detail: string;
  /** Policies that satisfy (or partially satisfy) this control */
  matchingPolicies: string[];
  /** Remediation guidance if failed */
  remediation?: string;
  /** Policies that are close but need modifications to satisfy this control */
  nearMissPolicies?: NearMissPolicy[];
}

// ─── Policy Creation Guidance ────────────────────────────────────────────────

/**
 * Step-by-step guidance for creating a policy in the Entra admin center
 * that satisfies a CIS control. The suggestedName follows the IAC naming
 * convention from https://github.com/Jhope188/ConditionalAccessPolicies
 */
export interface PolicyGuidance {
  /** Recommended policy name following IAC naming convention */
  suggestedName: string;
  /** Ordered portal steps — each step maps to a tab / blade in the Entra admin center */
  portalSteps: PortalStep[];
  /** Prerequisite steps that must be completed before the CA policy (e.g. Intune config) */
  prerequisiteSteps?: PrerequisiteSection[];
  /** Sample JSON template for the CA policy */
  sampleJson?: object;
}

export interface PrerequisiteSection {
  /** Section title, e.g. "Part 1: Create Intune App Protection Policies" */
  title: string;
  /** Ordered steps within this prerequisite section */
  steps: PrerequisiteStep[];
}

export interface PrerequisiteStep {
  /** Step label */
  label: string;
  /** Detailed instructions for this step */
  instructions: string[];
}

export interface PortalStep {
  /** Tab / blade name in the Entra admin center */
  tab: string;
  /** What to configure in that tab */
  instructions: string[];
}

export interface CISAlignmentResult {
  controls: CISControlResult[];
  passCount: number;
  failCount: number;
  manualCount: number;
  notApplicableCount: number;
  totalControls: number;
  alignmentScore: number; // 0-100 percentage
  benchmarkVersion: string;
}

export interface CISControlResult {
  control: CISControl;
  result: CISCheckResult;
}

// ─── Helper Functions ────────────────────────────────────────────────────────

function getEnabled(policies: ConditionalAccessPolicy[]) {
  return policies.filter(
    (p) => p.state === "enabled" || p.state === "enabledForReportingButNotEnforced"
  );
}

function hasGrantControl(
  policy: ConditionalAccessPolicy,
  control: string
): boolean {
  return policy.grantControls?.builtInControls.includes(control) ?? false;
}

function targetsAllUsers(policy: ConditionalAccessPolicy): boolean {
  return policy.conditions.users.includeUsers.includes("All");
}

function targetsAllApps(policy: ConditionalAccessPolicy): boolean {
  return policy.conditions.applications.includeApplications.includes("All");
}

function hasAdminRoles(policy: ConditionalAccessPolicy): boolean {
  return policy.conditions.users.includeRoles.length > 0;
}

function hasAuthStrength(policy: ConditionalAccessPolicy): boolean {
  return policy.grantControls?.authenticationStrength != null;
}

function hasPhishingResistantAuthStrength(
  policy: ConditionalAccessPolicy
): boolean {
  const strength = policy.grantControls?.authenticationStrength;
  if (!strength) return false;
  const name = strength.displayName.toLowerCase();
  return (
    name.includes("phishing") ||
    name.includes("passwordless") ||
    name.includes("fido") ||
    name.includes("certificate")
  );
}

/**
 * Check if a policy uses the "Require risk remediation" grant control
 * (preview). This is a new builtInControls value that consolidates
 * password-based and passwordless user-risk remediation into one policy.
 * Only applies to user risk — not sign-in risk.
 * @see https://learn.microsoft.com/entra/id-protection/concept-identity-protection-policies#require-risk-remediation-with-microsoft-managed-remediation-preview
 */
function hasRiskRemediation(policy: ConditionalAccessPolicy): boolean {
  return policy.grantControls?.builtInControls.includes("riskRemediation") ?? false;
}

// ─── Near-Miss Detection ─────────────────────────────────────────────────────

/**
 * Generic near-miss detector — tests each policy individually against a CIS check
 * by pretending it is enabled. Catches disabled policies that would otherwise
 * satisfy the check, and report-only policies missed by cross-referencing checks.
 */
function detectNearMissPolicies(
  control: CISControl,
  context: TenantContext
): NearMissPolicy[] {
  const nearMisses: NearMissPolicy[] = [];

  for (const p of context.policies) {
    const enabledCopy: ConditionalAccessPolicy = { ...p, state: "enabled" };

    try {
      const testResult = control.check([enabledCopy], context);
      if (testResult.status === "pass" || testResult.matchingPolicies.length > 0) {
        const met: string[] = [];
        const gaps: string[] = [];

        if (p.state === "disabled") {
          met.push("Satisfies all check criteria");
          gaps.push("Policy is disabled — enable it or set to report-only");
        } else if (p.state === "enabledForReportingButNotEnforced") {
          met.push("Satisfies all check criteria");
          gaps.push("Policy is in report-only mode (not enforced)");
        } else {
          met.push("Partially satisfies check criteria");
          gaps.push("Review policy configuration — may need adjustments");
        }

        nearMisses.push({
          policyName: p.displayName,
          state: p.state as NearMissPolicy["state"],
          met,
          gaps,
        });
      }
    } catch {
      // Skip policies that cause errors in individual testing
    }
  }

  return nearMisses;
}

// ─── CIS Controls ────────────────────────────────────────────────────────────

export const CIS_CONTROLS: CISControl[] = [
  // ═══════════════════════════════════════════════════════════════════════
  // Section 5.3 — Conditional Access Policies
  // ═══════════════════════════════════════════════════════════════════════
  {
    id: "5.3.1",
    title: "Ensure multifactor authentication is required for all users",
    level: "L1",
    section: "5.3 - Conditional Access",
    description:
      'A CA policy must exist that targets "All users" and "All cloud apps" with MFA as a grant control ' +
      "(or authentication strength requiring MFA). The policy must be enabled or in report-only mode.",
    policyGuidance: {
      suggestedName: "YOURORG - GLOBAL - GRANT - MFA - AllUsers",
      portalSteps: [
        { tab: "Name", instructions: ["Enter policy name: YOURORG - GLOBAL - GRANT - MFA - AllUsers"] },
        { tab: "Users", instructions: ["Include → All users", "Exclude → select break-glass / emergency access accounts"] },
        { tab: "Target resources", instructions: ["Cloud apps → Include → All cloud apps"] },
        { tab: "Grant", instructions: ["Grant access → check Require multifactor authentication"] },
        { tab: "Enable policy", instructions: ["Set to Report-only first, then switch to On after validation"] },
      ],
    },
    msLearnLinks: [
      { label: "MS Learn: Require MFA for all users", url: "https://learn.microsoft.com/entra/identity/conditional-access/policy-all-users-mfa-strength" },
      { label: "MS Learn: Grant controls", url: "https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-grant" },
    ],
    advisories: [
      {
        id: "MC1223829",
        title: "Improved enforcement for policies with resource exclusions",
        summary: "Starting March 27 2026, CA policies targeting All resources will enforce even when resource exclusions exist. Custom apps requesting only OIDC scopes may now receive MFA/compliance challenges.",
        severity: "warning",
        effectiveDate: "2026-03-27",
        url: "https://deltapulse.app/dashboard?message=MC1223829",
      },
    ],
    check: (policies) => {
      const matching = getEnabled(policies).filter(
        (p) =>
          targetsAllUsers(p) &&
          targetsAllApps(p) &&
          (hasGrantControl(p, "mfa") || hasAuthStrength(p))
      );

      return {
        status: matching.length > 0 ? "pass" : "fail",
        detail:
          matching.length > 0
            ? `Found ${matching.length} policy(ies) requiring MFA for all users and all apps.`
            : "No enabled policy requires MFA for ALL users on ALL cloud apps.",
        matchingPolicies: matching.map((p) => p.displayName),
        remediation:
          'Create a CA policy targeting "All users" → "All cloud apps" with grant control "Require multifactor authentication" ' +
          "or authentication strength requiring MFA. Exclude only break-glass accounts.",
      };
    },
  },
  {
    id: "5.3.2",
    title: "Ensure multifactor authentication is required for administrative roles",
    level: "L1",
    section: "5.3 - Conditional Access",
    description:
      "A dedicated CA policy must require MFA specifically for admin directory roles. Even if an all-users MFA policy " +
      "exists, a separate admin policy provides defense-in-depth and can enforce stronger authentication.",
    policyGuidance: {
      suggestedName: "YOURORG - GLOBAL - GRANT - MFA - AllAdmins",
      portalSteps: [
        { tab: "Name", instructions: ["Enter policy name: YOURORG - GLOBAL - GRANT - MFA - AllAdmins"] },
        { tab: "Users", instructions: ["Include → Select Directory roles → choose Global Administrator, Exchange Administrator, Security Administrator, SharePoint Administrator, Conditional Access Administrator, Helpdesk Administrator, Billing Administrator, User Administrator, Authentication Administrator, Application Administrator, Cloud Application Administrator, Password Administrator, Privileged Authentication Administrator, Privileged Role Administrator", "Exclude → select break-glass / emergency access accounts"] },
        { tab: "Target resources", instructions: ["Cloud apps → Include → All cloud apps"] },
        { tab: "Grant", instructions: ["Grant access → check Require multifactor authentication (or select Require authentication strength → Multifactor authentication)"] },
        { tab: "Enable policy", instructions: ["Set to Report-only first, then switch to On after validation"] },
      ],
    },
    msLearnLinks: [
      { label: "MS Learn: Require MFA for admins", url: "https://learn.microsoft.com/entra/identity/conditional-access/policy-old-require-mfa-admin" },
      { label: "MS Learn: Authentication strengths", url: "https://learn.microsoft.com/entra/identity/authentication/concept-authentication-strengths" },
    ],
    check: (policies) => {
      const matching = getEnabled(policies).filter(
        (p) =>
          hasAdminRoles(p) &&
          (hasGrantControl(p, "mfa") || hasAuthStrength(p))
      );

      return {
        status: matching.length > 0 ? "pass" : "fail",
        detail:
          matching.length > 0
            ? `Found ${matching.length} policy(ies) requiring MFA for admin roles.`
            : "No dedicated policy requires MFA for administrative roles.",
        matchingPolicies: matching.map((p) => p.displayName),
        remediation:
          "Create a CA policy targeting admin directory roles (Global Admin, Exchange Admin, Security Admin, etc.) " +
          "with MFA or phishing-resistant authentication strength as the grant control.",
      };
    },
  },
  {
    id: "5.3.3",
    title: "Ensure multifactor authentication is required for guest and external users",
    level: "L1",
    section: "5.3 - Conditional Access",
    description:
      "A CA policy must require MFA for guest, B2B collaboration, and external users to prevent unauthorized access " +
      "through external identities.",
    policyGuidance: {
      suggestedName: "YOURORG - GLOBAL - GRANT - MFA - External-Guest-Users",
      portalSteps: [
        { tab: "Name", instructions: ["Enter policy name: YOURORG - GLOBAL - GRANT - MFA - External-Guest-Users"] },
        { tab: "Users", instructions: ["Include → Select Guest or external users → check all guest/external user types (B2B collaboration, B2B direct connect, local guest, service provider, other external)"] },
        { tab: "Target resources", instructions: ["Cloud apps → Include → All cloud apps"] },
        { tab: "Grant", instructions: ["Grant access → check Require multifactor authentication"] },
        { tab: "Enable policy", instructions: ["Set to Report-only first, then switch to On after validation"] },
      ],
    },
    msLearnLinks: [
      { label: "MS Learn: Block legacy authentication", url: "https://learn.microsoft.com/entra/identity/conditional-access/policy-block-legacy-authentication" },
      { label: "MS Learn: Microsoft-managed CA policies", url: "https://learn.microsoft.com/entra/identity/conditional-access/managed-policies" },
    ],
    advisories: [
      {
        id: "MC1243549",
        title: "SharePoint OTP retirement — all external users move to Entra B2B",
        summary: "SPO OTP authentication retires by Aug 31, 2026. After retirement all external users authenticate through Entra B2B and become fully subject to CA policies, Identity Protection, and guest governance. Ensure guest MFA policies are in place.",
        severity: "warning",
        effectiveDate: "2026-07-01",
        url: "https://deltapulse.app/dashboard?message=MC1243549",
      },
    ],
    check: (policies) => {
      const matching = getEnabled(policies).filter((p) => {
        const users = p.conditions.users;
        const targetsGuests =
          users.includeGuestsOrExternalUsers != null ||
          users.includeUsers.includes("GuestsOrExternalUsers");
        const requiresMfa =
          hasGrantControl(p, "mfa") || hasAuthStrength(p);
        return targetsGuests && requiresMfa;
      });

      // Also check if All Users MFA covers guests
      const allUsersMfa = getEnabled(policies).filter(
        (p) =>
          targetsAllUsers(p) &&
          targetsAllApps(p) &&
          (hasGrantControl(p, "mfa") || hasAuthStrength(p))
      );

      const total = [...matching, ...allUsersMfa];
      const names = [...new Set(total.map((p) => p.displayName))];

      return {
        status: names.length > 0 ? "pass" : "fail",
        detail:
          names.length > 0
            ? `${names.length} policy(ies) cover guest MFA (dedicated guest policy or all-users MFA).`
            : "No policy requires MFA for guest/external users.",
        matchingPolicies: names,
        remediation:
          "Create a CA policy targeting guest/external user types with MFA grant control using authentication strength, " +
          "or ensure your all-users MFA policy does not exclude guests.",
      };
    },
  },
  {
    id: "5.3.4",
    title: "Ensure phishing-resistant MFA strength is required for administrators",
    level: "L1",
    section: "5.3 - Conditional Access",
    description:
      "Administrative roles must be protected with phishing-resistant MFA (FIDO2, certificate-based, or Windows Hello). " +
      "Standard MFA (push notifications, OTP) is not sufficient for admin accounts due to MFA fatigue and social engineering risks.",
    policyGuidance: {
      suggestedName: "YOURORG - GLOBAL - GRANT - PhishingResistantMFA - AllAdmins",
      portalSteps: [
        { tab: "Name", instructions: ["Enter policy name: YOURORG - GLOBAL - GRANT - PhishingResistantMFA - AllAdmins"] },
        { tab: "Users", instructions: ["Include → Select Directory roles → choose Global Administrator, Exchange Administrator, Security Administrator, SharePoint Administrator, Conditional Access Administrator, Privileged Authentication Administrator, Privileged Role Administrator", "Exclude → select break-glass / emergency access accounts"] },
        { tab: "Target resources", instructions: ["Cloud apps → Include → All cloud apps"] },
        { tab: "Grant", instructions: ["Grant access → check Require authentication strength → select Phishing-resistant MFA (includes FIDO2, Certificate-based authentication, Windows Hello for Business)"] },
        { tab: "Enable policy", instructions: ["Set to Report-only first, then switch to On after validation"] },
      ],
    },
    msLearnLinks: [
      { label: "MS Learn: Require phishing-resistant MFA for admins", url: "https://learn.microsoft.com/entra/identity/conditional-access/policy-admin-phish-resistant-mfa" },
      { label: "MS Learn: Authentication strengths", url: "https://learn.microsoft.com/entra/identity/authentication/concept-authentication-strengths" },
    ],
    check: (policies) => {
      const matching = getEnabled(policies).filter(
        (p) => hasAdminRoles(p) && hasPhishingResistantAuthStrength(p)
      );

      // Also accept if any admin policy uses authentication strength (even non-phishing-resistant)
      const hasAnyAuthStrength = getEnabled(policies).filter(
        (p) => hasAdminRoles(p) && hasAuthStrength(p)
      );

      if (matching.length > 0) {
        return {
          status: "pass",
          detail: `Found ${matching.length} policy(ies) requiring phishing-resistant MFA for admin roles.`,
          matchingPolicies: matching.map((p) => p.displayName),
        };
      }

      if (hasAnyAuthStrength.length > 0) {
        return {
          status: "pass",
          detail:
            `Found ${hasAnyAuthStrength.length} admin policy(ies) using authentication strength, ` +
            "but verify it includes phishing-resistant methods (FIDO2, CBA, Windows Hello).",
          matchingPolicies: hasAnyAuthStrength.map((p) => p.displayName),
          remediation:
            'Upgrade the authentication strength to "Phishing-resistant MFA" to fully satisfy this control.',
        };
      }

      return {
        status: "fail",
        detail: "No policy enforces phishing-resistant authentication strength for admin roles.",
        matchingPolicies: [],
        remediation:
          "Create a CA policy targeting admin roles with authentication strength set to " +
          '"Phishing-resistant MFA" (includes FIDO2 security keys, certificate-based auth, and Windows Hello for Business).',
      };
    },
  },
  {
    id: "5.3.5",
    title: "Ensure MFA is required to register or join devices",
    level: "L1",
    section: "5.3 - Conditional Access",
    description:
      "A CA policy must require MFA for the user action 'Register or join devices' OR 'Register security information', " +
      "preventing unauthorized device registration.",
    policyGuidance: {
      suggestedName: "YOURORG - GLOBAL - GRANT - MFA - RegisterSecurityInfo",
      portalSteps: [
        { tab: "Name", instructions: ["Enter policy name: YOURORG - GLOBAL - GRANT - MFA - RegisterSecurityInfo"] },
        { tab: "Users", instructions: ["Include → All users", "Exclude → select break-glass / emergency access accounts"] },
        { tab: "Target resources", instructions: ["Select User actions → check Register security information"] },
        { tab: "Grant", instructions: ["Grant access → check Require multifactor authentication"] },
        { tab: "Enable policy", instructions: ["Set to Report-only first, then switch to On after validation"] },
      ],
    },
    msLearnLinks: [
      { label: "MS Learn: Sign-in risk-based CA policy", url: "https://learn.microsoft.com/entra/id-protection/howto-identity-protection-configure-risk-policies" },
      { label: "MS Learn: Conditions — sign-in risk", url: "https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-conditions#sign-in-risk" },
    ],
    check: (policies) => {
      const matching = getEnabled(policies).filter((p) => {
        const actions = p.conditions.applications.includeUserActions;
        return (
          (actions.includes("urn:user:registersecurityinfo") ||
            actions.includes("urn:user:registerdevice")) &&
          (hasGrantControl(p, "mfa") || hasAuthStrength(p))
        );
      });

      return {
        status: matching.length > 0 ? "pass" : "fail",
        detail:
          matching.length > 0
            ? `Found ${matching.length} policy(ies) requiring MFA for device/security registration.`
            : "No policy requires MFA for registering security info or joining devices.",
        matchingPolicies: matching.map((p) => p.displayName),
        remediation:
          'Create a CA policy targeting user action "Register or join devices" or "Register security information" ' +
          "with MFA grant control.",
      };
    },
  },
  {
    id: "5.3.6",
    title: "Ensure sign-in risk policy is configured",
    level: "L1",
    section: "5.3 - Conditional Access",
    licenseRequirement: "entraIdP2",
    description:
      "A risk-based CA policy must require MFA or block access for medium and high-risk sign-ins " +
      "detected by Identity Protection. Promoted from L2 to L1 in v6.0.",
    policyGuidance: {
      suggestedName: "YOURORG - P2 - GLOBAL - GRANT - SignInRisk-MediumHigh",
      portalSteps: [
        { tab: "Name", instructions: ["Enter policy name: YOURORG - P2 - GLOBAL - GRANT - SignInRisk-MediumHigh"] },
        { tab: "Users", instructions: ["Include → All users", "Exclude → select break-glass / emergency access accounts"] },
        { tab: "Target resources", instructions: ["Cloud apps → Include → All cloud apps"] },
        { tab: "Conditions", instructions: ["Sign-in risk → Configure Yes → check High and Medium"] },
        { tab: "Grant", instructions: ["Grant access → check Require multifactor authentication"] },
        { tab: "Enable policy", instructions: ["Set to Report-only first, then switch to On after validation", "Requires Entra ID P2 license"] },
      ],
    },
    msLearnLinks: [
      { label: "MS Learn: User risk-based CA policy", url: "https://learn.microsoft.com/entra/id-protection/howto-identity-protection-configure-risk-policies" },
      { label: "MS Learn: Require password change for high-risk users", url: "https://learn.microsoft.com/entra/identity/conditional-access/policy-risk-based-user" },
    ],
    advisories: [
      {
        id: "ID-PROTECTION-RISK-RETIREMENT",
        title: "Legacy ID Protection sign-in risk policies retiring October 2026",
        summary: "The legacy sign-in risk policy configured in Microsoft Entra ID Protection (formerly Identity Protection) is retiring on October 1, 2026. Migrate to Conditional Access sign-in risk policies for unified management, report-only mode, Graph API support, and backup authentication system compatibility.",
        severity: "warning",
        effectiveDate: "2026-10-01",
        url: "https://learn.microsoft.com/entra/id-protection/howto-identity-protection-configure-risk-policies#migrate-risk-policies-to-conditional-access",
      },
    ],
    check: (policies) => {
      const matching = getEnabled(policies).filter((p) => {
        const riskLevels = p.conditions.signInRiskLevels ?? [];
        return (
          riskLevels.length > 0 &&
          (hasGrantControl(p, "mfa") ||
            hasGrantControl(p, "block") ||
            hasAuthStrength(p))
        );
      });

      const coversHigh = matching.some((p) =>
        p.conditions.signInRiskLevels?.includes("high")
      );
      const coversMedium = matching.some((p) =>
        p.conditions.signInRiskLevels?.includes("medium")
      );

      let status: CISStatus = "fail";
      if (coversHigh && coversMedium) status = "pass";
      else if (coversHigh || coversMedium) status = "pass";

      return {
        status,
        detail:
          status === "pass"
            ? `Sign-in risk policies cover: ${coversHigh ? "High" : ""}${coversHigh && coversMedium ? " + " : ""}${coversMedium ? "Medium" : ""} risk levels.`
            : "No sign-in risk-based CA policy found. Requires Entra ID P2.",
        matchingPolicies: matching.map((p) => p.displayName),
        remediation:
          'Create CA policies targeting "All users" → "All cloud apps" with sign-in risk condition set to ' +
          '"High" and "Medium" with appropriate grant controls. Requires Entra ID P2 license.',
      };
    },
  },
  {
    id: "5.3.7",
    title: "Ensure user risk policy is configured",
    level: "L1",
    section: "5.3 - Conditional Access",
    licenseRequirement: "entraIdP2",
    description:
      "A risk-based CA policy must require password change and MFA (or Require Risk Remediation) for medium and high-risk users " +
      "detected by Identity Protection. Promoted from L2 to L1 in v6.0.",
    policyGuidance: {
      suggestedName: "YOURORG - P2 - GLOBAL - GRANT - UserRisk-MediumHigh",
      portalSteps: [
        { tab: "Name", instructions: ["Enter policy name: YOURORG - P2 - GLOBAL - GRANT - UserRisk-MediumHigh"] },
        { tab: "Users", instructions: ["Include → All users", "Exclude → select break-glass / emergency access accounts"] },
        { tab: "Target resources", instructions: ["Cloud apps → Include → All cloud apps"] },
        { tab: "Conditions", instructions: ["User risk → Configure Yes → check High and Medium"] },
        { tab: "Grant", instructions: ["Grant access → check Require multifactor authentication AND Require password change", "OR use the new Require risk remediation control (preview) — automatically applies auth strength + sign-in frequency every time"] },
        { tab: "Enable policy", instructions: ["Set to Report-only first, then switch to On after validation", "Requires Entra ID P2 license"] },
      ],
    },
    msLearnLinks: [
      { label: "MS Learn: Require password change for high-risk users", url: "https://learn.microsoft.com/entra/identity/conditional-access/policy-risk-based-user" },
      { label: "MS Learn: Require risk remediation (preview)", url: "https://learn.microsoft.com/entra/id-protection/concept-identity-protection-policies#require-risk-remediation-with-microsoft-managed-remediation-preview" },
      { label: "MS Learn: Configure risk policies", url: "https://learn.microsoft.com/entra/id-protection/howto-identity-protection-configure-risk-policies" },
    ],
    advisories: [
      {
        id: "ID-PROTECTION-RISK-RETIREMENT",
        title: "Legacy ID Protection user risk policies retiring October 2026",
        summary: "The legacy user risk policy configured in Microsoft Entra ID Protection is retiring on October 1, 2026. Migrate to Conditional Access user risk policies for unified management, report-only mode, Graph API support, granular access control, and backup authentication system compatibility.",
        severity: "warning",
        effectiveDate: "2026-10-01",
        url: "https://learn.microsoft.com/entra/id-protection/howto-identity-protection-configure-risk-policies#migrate-risk-policies-to-conditional-access",
      },
    ],
    check: (policies) => {
      const matching = getEnabled(policies).filter((p) => {
        const riskLevels = p.conditions.userRiskLevels ?? [];
        return (
          riskLevels.length > 0 &&
          (hasGrantControl(p, "passwordChange") ||
            hasGrantControl(p, "mfa") ||
            hasGrantControl(p, "block") ||
            hasRiskRemediation(p))
        );
      });

      const coversHigh = matching.some((p) =>
        p.conditions.userRiskLevels?.includes("high")
      );
      const coversMedium = matching.some((p) =>
        p.conditions.userRiskLevels?.includes("medium")
      );

      let status: CISStatus = "fail";
      if (coversHigh && coversMedium) status = "pass";
      else if (coversHigh || coversMedium) status = "pass";

      return {
        status,
        detail:
          status === "pass"
            ? `User risk policies cover: ${coversHigh ? "High" : ""}${coversHigh && coversMedium ? " + " : ""}${coversMedium ? "Medium" : ""} risk levels` +
              (matching.some((p) => hasRiskRemediation(p)) ? " (using Require Risk Remediation)." : ".")
            : "No user risk-based CA policy found. Requires Entra ID P2.",
        matchingPolicies: matching.map((p) => p.displayName),
        remediation:
          'Create a CA policy targeting "All users" → "All cloud apps" with user risk condition set to ' +
          '"High" and "Medium". Use either Require password change + MFA, or the new Require Risk Remediation ' +
            "control (preview) which handles both password and passwordless flows. Requires Entra ID P2.",
      };
    },
  },
  {
    id: "5.3.8",
    title: "Ensure access from non-allowed countries is blocked",
    level: "L1",
    section: "5.3 - Conditional Access",
    description:
      "A CA policy must block access from countries where the organization does not operate using named locations.",
    policyGuidance: {
      suggestedName: "YOURORG - GLOBAL - BLOCK - Countries-NotAllowed",
      portalSteps: [
        { tab: "Prerequisites", instructions: ["Navigate to Protection → Conditional Access → Named locations", "Create a new Countries location with your allowed countries (e.g., 'Allowed Countries')"] },
        { tab: "Name", instructions: ["Enter policy name: YOURORG - GLOBAL - BLOCK - Countries-NotAllowed"] },
        { tab: "Users", instructions: ["Include → All users", "Exclude → select break-glass / emergency access accounts"] },
        { tab: "Target resources", instructions: ["Cloud apps → Include → All cloud apps"] },
        { tab: "Conditions", instructions: ["Locations → Configure Yes → Include: Any location → Exclude: select your Allowed Countries named location"] },
        { tab: "Grant", instructions: ["Block access"] },
        { tab: "Enable policy", instructions: ["Set to Report-only first, then switch to On after validation"] },
      ],
    },
    msLearnLinks: [
      { label: "MS Learn: Named locations in Conditional Access", url: "https://learn.microsoft.com/entra/identity/conditional-access/concept-assignment-network" },
      { label: "MS Learn: Block access by location", url: "https://learn.microsoft.com/entra/identity/conditional-access/howto-conditional-access-policy-location" },
    ],
    check: (policies) => {
      const matching = getEnabled(policies).filter((p) => {
        const locs = p.conditions.locations;
        return (
          targetsAllUsers(p) &&
          targetsAllApps(p) &&
          hasGrantControl(p, "block") &&
          locs != null &&
          locs.includeLocations.length > 0
        );
      });

      // ── Near-miss detection for geo-blocking policies ──────────────
      // Catches policies that have block + location conditions but are
      // missing Cloud Apps or Users scope, or are disabled/report-only.
      const nearMissPolicies: NearMissPolicy[] = [];

      if (matching.length === 0) {
        for (const p of getEnabled(policies)) {
          const locs = p.conditions.locations;
          const hasBlock = hasGrantControl(p, "block");
          const hasLocations = locs != null && locs.includeLocations.length > 0;

          // Only consider policies that look like geo-blocking attempts
          if (!hasBlock || !hasLocations) continue;

          const met: string[] = [];
          const gaps: string[] = [];

          met.push("Grant control: Block access ✓");
          met.push("Location conditions configured ✓");

          if (targetsAllUsers(p)) {
            met.push("Targets: All users ✓");
          } else {
            gaps.push("Users not set to \"All users\" — geo-block may not cover all accounts");
          }

          if (targetsAllApps(p)) {
            met.push("Cloud apps: All cloud apps ✓");
          } else {
            gaps.push("Cloud apps not set to \"All cloud apps\" — geo-block does not protect any resources");
          }

          if (gaps.length > 0) {
            nearMissPolicies.push({
              policyName: p.displayName,
              state: p.state as NearMissPolicy["state"],
              met,
              gaps,
            });
          }
        }

        // Also check disabled/report-only policies that would fully pass
        for (const p of policies.filter(
          (pol) => pol.state === "disabled" || pol.state === "enabledForReportingButNotEnforced"
        )) {
          const locs = p.conditions.locations;
          if (
            targetsAllUsers(p) &&
            targetsAllApps(p) &&
            hasGrantControl(p, "block") &&
            locs != null &&
            locs.includeLocations.length > 0
          ) {
            nearMissPolicies.push({
              policyName: p.displayName,
              state: p.state as NearMissPolicy["state"],
              met: ["Satisfies all geo-blocking criteria"],
              gaps: [
                p.state === "disabled"
                  ? "Policy is disabled — enable it to enforce the geo-block"
                  : "Policy is in report-only mode — switch to On to enforce",
              ],
            });
          }
        }
      }

      return {
        status: matching.length > 0 ? "pass" : "fail",
        detail:
          matching.length > 0
            ? `Found ${matching.length} geo-blocking policy(ies).`
            : "No policy blocks access from non-allowed countries.",
        matchingPolicies: matching.map((p) => p.displayName),
        nearMissPolicies: nearMissPolicies.length > 0 ? nearMissPolicies : undefined,
        remediation:
          "Create a named location with allowed countries, then create a CA policy targeting All users → " +
            "All cloud apps → block access from all locations except the allowed country list.",
      };
    },
  },
  {
    id: "5.3.9",
    title: "Ensure legacy authentication is blocked",
    level: "L1",
    section: "5.3 - Conditional Access",
    description:
      "Legacy authentication protocols (IMAP, POP3, SMTP, Exchange ActiveSync) must be blocked " +
      "because they cannot enforce MFA and are a primary attack vector for password spray and credential stuffing.",
    policyGuidance: {
      suggestedName: "YOURORG - GLOBAL - BLOCK - LegacyAuthentication",
      portalSteps: [
        { tab: "Name", instructions: ["Enter policy name: YOURORG - GLOBAL - BLOCK - LegacyAuthentication"] },
        { tab: "Users", instructions: ["Include → All users", "Exclude → select break-glass / emergency access accounts"] },
        { tab: "Target resources", instructions: ["Cloud apps → Include → All cloud apps"] },
        { tab: "Conditions", instructions: ["Client apps → Configure Yes → check Exchange ActiveSync clients and Other clients", "Uncheck Browser and Mobile apps and desktop clients"] },
        { tab: "Grant", instructions: ["Block access"] },
        { tab: "Enable policy", instructions: ["Set to Report-only first, then switch to On after validation"] },
      ],
    },
    msLearnLinks: [
      { label: "MS Learn: Block legacy authentication", url: "https://learn.microsoft.com/entra/identity/conditional-access/policy-block-legacy-authentication" },
    ],
    check: (policies) => {
      const matching = getEnabled(policies).filter((p) => {
        const types = p.conditions.clientAppTypes;
        return (
          targetsAllUsers(p) &&
          (types.includes("exchangeActiveSync") || types.includes("other")) &&
          hasGrantControl(p, "block")
        );
      });

      return {
        status: matching.length > 0 ? "pass" : "fail",
        detail:
          matching.length > 0
            ? `Found ${matching.length} policy(ies) blocking legacy authentication.`
            : "No policy blocks legacy authentication protocols.",
        matchingPolicies: matching.map((p) => p.displayName),
        remediation:
          'Create a CA policy targeting "All users" → "All cloud apps" with client apps "Exchange ActiveSync clients" ' +
          'and "Other clients" and grant control "Block access".',
      };
    },
  },
  {
    id: "5.3.10",
    title: "Ensure continuous access evaluation is not disabled",
    level: "L1",
    section: "5.3 - Conditional Access",
    description:
      "Continuous access evaluation (CAE) enables real-time revocation of access tokens when security events occur. " +
      "No CA policy should explicitly disable CAE, as this creates a vulnerability window up to 1 hour after a " +
      "security event (user disabled, password change, location change).",
    policyGuidance: {
      suggestedName: "(No new policy needed — remove CAE disable from offending policies)",
      portalSteps: [
        { tab: "Identify", instructions: ["Open each failing policy listed above in Protection → Conditional Access → Policies"] },
        { tab: "Session", instructions: ["Click Session → find Customize continuous access evaluation → set to Do not disable (or remove the setting entirely)"] },
        { tab: "Save", instructions: ["Save the policy — CAE is enabled by default and should not be disabled"] },
      ],
    },
    msLearnLinks: [
      { label: "MS Learn: Continuous access evaluation", url: "https://learn.microsoft.com/entra/identity/conditional-access/concept-continuous-access-evaluation" },
      { label: "MS Learn: Session controls", url: "https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-session" },
    ],
    check: (policies) => {
      const disablingPolicies = getEnabled(policies).filter((p) => {
        const cae = p.sessionControls?.continuousAccessEvaluation;
        return cae && cae.mode === "disabled";
      });

      return {
        status: disablingPolicies.length === 0 ? "pass" : "fail",
        detail:
          disablingPolicies.length === 0
            ? "No policy disables continuous access evaluation. CAE is active."
            : `${disablingPolicies.length} policy(ies) explicitly disable CAE, reducing real-time security enforcement.`,
        matchingPolicies: disablingPolicies.map((p) => p.displayName),
        remediation:
          "Remove the CAE disable setting from all CA policies unless strict real-time evaluation is " +
          "causing specific documented issues. CAE should remain enabled for real-time token revocation.",
      };
    },
  },
  {
    id: "5.3.11",
    title: "Ensure unknown or unsupported device platforms are blocked",
    level: "L1",
    section: "5.3 - Conditional Access",
    description:
      "Users should be blocked from accessing resources when the device type is unknown or unsupported. " +
      "This prevents attackers from spoofing user-agent strings to bypass platform-specific controls.",
    policyGuidance: {
      suggestedName: "YOURORG - GLOBAL - BLOCK - UnsupportedDevicePlatforms",
      portalSteps: [
        { tab: "Name", instructions: ["Enter policy name: YOURORG - GLOBAL - BLOCK - UnsupportedDevicePlatforms"] },
        { tab: "Users", instructions: ["Include → All users", "Exclude → select break-glass / emergency access accounts"] },
        { tab: "Target resources", instructions: ["Cloud apps → Include → All cloud apps"] },
        { tab: "Conditions", instructions: ["Device platforms → Configure Yes → Include: Select All platforms → Exclude: check Android, iOS, Windows, macOS (leave Linux and other unchecked)"] },
        { tab: "Grant", instructions: ["Block access"] },
        { tab: "Enable policy", instructions: ["Set to Report-only first, review sign-in logs for unexpected blocks, then switch to On"] },
      ],
    },
    msLearnLinks: [
      { label: "MS Learn: Block unknown device platforms", url: "https://learn.microsoft.com/entra/identity/conditional-access/policy-all-users-device-unknown-unsupported" },
      { label: "MS Learn: Conditions — device platforms", url: "https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-conditions#device-platforms" },
    ],
    check: (policies) => {
      const isBlockUnsupported = (p: ConditionalAccessPolicy) => {
        const platforms = p.conditions.platforms;
        if (!platforms) return false;
        const targetsUnknown =
          platforms.includePlatforms.includes("all") &&
          platforms.excludePlatforms.length > 0 &&
          hasGrantControl(p, "block");
        const explicitBlock =
          platforms.includePlatforms.some((plat) =>
            ["unknownFutureValue", "linux"].includes(plat)
          ) && hasGrantControl(p, "block");
        return targetsUnknown || explicitBlock;
      };

      const enabled = getEnabled(policies).filter(isBlockUnsupported);
      const disabled = policies
        .filter((p) => p.state === "disabled")
        .filter(isBlockUnsupported);

      if (enabled.length > 0) {
        return {
          status: "pass",
          detail: `Found ${enabled.length} enabled policy(ies) blocking unknown/unsupported device platforms.`,
          matchingPolicies: enabled.map((p) => p.displayName),
        };
      }

      if (disabled.length > 0) {
        return {
          status: "manual",
          detail:
            `Found ${disabled.length} matching policy(ies) but currently disabled: ` +
            disabled.map((p) => p.displayName).join(", ") +
            ". Enable the policy to pass this control.",
          matchingPolicies: disabled.map((p) => p.displayName),
          remediation:
            "A policy that blocks unsupported device platforms exists but is disabled. " +
            "Review and enable it to satisfy this CIS control.",
        };
      }

      return {
        status: "fail",
        detail: "No policy blocks unknown or unsupported device platforms.",
        matchingPolicies: [],
        remediation:
          "Create a CA policy that blocks access from unsupported device platforms. Target all platforms, " +
          "exclude known platforms (Windows, macOS, iOS, Android), and set grant control to Block.",
      };
    },
  },
  {
    id: "5.3.12",
    title: "Ensure device code flow is blocked",
    level: "L1",
    section: "5.3 - Conditional Access",
    description:
      "Device code flow should be blocked to prevent device code phishing attacks where attackers trick users " +
      "into authenticating on their behalf. Exclude Teams Rooms / phone resource accounts if needed.",
    policyGuidance: {
      suggestedName: "YOURORG - GLOBAL - BLOCK - DeviceCodeAuthFlow",
      portalSteps: [
        { tab: "Name", instructions: ["Enter policy name: YOURORG - GLOBAL - BLOCK - DeviceCodeAuthFlow"] },
        { tab: "Users", instructions: ["Include → All users", "Exclude → break-glass accounts and Teams Rooms / phone resource accounts"] },
        { tab: "Target resources", instructions: ["Cloud apps → Include → All cloud apps"] },
        { tab: "Conditions", instructions: ["Authentication flows → Configure Yes → check 'Device code flow'"] },
        { tab: "Grant", instructions: ["Block access"] },
        { tab: "Enable policy", instructions: ["Set to Report-only first, verify Teams Rooms / phone devices still function, then switch to On"] },
      ],
    },
    msLearnLinks: [
      { label: "MS Learn: Require compliant or hybrid joined device for admins", url: "https://learn.microsoft.com/entra/identity/conditional-access/policy-alt-admin-device-compliand-hybrid" },
      { label: "MS Learn: Grant controls", url: "https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-grant" },
    ],
    check: (policies) => {
      const matching = getEnabled(policies).filter((p) => {
        const authFlows = (p.conditions as Record<string, unknown>)
          .authenticationFlows as
          | { transferMethods?: string }
          | null
          | undefined;
        return (
          targetsAllUsers(p) &&
          hasGrantControl(p, "block") &&
          authFlows?.transferMethods != null
        );
      });

      return {
        status: matching.length > 0 ? "pass" : "fail",
        detail:
          matching.length > 0
            ? `Found ${matching.length} policy(ies) blocking device code / auth transfer flows.`
            : "No policy blocks device code authentication flow.",
        matchingPolicies: matching.map((p) => p.displayName),
        remediation:
          'Create a CA policy targeting "All users" → "All cloud apps" with authentication flow condition ' +
          '"Device code flow" and grant control "Block access". Exclude Teams device resource accounts if needed.',
      };
    },
  },
  {
    id: "5.3.13",
    title: "Ensure sign-in frequency for admin portals is limited",
    level: "L2",
    section: "5.3 - Conditional Access",
    description:
      "Admin sessions should have a limited sign-in frequency (e.g., 4 hours or less) to reduce the window " +
      "of opportunity if an admin session token is compromised.",
    policyGuidance: {
      suggestedName: "YOURORG - APP - SESSION - AdminPortal-SIF(4Hours)",
      portalSteps: [
        { tab: "Name", instructions: ["Enter policy name: YOURORG - APP - SESSION - AdminPortal-SIF(4Hours)"] },
        { tab: "Users", instructions: ["Include → Directory roles → select all privileged admin roles (Global Administrator, Security Administrator, Exchange Administrator, SharePoint Administrator, etc.)"] },
        { tab: "Target resources", instructions: ["Cloud apps → Include → Select apps → Microsoft Admin Portals (includes Azure portal, Microsoft 365 admin center, Exchange admin center, etc.)"] },
        { tab: "Session", instructions: ["Sign-in frequency → set to 4 hours", "Persistent browser session → optionally set to 'Never persistent'"] },
        { tab: "Enable policy", instructions: ["Set to Report-only first, confirm admin workflows are not disrupted, then switch to On"] },
      ],
    },
    msLearnLinks: [
      { label: "MS Learn: Sign-in frequency", url: "https://learn.microsoft.com/entra/identity/conditional-access/concept-session-lifetime#user-sign-in-frequency" },
      { label: "MS Learn: Session controls", url: "https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-session" },
    ],
    check: (policies) => {
      const matching = getEnabled(policies).filter((p) => {
        return (
          hasAdminRoles(p) &&
          p.sessionControls?.signInFrequency?.isEnabled === true
        );
      });

      return {
        status: matching.length > 0 ? "pass" : "fail",
        detail:
          matching.length > 0
            ? `Found ${matching.length} policy(ies) limiting admin sign-in frequency.`
            : "No policy limits sign-in frequency for admin roles.",
        matchingPolicies: matching.map((p) => p.displayName),
        remediation:
          "Create a CA policy targeting admin roles (or Microsoft Admin Portals) with session control " +
          "sign-in frequency set to 4 hours or less.",
      };
    },
  },

  // ═══════════════════════════════════════════════════════════════════════
  // Section 5.4 — Identity Protection & Device Controls
  // ═══════════════════════════════════════════════════════════════════════
  {
    id: "5.4.1",
    title: "Ensure high-risk users are blocked",
    level: "L1",
    section: "5.4 - Identity Protection",
    licenseRequirement: "entraIdP2",
    description:
      "A CA policy should block access or require risk remediation for users with high user risk level. This ensures compromised accounts " +
      "are immediately locked out or forced through self-service remediation.",
    policyGuidance: {
      suggestedName: "YOURORG - P2 - GLOBAL - BLOCK - HighRiskUsers",
      portalSteps: [
        { tab: "Name", instructions: ["Enter policy name: YOURORG - P2 - GLOBAL - BLOCK - HighRiskUsers"] },
        { tab: "Users", instructions: ["Include → All users", "Exclude → break-glass / emergency access accounts"] },
        { tab: "Target resources", instructions: ["Cloud apps → Include → All cloud apps"] },
        { tab: "Conditions", instructions: ["User risk → Configure Yes → select 'High'"] },
        { tab: "Grant", instructions: ["Block access, OR Grant access → Require password change + MFA, OR Grant access → Require risk remediation (preview)"] },
        { tab: "Enable policy", instructions: ["Set to Report-only first, review Identity Protection risk reports, then switch to On"] },
      ],
    },
    msLearnLinks: [
      { label: "MS Learn: Block access for high-risk sign-ins", url: "https://learn.microsoft.com/entra/identity/conditional-access/policy-risk-based-sign-in" },
      { label: "MS Learn: ID Protection — risk policies", url: "https://learn.microsoft.com/entra/id-protection/howto-identity-protection-configure-risk-policies" },
    ],
    check: (policies) => {
      const matching = getEnabled(policies).filter((p) => {
        const riskLevels = p.conditions.userRiskLevels ?? [];
        return (
          riskLevels.includes("high") &&
          (hasGrantControl(p, "block") ||
            hasGrantControl(p, "passwordChange") ||
            hasRiskRemediation(p))
        );
      });

      return {
        status: matching.length > 0 ? "pass" : "fail",
        detail:
          matching.length > 0
            ? `Found ${matching.length} policy(ies) blocking or requiring remediation for high-risk users` +
              (matching.some((p) => hasRiskRemediation(p)) ? " (using Require Risk Remediation)." : ".")
            : "No policy blocks or forces remediation for high-risk users.",
        matchingPolicies: matching.map((p) => p.displayName),
        remediation:
          'Create a CA policy targeting "All users" with user risk condition set to "High" and ' +
          'grant control "Block access", "Require password change + MFA", or "Require risk remediation" (preview). Requires Entra ID P2.',
      };
    },
  },
  {
    id: "5.4.2",
    title: "Ensure high-risk sign-ins are blocked",
    level: "L1",
    section: "5.4 - Identity Protection",
    licenseRequirement: "entraIdP2",
    description:
      "A CA policy should block access for sign-ins with high risk level. High-risk sign-ins indicate " +
      "strong likelihood of compromised credentials or anomalous behavior.",
    policyGuidance: {
      suggestedName: "YOURORG - P2 - GLOBAL - BLOCK - HighRiskSignIns",
      portalSteps: [
        { tab: "Name", instructions: ["Enter policy name: YOURORG - P2 - GLOBAL - BLOCK - HighRiskSignIns"] },
        { tab: "Users", instructions: ["Include → All users", "Exclude → break-glass / emergency access accounts"] },
        { tab: "Target resources", instructions: ["Cloud apps → Include → All cloud apps"] },
        { tab: "Conditions", instructions: ["Sign-in risk → Configure Yes → select 'High'"] },
        { tab: "Grant", instructions: ["Block access (or Grant access → Require multifactor authentication)"] },
        { tab: "Enable policy", instructions: ["Set to Report-only first, review Identity Protection risk reports, then switch to On"] },
      ],
    },
    msLearnLinks: [
      { label: "MS Learn: Block access for high-risk users", url: "https://learn.microsoft.com/entra/identity/conditional-access/policy-risk-based-user" },
      { label: "MS Learn: ID Protection — risk policies", url: "https://learn.microsoft.com/entra/id-protection/howto-identity-protection-configure-risk-policies" },
    ],
    check: (policies) => {
      const matching = getEnabled(policies).filter((p) => {
        const riskLevels = p.conditions.signInRiskLevels ?? [];
        return (
          riskLevels.includes("high") &&
          (hasGrantControl(p, "block") || hasGrantControl(p, "mfa") || hasAuthStrength(p))
        );
      });

      return {
        status: matching.length > 0 ? "pass" : "fail",
        detail:
          matching.length > 0
            ? `Found ${matching.length} policy(ies) addressing high-risk sign-ins.`
            : "No policy addresses high-risk sign-ins.",
        matchingPolicies: matching.map((p) => p.displayName),
        remediation:
          'Create a CA policy targeting "All users" with sign-in risk condition set to "High" and ' +
          'grant control "Block access" or "Require MFA". Requires Entra ID P2.',
      };
    },
  },
  {
    id: "5.4.3",
    title: "Ensure compliant device requirement is configured",
    level: "L2",
    section: "5.4 - Device Compliance",
    licenseRequirement: "intunePlan1",
    description:
      "A CA policy should require device compliance for accessing corporate resources, ensuring only healthy " +
      "managed devices enrolled in Intune can connect.",
    policyGuidance: {
      suggestedName: "YOURORG - INTUNE - GRANT - RequireCompliantDevice",
      portalSteps: [
        { tab: "Name", instructions: ["Enter policy name: YOURORG - INTUNE - GRANT - RequireCompliantDevice"] },
        { tab: "Users", instructions: ["Include → All users", "Exclude → break-glass accounts, guest users, and service accounts that don't use devices"] },
        { tab: "Target resources", instructions: ["Cloud apps → Include → All cloud apps (or select specific apps like Office 365)"] },
        { tab: "Conditions", instructions: ["Device platforms → Configure Yes → Include: Windows, macOS, iOS, Android (select platforms managed by Intune)"] },
        { tab: "Grant", instructions: ["Grant access → Require device to be marked as compliant"] },
        { tab: "Enable policy", instructions: ["Set to Report-only first — ensure Intune compliance policies are configured and devices have time to enroll, then switch to On"] },
      ],
    },
    msLearnLinks: [
      { label: "MS Learn: Require compliant device", url: "https://learn.microsoft.com/entra/identity/conditional-access/policy-all-users-device-compliance" },
      { label: "MS Learn: Intune device compliance", url: "https://learn.microsoft.com/mem/intune/protect/device-compliance-get-started" },
      { label: "MS Learn: Grant controls", url: "https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-grant#require-device-to-be-marked-as-compliant" },
    ],
    check: (policies) => {
      const matching = getEnabled(policies).filter((p) =>
        hasGrantControl(p, "compliantDevice")
      );

      if (matching.length > 0) {
        return {
          status: "pass",
          detail: `Found ${matching.length} policy(ies) requiring compliant devices.`,
          matchingPolicies: matching.map((p) => p.displayName),
        };
      }

      // Near-miss: find policies with related device grant controls
      const nearMissPolicies: NearMissPolicy[] = [];
      for (const p of policies) {
        const met: string[] = [];
        const gaps: string[] = [];

        const isActive = p.state === "enabled" || p.state === "enabledForReportingButNotEnforced";
        const hasCompliant = hasGrantControl(p, "compliantDevice");
        const hasDomainJoined = hasGrantControl(p, "domainJoinedDevice");

        if (!hasCompliant && !hasDomainJoined) continue;

        if (isActive) met.push("Policy is " + (p.state === "enabledForReportingButNotEnforced" ? "report-only" : "enabled"));
        else gaps.push("Policy is disabled — enable it or set to report-only");

        if (hasCompliant) met.push("Has 'Require compliant device' grant control");
        else gaps.push("Missing 'Require compliant device' grant control");

        if (hasDomainJoined && !hasCompliant) {
          met.push("Has 'Require Hybrid Azure AD joined device'");
          gaps.push("Hybrid join alone does not satisfy CIS — add 'Require device to be marked as compliant'");
        }

        if (gaps.length > 0) {
          nearMissPolicies.push({
            policyName: p.displayName,
            state: p.state as NearMissPolicy["state"],
            met,
            gaps,
          });
        }
      }

      return {
        status: "fail",
        detail: "No policy requires device compliance.",
        matchingPolicies: [],
        nearMissPolicies: nearMissPolicies.length > 0 ? nearMissPolicies : undefined,
        remediation:
          'Create a CA policy with grant control "Require device to be marked as compliant". ' +
          "This requires Intune enrollment and device compliance policies.",
      };
    },
  },
  {
    id: "5.4.4",
    title: "Ensure token protection is configured for sensitive applications",
    level: "L2",
    section: "5.4 - Token Security",
    description:
      "Token protection (token binding) should be configured for Exchange Online, SharePoint Online, and Teams " +
      "to prevent token replay attacks. Only supported on Windows 10+ with supported applications.",
    policyGuidance: {
      suggestedName: "YOURORG - APP - SESSION - Windows - TokenProtection",
      portalSteps: [
        { tab: "Name", instructions: ["Enter policy name: YOURORG - APP - SESSION - Windows - TokenProtection"] },
        { tab: "Users", instructions: ["Include → All users", "Exclude → break-glass accounts, Surface Hub device accounts, Teams Rooms accounts"] },
        { tab: "Target resources", instructions: ["Cloud apps → Include → Select apps → Office 365 Exchange Online, Office 365 SharePoint Online, Microsoft Teams"] },
        { tab: "Conditions", instructions: ["Device platforms → Configure Yes → Include: Windows only", "Client apps → Browser, Mobile apps and desktop clients"] },
        { tab: "Session", instructions: ["Require token protection for sign-in sessions → Enabled"] },
        { tab: "Enable policy", instructions: ["Set to Report-only first — token protection is in preview and may affect non-Windows clients. Verify Windows SSO works, then switch to On"] },
      ],
    },
    msLearnLinks: [
      { label: "MS Learn: Token protection", url: "https://learn.microsoft.com/entra/identity/conditional-access/concept-token-protection" },
      { label: "MS Learn: Protecting tokens in Entra", url: "https://learn.microsoft.com/entra/identity/devices/protecting-tokens-microsoft-entra-id" },
    ],
    check: (policies) => {
      const matching = getEnabled(policies).filter((p) => {
        const session = p.sessionControls as Record<string, unknown> | undefined;
        if (!session) return false;
        const ssis = session.secureSignInSession as
          | { isEnabled?: boolean }
          | undefined;
        const tp = session.tokenProtection as
          | { signInSessionTokenProtection?: { isEnabled?: boolean } }
          | undefined;
        return ssis?.isEnabled || tp?.signInSessionTokenProtection?.isEnabled;
      });

      return {
        status: matching.length > 0 ? "pass" : "fail",
        detail:
          matching.length > 0
            ? `Found ${matching.length} policy(ies) enforcing token protection.`
            : "No policy enforces token protection for sign-in sessions.",
        matchingPolicies: matching.map((p) => p.displayName),
        remediation:
          "Create a CA policy targeting Exchange Online, SharePoint Online, and Teams Services with session " +
          'control "Require token protection for sign-in sessions". Target Windows platform only, ' +
          "desktop clients only. Exclude Surface Hub and Teams Rooms device accounts.",
      };
    },
  },
  {
    id: "5.4.5",
    title: "Ensure app protection policy is required for mobile devices",
    level: "L2",
    section: "5.4 - Mobile Security",
    licenseRequirement: "intunePlan1",
    description:
      "A CA policy should require an Intune app protection policy for mobile device access, ensuring " +
      "corporate data is protected within managed apps even on unmanaged (BYOD) devices.",
    policyGuidance: {
      suggestedName: "YOURORG - INTUNE - GRANT - AppProtection-Mobile",
      prerequisiteSteps: [
        {
          title: "Part 1: Create Intune App Protection Policies",
          steps: [
            {
              label: "Create iOS App Protection Policy",
              instructions: [
                "Sign in to Intune admin center (intune.microsoft.com) → Apps → App protection policies",
                "Click + Create policy → iOS/iPadOS",
                "Name: YOURORG - iOS App Protection Policy",
                "Target apps: Core Microsoft Apps (Outlook, Teams, OneDrive, Edge, Word, Excel, PowerPoint, OneNote, SharePoint, To Do)",
                "Data protection: Block org data transfer to unmanaged apps, Restrict cut/copy/paste between apps, Encrypt org data",
                "Access requirements: Require PIN for access, require biometric instead of PIN (optional)",
                "Conditional launch: Max OS version, jailbreak/rooted detection → Block access",
                "Assignments: All Users (or target security group)",
              ],
            },
            {
              label: "Create Android App Protection Policy",
              instructions: [
                "In Intune admin center → Apps → App protection policies",
                "Click + Create policy → Android",
                "Name: YOURORG - Android App Protection Policy",
                "Target apps: Core Microsoft Apps (same set as iOS)",
                "Data protection: Block org data transfer to unmanaged apps, Restrict cut/copy/paste, Encrypt org data, Block screen capture",
                "Access requirements: Require PIN for access, require biometric instead of PIN (optional)",
                "Conditional launch: Max OS version, rooted device detection → Block access, SafetyNet device attestation → Block access",
                "Assignments: All Users (or target security group)",
              ],
            },
            {
              label: "Install Broker Apps (User Requirement)",
              instructions: [
                "iOS devices: Users must install Microsoft Authenticator from the App Store",
                "Android devices: Users must install Intune Company Portal from the Play Store",
                "These broker apps are required for app protection policy enforcement",
              ],
            },
          ],
        },
      ],
      portalSteps: [
        { tab: "Name", instructions: ["Enter policy name: YOURORG - INTUNE - GRANT - AppProtection-Mobile"] },
        { tab: "Users", instructions: ["Include → All users", "Exclude → break-glass / emergency access accounts", "Exclude → users with fully managed (compliant) devices if desired"] },
        { tab: "Target resources", instructions: ["Cloud apps → Include → All cloud apps (or select Office 365 suite)"] },
        { tab: "Conditions", instructions: ["Device platforms → Configure Yes → Include: Android, iOS only", "Client apps → Mobile apps and desktop clients"] },
        { tab: "Grant", instructions: ["Grant access → Select both:", "✅ Require approved client app", "✅ Require app protection policy", "For multiple controls → Require one of the selected controls (OR)"] },
        { tab: "Enable policy", instructions: ["Set to Report-only first", "Verify sign-in logs and CA insights workbook", "Once confirmed, switch to On"] },
      ],
      sampleJson: {
        displayName: "YOURORG - INTUNE - GRANT - AppProtection-Mobile",
        state: "disabled",
        conditions: {
          users: {
            includeUsers: ["All"],
            excludeUsers: [],
            excludeGroups: ["<Break-Glass-Group-ID>"],
          },
          applications: {
            includeApplications: ["All"],
          },
          platforms: {
            includePlatforms: ["android", "iOS"],
          },
          clientAppTypes: ["mobileAppsAndDesktopClients"],
        },
        grantControls: {
          operator: "OR",
          builtInControls: ["approvedApplication", "compliantApplication"],
        },
      },
    },
    msLearnLinks: [
      { label: "MS Learn: Require app protection policy", url: "https://learn.microsoft.com/entra/identity/conditional-access/policy-all-users-device-compliance" },
      { label: "MS Learn: Intune app protection", url: "https://learn.microsoft.com/mem/intune/apps/app-protection-policy" },
      { label: "MS Learn: Migrate approved client app to app protection", url: "https://learn.microsoft.com/entra/identity/conditional-access/migrate-approved-client-app" },
    ],
    advisories: [
      {
        id: "APPROVED-CLIENT-APP-RETIREMENT",
        title: "Approved client app grant control retiring March 2026",
        summary: "The 'Require approved client app' grant control is retiring in early March 2026. Policies using only this control must transition to 'Require application protection policy' (or use both with OR). New policies should only use the application protection policy grant.",
        severity: "critical",
        effectiveDate: "2026-03-01",
        url: "https://learn.microsoft.com/entra/identity/conditional-access/migrate-approved-client-app",
      },
    ],
    check: (policies) => {
      const matching = getEnabled(policies).filter((p) => {
        const hasAppProtection =
          hasGrantControl(p, "compliantApplication") ||
          hasGrantControl(p, "approvedApplication");
        return hasAppProtection;
      });

      return {
        status: matching.length > 0 ? "pass" : "fail",
        detail:
          matching.length > 0
            ? `Found ${matching.length} policy(ies) requiring app protection or approved apps.`
            : "No policy requires app protection or approved client apps for mobile devices.",
        matchingPolicies: matching.map((p) => p.displayName),
        remediation:
          "Create a CA policy targeting iOS and Android platforms with grant control " +
          '"Require app protection policy" or "Require approved client app". ' +
          "This requires Intune app protection policies to be configured first.",
      };
    },
  },

  // ═══════════════════════════════════════════════════════════════════════
  // Section 1.3 — Session Timeout
  // ═══════════════════════════════════════════════════════════════════════
  {
    id: "1.3.2",
    title: "Ensure 'Idle session timeout' is set to '3 hours (or less)' for unmanaged devices",
    level: "L2",
    section: "1.3 - Session Timeout",
    description:
      "A Conditional Access policy should enforce a sign-in frequency of 3 hours or less for unmanaged " +
      "(non-compliant, non-Hybrid Azure AD joined) devices. This limits the idle session window, reducing " +
      "the risk of session hijacking on devices the organization does not manage. The CIS benchmark " +
      "recommends configuring both the Global Idle Session Timeout in Microsoft 365 admin settings AND " +
      "a CA policy to enforce session limits on unmanaged devices.",
    policyGuidance: {
      suggestedName: "YOURORG - GLOBAL - SESSION - IdleTimeout-Unmanaged(3Hours)",
      portalSteps: [
        { tab: "Name", instructions: ["Enter policy name: YOURORG - GLOBAL - SESSION - IdleTimeout-Unmanaged(3Hours)"] },
        { tab: "Users", instructions: ["Include → All users", "Exclude → break-glass accounts"] },
        { tab: "Target resources", instructions: ["Cloud apps → Include → All cloud apps"] },
        {
          tab: "Conditions",
          instructions: [
            "Filter for devices → Configure Yes → Exclude filtered devices from policy",
            "Rule syntax: device.isCompliant -eq True -or device.trustType -eq \"ServerAD\"",
            "(This scopes the policy to unmanaged devices by excluding compliant and Hybrid Azure AD joined devices)",
          ],
        },
        { tab: "Session", instructions: ["Sign-in frequency → set to 3 hours", "Persistent browser session → set to 'Never persistent'"] },
        { tab: "Enable policy", instructions: ["Set to Report-only first, verify user experience is acceptable, then switch to On"] },
      ],
    },
    msLearnLinks: [
      { label: "MS Learn: Sign-in frequency & session lifetime", url: "https://learn.microsoft.com/entra/identity/conditional-access/concept-session-lifetime" },
      { label: "MS Learn: M365 idle session timeout", url: "https://learn.microsoft.com/microsoft-365/admin/manage/idle-session-timeout-web-apps" },
    ],
    check: (policies) => {
      const matching = getEnabled(policies).filter((p) => {
        const sif = p.sessionControls?.signInFrequency;
        if (!sif?.isEnabled || sif.value == null) return false;

        // Convert to minutes for comparison
        const minutes =
          sif.type === "hours"
            ? sif.value * 60
            : sif.type === "days"
              ? sif.value * 24 * 60
              : sif.value; // assume minutes if unrecognised type

        // Must be ≤ 180 minutes (3 hours)
        if (minutes > 180) return false;

        // Should target broadly — not just admin roles (that's 5.3.13)
        const broadTarget =
          targetsAllUsers(p) ||
          p.conditions.users.includeGroups.length > 0;

        // Extra confidence if the policy scopes to unmanaged devices
        const hasDeviceFilter = p.conditions.devices?.deviceFilter != null;
        const hasAppRestrictions =
          p.sessionControls?.applicationEnforcedRestrictions?.isEnabled === true;
        const hasPersistentBrowserNever =
          p.sessionControls?.persistentBrowser?.isEnabled === true &&
          p.sessionControls?.persistentBrowser?.mode === "never";

        // Accept if broad target or device-filtered
        return broadTarget || hasDeviceFilter || hasAppRestrictions || hasPersistentBrowserNever;
      });

      return {
        status: matching.length > 0 ? "pass" : "fail",
        detail:
          matching.length > 0
            ? `Found ${matching.length} policy(ies) enforcing session timeout ≤ 3 hours for unmanaged devices.`
            : "No CA policy enforces idle session timeout of 3 hours or less for unmanaged devices.",
        matchingPolicies: matching.map((p) => p.displayName),
        remediation:
          "Create a CA policy targeting all users → all cloud apps with session control " +
          "sign-in frequency set to 3 hours or less. Scope to unmanaged devices using a device filter " +
          '(exclude devices where device.isCompliant -eq True -or device.trustType -eq "ServerAD") ' +
          "and set persistent browser to 'Never persistent'. Also configure the Global Idle Session " +
          "Timeout in Microsoft 365 admin center → Org settings → Security & privacy → Idle session timeout.",
      };
    },
  },
];

// ─── CIS Alignment Runner ────────────────────────────────────────────────────

export function runCISAlignment(context: TenantContext): CISAlignmentResult {
  const results: CISControlResult[] = CIS_CONTROLS.map((control) => {
    // License-aware: if the control requires a license the tenant doesn't have,
    // mark it not-applicable so it doesn't penalise the score.
    if (
      control.licenseRequirement &&
      !isLicensed(context.licenses, control.licenseRequirement)
    ) {
      const licenseLabel =
        control.licenseRequirement === "entraIdP2"
          ? "Entra ID P2"
          : control.licenseRequirement === "intunePlan1"
            ? "Intune Plan 1"
            : "Entra ID P1";
      return {
        control,
        result: {
          status: "not-applicable" as CISStatus,
          detail: `Requires ${licenseLabel} license (not detected in tenant).`,
          matchingPolicies: [],
          remediation: `This control requires a ${licenseLabel} license to evaluate. Acquire the license or exclude this control from scoring.`,
        },
      };
    }

    const result = control.check(context.policies, context);

    // If check passed, verify at least one matching policy is truly enforced.
    // Report-only policies don't actually enforce controls — downgrade to manual
    // so the operator knows to flip the policy to "On".
    if (result.status === "pass" && result.matchingPolicies.length > 0) {
      const hasEnforcedMatch = result.matchingPolicies.some((name) =>
        context.policies.some(
          (p) => p.displayName === name && p.state === "enabled"
        )
      );

      if (!hasEnforcedMatch) {
        return {
          control,
          result: {
            ...result,
            status: "manual" as CISStatus,
            detail:
              result.detail.replace(/\.$/, "") +
              " (report-only — not currently enforced).",
            remediation:
              "Matching policy(ies) are in report-only mode and not actively enforcing. " +
              "Switch to enabled: " +
              result.matchingPolicies.join(", ") +
              ".",
          },
        };
      }
    }

    // Generic near-miss detection for failed checks — if the check
    // didn't already provide check-specific near-misses, scan all
    // policies individually to find disabled/partial matches.
    if (result.status === "fail" && !result.nearMissPolicies?.length) {
      const nearMisses = detectNearMissPolicies(control, context);
      if (nearMisses.length > 0) {
        result.nearMissPolicies = nearMisses;
      }
    }

    return { control, result };
  });

  const passCount = results.filter((r) => r.result.status === "pass").length;
  const failCount = results.filter((r) => r.result.status === "fail").length;
  const manualCount = results.filter(
    (r) => r.result.status === "manual"
  ).length;
  const notApplicableCount = results.filter(
    (r) => r.result.status === "not-applicable"
  ).length;

  const scorable = results.filter(
    (r) => r.result.status !== "not-applicable" && r.result.status !== "manual"
  );
  const alignmentScore =
    scorable.length > 0
      ? Math.round((passCount / scorable.length) * 100)
      : 0;

  return {
    controls: results,
    passCount,
    failCount,
    manualCount,
    notApplicableCount,
    totalControls: CIS_CONTROLS.length,
    alignmentScore,
    benchmarkVersion: "6.0.0",
  };
}
