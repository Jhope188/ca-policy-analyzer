/**
 * CIS Microsoft 365 Foundations Benchmark — Conditional Access Controls
 *
 * Based on CIS Microsoft 365 Foundations Benchmark v4.0
 * Section 6.2: Conditional Access Policies
 * Section 6.3: Identity Protection (Risk-based CA)
 *
 * Each control defines:
 *   - What to check in the tenant's CA policies
 *   - How to determine pass/fail
 *   - The CIS recommendation text
 */

import { ConditionalAccessPolicy, TenantContext } from "@/lib/graph-client";

// ─── Types ───────────────────────────────────────────────────────────────────

export type CISLevel = "L1" | "L2";

export interface CISControl {
  /** CIS control ID, e.g. "6.2.1" */
  id: string;
  /** CIS section title */
  title: string;
  /** CIS level: L1 (essential) or L2 (defense-in-depth) */
  level: CISLevel;
  /** The CIS benchmark section */
  section: string;
  /** What this control requires */
  description: string;
  /** The check function — returns pass/fail + detail */
  check: (policies: ConditionalAccessPolicy[], context: TenantContext) => CISCheckResult;
}

export type CISStatus = "pass" | "fail" | "manual" | "not-applicable";

export interface CISCheckResult {
  status: CISStatus;
  /** Short result description */
  detail: string;
  /** Policies that satisfy (or partially satisfy) this control */
  matchingPolicies: string[];
  /** Remediation guidance if failed */
  remediation?: string;
}

export interface CISAlignmentResult {
  controls: CISControlResult[];
  passCount: number;
  failCount: number;
  manualCount: number;
  totalControls: number;
  alignmentScore: number; // 0-100 percentage
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

// ─── CIS Controls ────────────────────────────────────────────────────────────

export const CIS_CONTROLS: CISControl[] = [
  // ═══════════════════════════════════════════════════════════════════════
  // Section 6.2 — Conditional Access Policies
  // ═══════════════════════════════════════════════════════════════════════
  {
    id: "6.2.1",
    title: "Ensure MFA is required for all users",
    level: "L1",
    section: "6.2 - Conditional Access",
    description:
      'A CA policy must exist that targets "All users" and "All cloud apps" with MFA as a grant control (or authentication strength requiring MFA). The policy must be enabled or in report-only mode.',
    check: (policies) => {
      const matching = getEnabled(policies).filter(
        (p) =>
          targetsAllUsers(p) &&
          targetsAllApps(p) &&
          (hasGrantControl(p, "mfa") ||
            p.grantControls?.authenticationStrength != null)
      );

      return {
        status: matching.length > 0 ? "pass" : "fail",
        detail:
          matching.length > 0
            ? `Found ${matching.length} policy(ies) requiring MFA for all users and all apps.`
            : "No enabled policy requires MFA for ALL users on ALL cloud apps.",
        matchingPolicies: matching.map((p) => p.displayName),
        remediation:
          'Create a CA policy targeting "All users" → "All cloud apps" with grant control "Require multifactor authentication".',
      };
    },
  },
  {
    id: "6.2.2",
    title: "Ensure MFA is required for guest and external users",
    level: "L1",
    section: "6.2 - Conditional Access",
    description:
      "A CA policy must require MFA for guest, B2B collaboration, and external users to prevent unauthorized access through external identities.",
    check: (policies) => {
      const matching = getEnabled(policies).filter((p) => {
        const users = p.conditions.users;
        const targetsGuests =
          users.includeGuestsOrExternalUsers != null ||
          users.includeUsers.includes("GuestsOrExternalUsers");
        const requiresMfa =
          hasGrantControl(p, "mfa") ||
          p.grantControls?.authenticationStrength != null;
        return targetsGuests && requiresMfa;
      });

      // Also check if All Users MFA covers guests
      const allUsersMfa = getEnabled(policies).filter(
        (p) =>
          targetsAllUsers(p) &&
          targetsAllApps(p) &&
          (hasGrantControl(p, "mfa") ||
            p.grantControls?.authenticationStrength != null)
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
          "Create a CA policy targeting guest/external user types with MFA grant control, or ensure your all-users MFA policy does not exclude guests.",
      };
    },
  },
  {
    id: "6.2.3",
    title: "Ensure MFA is required for administrative roles",
    level: "L1",
    section: "6.2 - Conditional Access",
    description:
      "A dedicated CA policy must require MFA specifically for admin roles. Even if an all-users MFA policy exists, a separate admin policy provides defense-in-depth.",
    check: (policies) => {
      const matching = getEnabled(policies).filter(
        (p) =>
          hasAdminRoles(p) &&
          (hasGrantControl(p, "mfa") ||
            p.grantControls?.authenticationStrength != null)
      );

      return {
        status: matching.length > 0 ? "pass" : "fail",
        detail:
          matching.length > 0
            ? `Found ${matching.length} policy(ies) requiring MFA for admin roles.`
            : "No dedicated policy requires MFA for administrative roles.",
        matchingPolicies: matching.map((p) => p.displayName),
        remediation:
          "Create a CA policy targeting admin directory roles (Global Admin, Exchange Admin, etc.) with MFA grant control.",
      };
    },
  },
  {
    id: "6.2.4",
    title: "Ensure MFA is required to register or join devices",
    level: "L1",
    section: "6.2 - Conditional Access",
    description:
      "A CA policy must require MFA for the user action 'Register or join devices' OR for the 'Register security information' user action, preventing unauthorized device registration.",
    check: (policies) => {
      const matching = getEnabled(policies).filter((p) => {
        const actions = p.conditions.applications.includeUserActions;
        return (
          (actions.includes("urn:user:registersecurityinfo") ||
            actions.includes("urn:user:registerdevice")) &&
          (hasGrantControl(p, "mfa") ||
            p.grantControls?.authenticationStrength != null)
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
          'Create a CA policy targeting user action "Register or join devices" or "Register security information" with MFA grant control.',
      };
    },
  },
  {
    id: "6.2.5",
    title: "Ensure access from non-allowed countries is blocked",
    level: "L1",
    section: "6.2 - Conditional Access",
    description:
      "A CA policy must block access from countries where the organization does not operate using named locations.",
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

      return {
        status: matching.length > 0 ? "pass" : "fail",
        detail:
          matching.length > 0
            ? `Found ${matching.length} geo-blocking policy(ies).`
            : "No policy blocks access from non-allowed countries.",
        matchingPolicies: matching.map((p) => p.displayName),
        remediation:
          "Create a named location with allowed countries, then create a CA policy blocking all users from all locations except the allowed country list.",
      };
    },
  },
  {
    id: "6.2.6",
    title: "Ensure device code flow is blocked",
    level: "L1",
    section: "6.2 - Conditional Access",
    description:
      "Device code flow should be blocked to prevent device code phishing attacks where attackers trick users into authenticating on their behalf.",
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
          'Create a CA policy targeting "All users" → "All cloud apps" with authentication flow condition "Device code flow" and grant control "Block access".',
      };
    },
  },
  {
    id: "6.2.7",
    title: "Ensure legacy authentication is blocked",
    level: "L1",
    section: "6.2 - Conditional Access",
    description:
      "Legacy authentication protocols (IMAP, POP3, SMTP, Exchange ActiveSync) must be blocked because they cannot enforce MFA.",
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
          'Create a CA policy targeting "All users" → "All cloud apps" with client apps "Exchange ActiveSync clients" and "Other clients" and grant control "Block access".',
      };
    },
  },
  {
    id: "6.2.8",
    title: "Ensure sign-in frequency for admin portals is limited",
    level: "L2",
    section: "6.2 - Conditional Access",
    description:
      "Admin sessions should have a limited sign-in frequency (e.g., 1 hour) to reduce the window of opportunity if an admin session token is stolen.",
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
          "Create a CA policy targeting admin roles with session control sign-in frequency set to 1 hour.",
      };
    },
  },

  // ═══════════════════════════════════════════════════════════════════════
  // Section 6.3 — Identity Protection (Risk-based)
  // ═══════════════════════════════════════════════════════════════════════
  {
    id: "6.3.1",
    title: "Ensure sign-in risk policy is configured",
    level: "L2",
    section: "6.3 - Identity Protection",
    description:
      "A risk-based CA policy should be configured to require MFA or block access for medium and high-risk sign-ins detected by Identity Protection.",
    check: (policies) => {
      const matching = getEnabled(policies).filter((p) => {
        const riskLevels = p.conditions.signInRiskLevels ?? [];
        return (
          riskLevels.length > 0 &&
          (hasGrantControl(p, "mfa") ||
            hasGrantControl(p, "block") ||
            p.grantControls?.authenticationStrength != null)
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
          'Create CA policies targeting "All users" → "All cloud apps" with sign-in risk condition set to "High" and "Medium" with appropriate grant controls. Requires Entra ID P2 license.',
      };
    },
  },
  {
    id: "6.3.2",
    title: "Ensure user risk policy is configured",
    level: "L2",
    section: "6.3 - Identity Protection",
    description:
      "A risk-based CA policy should require password change and MFA for medium and high-risk users detected by Identity Protection.",
    check: (policies) => {
      const matching = getEnabled(policies).filter((p) => {
        const riskLevels = p.conditions.userRiskLevels ?? [];
        return (
          riskLevels.length > 0 &&
          (hasGrantControl(p, "passwordChange") ||
            hasGrantControl(p, "mfa") ||
            hasGrantControl(p, "block"))
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
            ? `User risk policies cover: ${coversHigh ? "High" : ""}${coversHigh && coversMedium ? " + " : ""}${coversMedium ? "Medium" : ""} risk levels.`
            : "No user risk-based CA policy found. Requires Entra ID P2.",
        matchingPolicies: matching.map((p) => p.displayName),
        remediation:
          'Create CA policies targeting "All users" → "All cloud apps" with user risk condition set to "High" and "Medium" requiring MFA + password change. Requires Entra ID P2 license.',
      };
    },
  },
  {
    id: "6.3.3",
    title: "Ensure compliant device requirement is configured",
    level: "L2",
    section: "6.3 - Device Compliance",
    description:
      "A CA policy should require device compliance for accessing corporate resources, ensuring only healthy managed devices can connect.",
    check: (policies) => {
      const matching = getEnabled(policies).filter((p) =>
        hasGrantControl(p, "compliantDevice")
      );

      return {
        status: matching.length > 0 ? "pass" : "fail",
        detail:
          matching.length > 0
            ? `Found ${matching.length} policy(ies) requiring compliant devices.`
            : "No policy requires device compliance.",
        matchingPolicies: matching.map((p) => p.displayName),
        remediation:
          'Create a CA policy with grant control "Require device to be marked as compliant". This requires Intune enrollment and compliance policies.',
      };
    },
  },
];

// ─── CIS Alignment Runner ────────────────────────────────────────────────────

export function runCISAlignment(context: TenantContext): CISAlignmentResult {
  const results: CISControlResult[] = CIS_CONTROLS.map((control) => ({
    control,
    result: control.check(context.policies, context),
  }));

  const passCount = results.filter((r) => r.result.status === "pass").length;
  const failCount = results.filter((r) => r.result.status === "fail").length;
  const manualCount = results.filter(
    (r) => r.result.status === "manual"
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
    totalControls: CIS_CONTROLS.length,
    alignmentScore,
  };
}
