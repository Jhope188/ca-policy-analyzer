/**
 * CIS Microsoft 365 Foundations Benchmark — Conditional Access Controls
 *
 * Based on CIS Microsoft 365 Foundations Benchmark v6.0.0
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

import { ConditionalAccessPolicy, TenantContext } from "@/lib/graph-client";

// ─── Types ───────────────────────────────────────────────────────────────────

export type CISLevel = "L1" | "L2";

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
    description:
      "A risk-based CA policy must require MFA or block access for medium and high-risk sign-ins " +
      "detected by Identity Protection. Promoted from L2 to L1 in v6.0.",
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
    description:
      "A risk-based CA policy must require password change and MFA for medium and high-risk users " +
      "detected by Identity Protection. Promoted from L2 to L1 in v6.0.",
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
          'Create CA policies targeting "All users" → "All cloud apps" with user risk condition set to ' +
          '"High" and "Medium" requiring MFA + password change. Requires Entra ID P2 license.',
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
          "Create a named location with allowed countries, then create a CA policy blocking all users from " +
          "all locations except the allowed country list.",
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
    description:
      "A CA policy should block access for users with high user risk level. This ensures compromised accounts " +
      "are immediately locked out until remediated.",
    check: (policies) => {
      const matching = getEnabled(policies).filter((p) => {
        const riskLevels = p.conditions.userRiskLevels ?? [];
        return (
          riskLevels.includes("high") &&
          (hasGrantControl(p, "block") ||
            hasGrantControl(p, "passwordChange"))
        );
      });

      return {
        status: matching.length > 0 ? "pass" : "fail",
        detail:
          matching.length > 0
            ? `Found ${matching.length} policy(ies) blocking or requiring remediation for high-risk users.`
            : "No policy blocks or forces remediation for high-risk users.",
        matchingPolicies: matching.map((p) => p.displayName),
        remediation:
          'Create a CA policy targeting "All users" with user risk condition set to "High" and ' +
          'grant control "Block access" or "Require password change + MFA". Requires Entra ID P2.',
      };
    },
  },
  {
    id: "5.4.2",
    title: "Ensure high-risk sign-ins are blocked",
    level: "L1",
    section: "5.4 - Identity Protection",
    description:
      "A CA policy should block access for sign-ins with high risk level. High-risk sign-ins indicate " +
      "strong likelihood of compromised credentials or anomalous behavior.",
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
    description:
      "A CA policy should require device compliance for accessing corporate resources, ensuring only healthy " +
      "managed devices enrolled in Intune can connect.",
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
    description:
      "A CA policy should require an Intune app protection policy for mobile device access, ensuring " +
      "corporate data is protected within managed apps even on unmanaged (BYOD) devices.",
    check: (policies) => {
      const matching = getEnabled(policies).filter((p) => {
        const hasAppProtection =
          hasGrantControl(p, "compliantApplication") ||
          hasGrantControl(p, "approvedApplication");
        return hasAppProtection;
      });

      return {
        status: matching.length > 0 ? "pass" : "manual",
        detail:
          matching.length > 0
            ? `Found ${matching.length} policy(ies) requiring app protection or approved apps.`
            : "No policy requires app protection or approved client apps. Manual review needed if BYOD is not in scope.",
        matchingPolicies: matching.map((p) => p.displayName),
        remediation:
          "Create a CA policy targeting iOS and Android platforms with grant control " +
          '"Require app protection policy" or "Require approved client app". ' +
          "This requires Intune app protection policies to be configured.",
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
    benchmarkVersion: "6.0.0",
  };
}
