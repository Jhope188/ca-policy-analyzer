/**
 * Microsoft Learn – Documented CA Policy Exclusions & Requirements
 *
 * This database maps specific CA policy patterns to known exclusions,
 * limitations, and configuration requirements sourced from official
 * Microsoft documentation (learn.microsoft.com).
 *
 * When a tenant policy matches a pattern but is missing a documented
 * exclusion or misconfigured, the analyzer flags it as a potential impact.
 */

import { ConditionalAccessPolicy, AuthenticationStrengthPolicy } from "@/lib/graph-client";

// ─── Types ───────────────────────────────────────────────────────────────────

export type ImpactSeverity = "critical" | "high" | "medium" | "info";

export interface DocumentedExclusion {
  /** Unique slug for this check */
  id: string;
  /** Short title for display */
  title: string;
  /** What policy pattern triggers this check */
  appliesWhen: string;
  /** What is documented as required */
  requirement: string;
  /** How to detect the issue */
  detect: (policy: ConditionalAccessPolicy, authStrengthPolicies?: Map<string, AuthenticationStrengthPolicy>) => ExclusionCheckResult | null;
  /** Severity when the exclusion is missing */
  severity: ImpactSeverity;
  /** Official MS Learn documentation URL */
  docUrl: string;
  /** Brief remediation guidance */
  remediation: string;
}

export interface ExclusionCheckResult {
  /** What exactly is wrong */
  detail: string;
  /** Impacted resources/services/users */
  impactedResources?: string[];
}

// ─── Well-known app IDs ──────────────────────────────────────────────────────

const EXCHANGE_ONLINE = "00000002-0000-0ff1-ce00-000000000000";
const SHAREPOINT_ONLINE = "00000003-0000-0ff1-ce00-000000000000";
const TEAMS_SERVICE = "cc15fd57-2c6c-4117-a88c-83b1d56b4bbe";
const OFFICE_365 = "Office365";
const AZURE_VIRTUAL_DESKTOP = "9cdead84-a844-4324-93f2-b2e6bb768d07";
const WINDOWS_365 = "0af06dc6-e4b5-4f28-818e-e78e62d137a5";
const DEFENDER_ATP_XPLAT = "a0e84e36-b067-4d5c-ab4a-3db38e598ae2";
const DEFENDER_TVM = "e724aa31-0f56-4018-b8be-f8cb82ca1196";
const WINDOWS_CLOUD_LOGIN = "372140e0-b3b7-4226-8ef9-d57986796201";

const TOKEN_PROTECTION_SUPPORTED_APPS = new Set([
  EXCHANGE_ONLINE,
  SHAREPOINT_ONLINE,
  TEAMS_SERVICE,
  AZURE_VIRTUAL_DESKTOP,
  WINDOWS_365,
  WINDOWS_CLOUD_LOGIN,
]);

// ─── Helper: detect token protection session control ─────────────────────────

function hasTokenProtection(policy: ConditionalAccessPolicy): boolean {
  const session = policy.sessionControls as Record<string, unknown> | undefined;
  if (!session) return false;
  // Check secureSignInSession or tokenProtection
  const ssis = session.secureSignInSession as
    | { isEnabled?: boolean }
    | undefined;
  if (ssis?.isEnabled) return true;
  // Graph v1.0 sometimes returns this as "tokenProtection"
  const tp = session.tokenProtection as
    | { signInSessionTokenProtection?: { isEnabled?: boolean } }
    | undefined;
  if (tp?.signInSessionTokenProtection?.isEnabled) return true;
  return false;
}

function hasDeviceComplianceGrant(policy: ConditionalAccessPolicy): boolean {
  return (
    policy.grantControls?.builtInControls.includes("compliantDevice") ?? false
  );
}

function hasMfaGrant(policy: ConditionalAccessPolicy): boolean {
  return (
    (policy.grantControls?.builtInControls.includes("mfa") ||
      policy.grantControls?.authenticationStrength != null) ??
    false
  );
}

function hasBlockGrant(policy: ConditionalAccessPolicy): boolean {
  return policy.grantControls?.builtInControls.includes("block") ?? false;
}

function targetsAllUsers(policy: ConditionalAccessPolicy): boolean {
  return policy.conditions.users.includeUsers.includes("All");
}

function targetsAllApps(policy: ConditionalAccessPolicy): boolean {
  return policy.conditions.applications.includeApplications.includes("All");
}

function isActivePolicy(policy: ConditionalAccessPolicy): boolean {
  return (
    policy.state === "enabled" ||
    policy.state === "enabledForReportingButNotEnforced"
  );
}

function hasNoUserExclusions(policy: ConditionalAccessPolicy): boolean {
  const u = policy.conditions.users;
  return (
    u.excludeUsers.length === 0 &&
    u.excludeGroups.length === 0 &&
    u.excludeRoles.length === 0
  );
}

function hasAdminRoles(policy: ConditionalAccessPolicy): boolean {
  return policy.conditions.users.includeRoles.length > 0;
}

// ─── Documented Exclusions Database ──────────────────────────────────────────

export const DOCUMENTED_EXCLUSIONS: DocumentedExclusion[] = [
  // ═══════════════════════════════════════════════════════════════════════
  // TOKEN PROTECTION
  // ═══════════════════════════════════════════════════════════════════════
  {
    id: "token-prot-apps",
    title: "Token Protection: Only supported for specific apps",
    appliesWhen: "Policy uses Token Protection session control",
    requirement:
      "Token Protection policies must only target Exchange Online, SharePoint Online, " +
      "Teams Services, Azure Virtual Desktop, Windows 365, and Windows Cloud Login. " +
      "Selecting the Office 365 application group may result in unintended failures.",
    detect: (policy) => {
      if (!isActivePolicy(policy) || !hasTokenProtection(policy)) return null;

      const apps = policy.conditions.applications;
      // Check if they're targeting "All" or "Office365" instead of specific apps
      if (apps.includeApplications.includes("All")) {
        return {
          detail:
            'Token Protection policy targets "All cloud apps" instead of specific supported applications. ' +
            "This will block users on unsupported apps like PowerQuery, VS Code extensions, and Office perpetual clients.",
          impactedResources: [
            "PowerShell modules accessing SharePoint",
            "PowerQuery extension for Excel",
            "VS Code extensions accessing Exchange/SharePoint",
            "Office perpetual clients",
          ],
        };
      }
      if (
        apps.includeApplications.some(
          (a) => a.toLowerCase() === OFFICE_365.toLowerCase()
        )
      ) {
        return {
          detail:
            "Token Protection policy uses the Office 365 application group. " +
            "Microsoft warns this may result in unintended failures. Target Exchange Online, " +
            "SharePoint Online, and Teams Services individually instead.",
          impactedResources: ["Office 365 application group members"],
        };
      }
      // Check for unsupported app targets
      const unsupported = apps.includeApplications.filter(
        (a) => !TOKEN_PROTECTION_SUPPORTED_APPS.has(a)
      );
      if (unsupported.length > 0) {
        return {
          detail:
            `Token Protection policy targets ${unsupported.length} application(s) that may not support token protection. ` +
            `Only Exchange Online, SharePoint Online, Teams, Azure Virtual Desktop, Windows 365, and Windows Cloud Login are supported.`,
          impactedResources: unsupported,
        };
      }
      return null;
    },
    severity: "high",
    docUrl:
      "https://learn.microsoft.com/entra/identity/conditional-access/concept-token-protection#deployment",
    remediation:
      "Configure the Token Protection policy to target only: Office 365 Exchange Online, " +
      "Office 365 SharePoint Online, Microsoft Teams Services. If AVD/W365 is deployed, include those too. " +
      "Do NOT use the Office 365 application group.",
  },
  {
    id: "token-prot-platform",
    title: "Token Protection: Must target Windows platform only",
    appliesWhen: "Policy uses Token Protection session control",
    requirement:
      "Token Protection is only available for Windows devices. The policy must target the Windows device platform and " +
      "must only use 'Mobile apps and desktop clients' (not browser).",
    detect: (policy) => {
      if (!isActivePolicy(policy) || !hasTokenProtection(policy)) return null;

      const platforms = policy.conditions.platforms;
      const clientTypes = policy.conditions.clientAppTypes;
      const issues: string[] = [];

      // Check platform is set to Windows
      if (!platforms || !platforms.includePlatforms.includes("windows")) {
        issues.push(
          "Token Protection policy does not explicitly target Windows platform. It is only supported on Windows 10+."
        );
      }

      // Check that browser is not the only client app type
      if (
        clientTypes.length === 0 ||
        clientTypes.includes("browser")
      ) {
        issues.push(
          'Token Protection policy includes "Browser" client apps or has no Client Apps condition configured. ' +
          "MSAL.js-based apps like Teams Web will be blocked."
        );
      }

      if (issues.length > 0) {
        return {
          detail: issues.join(" "),
          impactedResources: [
            "macOS / iOS / Android / Linux users",
            "Teams Web (MSAL.js)",
            "Browser-based applications",
          ],
        };
      }
      return null;
    },
    severity: "high",
    docUrl:
      "https://learn.microsoft.com/entra/identity/conditional-access/concept-token-protection#deployment",
    remediation:
      "Set Device platforms → Include → Windows only. Set Client apps → Mobile apps and desktop clients only. " +
      "Leave Browser unchecked to avoid blocking MSAL.js apps like Teams Web.",
  },
  {
    id: "token-prot-devices",
    title: "Token Protection: Unsupported device types must be excluded",
    appliesWhen: "Policy uses Token Protection session control",
    requirement:
      "Certain device registration types are unsupported for Token Protection and must be excluded via device filters: " +
      "Surface Hub, Teams Rooms (MTR), Azure AD joined AVD hosts, Cloud PCs, Autopilot self-deploying, Azure VMs, " +
      "and bulk-enrolled devices.",
    detect: (policy) => {
      if (!isActivePolicy(policy) || !hasTokenProtection(policy)) return null;

      // Check if there's a device filter to exclude unsupported devices
      const deviceFilter = policy.conditions.devices?.deviceFilter;
      if (!deviceFilter) {
        return {
          detail:
            "Token Protection policy has no device filter to exclude unsupported device types. " +
            "Surface Hub, Teams Rooms (MTR), Cloud PCs (AzureAD joined), AVD session hosts, " +
            "Autopilot self-deploying devices, bulk-enrolled devices, and Azure VMs will be BLOCKED. " +
            "Users on these devices will see unclear error messages.",
          impactedResources: [
            "Surface Hub",
            "Teams Rooms (MTR) on Windows",
            "Cloud PCs (Microsoft Entra joined)",
            "Azure Virtual Desktop session hosts (Microsoft Entra joined)",
            "Windows Autopilot self-deploying devices",
            "Bulk-enrolled Windows devices",
            "Azure VMs with Entra ID auth",
          ],
        };
      }

      // Check if the filter looks like it's excluding the right things
      const rule = deviceFilter.rule.toLowerCase();
      const knownExclusions = [
        { pattern: "cloudpc", label: "Cloud PCs" },
        { pattern: "azurevirtualdesktop", label: "Azure Virtual Desktop" },
        { pattern: "powerapautomate", label: "Power Automate hosted machines" },
        { pattern: "autopilot", label: "Autopilot self-deploying" },
        { pattern: "securevm", label: "Azure VMs" },
      ];

      const missing = knownExclusions.filter(
        (e) => !rule.includes(e.pattern)
      );
      if (missing.length > 0 && deviceFilter.mode === "exclude") {
        // Some exclusions exist but may be incomplete
        return {
          detail:
            `Token Protection device filter may not cover all unsupported device types. ` +
            `Potentially missing exclusions for: ${missing.map((m) => m.label).join(", ")}.`,
          impactedResources: missing.map((m) => m.label),
        };
      }

      return null;
    },
    severity: "high",
    docUrl:
      "https://learn.microsoft.com/entra/identity/conditional-access/concept-token-protection#known-limitations",
    remediation:
      "Add device filter conditions to exclude unsupported types. For example: " +
      'systemLabels -eq "CloudPC" and trustType -eq "AzureAD", ' +
      'systemLabels -eq "AzureVirtualDesktop" and trustType -eq "AzureAD", ' +
      'profileType -eq "SecureVM" and trustType -eq "AzureAD".',
  },

  // ═══════════════════════════════════════════════════════════════════════
  // EMERGENCY ACCESS / BREAK-GLASS
  // ═══════════════════════════════════════════════════════════════════════
  {
    id: "break-glass-missing",
    title: "Break-glass accounts: No user exclusions on broad policy",
    appliesWhen:
      "Policy targets All Users with MFA, block, compliance, or hybrid join controls",
    requirement:
      "Microsoft recommends excluding emergency access (break-glass) accounts from all CA policies " +
      "to prevent lockout due to policy misconfiguration. At least 2 break-glass accounts should be excluded.",
    detect: (policy) => {
      if (!isActivePolicy(policy)) return null;
      if (!targetsAllUsers(policy)) return null;
      // Only check for enforcement policies, not permissive ones
      if (
        !hasMfaGrant(policy) &&
        !hasBlockGrant(policy) &&
        !hasDeviceComplianceGrant(policy)
      )
        return null;

      if (hasNoUserExclusions(policy)) {
        return {
          detail:
            `Policy "${policy.displayName}" targets All Users with enforcement controls but has NO user exclusions. ` +
            "If this policy is misconfigured or an outage occurs, ALL users (including admins) will be locked out. " +
            "Microsoft strongly recommends excluding at least 2 emergency access accounts.",
          impactedResources: ["All administrators", "Emergency access accounts"],
        };
      }
      return null;
    },
    severity: "critical",
    docUrl:
      "https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access",
    remediation:
      "Exclude at least 2 emergency access (break-glass) accounts from this policy. " +
      "These accounts should have complex passwords, be cloud-only, and be monitored for use via alerts.",
  },

  // ═══════════════════════════════════════════════════════════════════════
  // SURFACE HUB
  // ═══════════════════════════════════════════════════════════════════════
  {
    id: "surface-hub-mfa",
    title: "Surface Hub: Cannot satisfy MFA or compliance requirements",
    appliesWhen:
      "Broad policy requires MFA, device compliance, hybrid join, approved app, or app protection",
    requirement:
      "Surface Hub device accounts are incompatible with MFA, authentication strength, device compliance, " +
      "hybrid join, approved client app, app protection, and password change grant controls. " +
      "Surface Hub accounts must be excluded from such policies.",
    detect: (policy) => {
      if (!isActivePolicy(policy)) return null;
      if (!targetsAllUsers(policy) || !targetsAllApps(policy)) return null;

      const grant = policy.grantControls;
      if (!grant) return null;

      const unsupportedControls = grant.builtInControls.filter((c) =>
        [
          "mfa",
          "compliantDevice",
          "domainJoinedDevice",
          "approvedApplication",
          "compliantApplication",
          "passwordChange",
        ].includes(c)
      );

      const hasAuthStrength = grant.authenticationStrength != null;

      if (unsupportedControls.length === 0 && !hasAuthStrength) return null;

      // This is a broad policy with unsupported controls - check for device filter or service account exclusion
      // We can't tell for sure if Surface Hub is excluded without knowing specific account IDs,
      // but we flag it as a recommendation
      return {
        detail:
          `Policy requires ${[...unsupportedControls, ...(hasAuthStrength ? ["authentication strength"] : [])].join(", ")} ` +
          "for all users. Surface Hub device accounts CANNOT satisfy these controls and will fail to sign in. " +
          "This affects meeting room calendar sync, Teams Rooms sign-in, and collaborative features.",
        impactedResources: [
          "Surface Hub calendar sync",
          "Surface Hub Teams meetings",
          "Surface Hub collaborative whiteboard",
        ],
      };
    },
    severity: "medium",
    docUrl:
      "https://learn.microsoft.com/surface-hub/conditional-access-for-surface-hub",
    remediation:
      "Exclude Surface Hub device accounts (or a group containing them) from this policy. " +
      "Ensure you select the user object, not the device object, when adding the exclusion.",
  },

  // ═══════════════════════════════════════════════════════════════════════
  // TEAMS ROOMS
  // ═══════════════════════════════════════════════════════════════════════
  {
    id: "teams-rooms-mfa",
    title: "Teams Rooms on Windows: MFA and auth strength not supported",
    appliesWhen:
      "Policy requires MFA or authentication strength for all users",
    requirement:
      "Teams Rooms on Windows does NOT support MFA or authentication strength grant controls. " +
      "Teams Rooms resource accounts must be excluded from MFA-enforcing policies.",
    detect: (policy) => {
      if (!isActivePolicy(policy)) return null;
      if (!targetsAllUsers(policy)) return null;

      const grant = policy.grantControls;
      if (!grant) return null;

      if (
        !grant.builtInControls.includes("mfa") &&
        !grant.authenticationStrength
      )
        return null;

      // Flag if broad MFA policy with all users
      if (targetsAllApps(policy)) {
        return {
          detail:
            "Policy requires MFA/authentication strength for all users and all apps. " +
            "Teams Rooms on Windows does NOT support MFA or authentication strength. " +
            "Teams Rooms Android devices support MFA but not authentication strength. " +
            "Room resource accounts will be blocked from signing in.",
          impactedResources: [
            "Teams Rooms on Windows",
            "Teams Rooms on Android (auth strength only)",
            "Teams Panels",
          ],
        };
      }
      return null;
    },
    severity: "medium",
    docUrl:
      "https://learn.microsoft.com/microsoftteams/rooms/supported-ca-and-compliance-policies",
    remediation:
      "Exclude Teams Rooms resource accounts (or a shared device group) from MFA-enforcing policies. " +
      "Use device compliance as an alternative control for Teams Rooms devices.",
  },

  // ═══════════════════════════════════════════════════════════════════════
  // DEVICE CODE FLOW + TEAMS ANDROID
  // ═══════════════════════════════════════════════════════════════════════
  {
    id: "device-code-teams-android",
    title: "Device Code Block: Breaks Teams Android remote sign-in",
    appliesWhen: "Policy blocks device code authentication flow",
    requirement:
      "Blocking device code flow prevents using microsoft.com/devicelogin to remotely sign in " +
      "Teams Android devices. Teams Android device accounts should be excluded, or use an " +
      "alternative sign-in method.",
    detect: (policy) => {
      if (!isActivePolicy(policy)) return null;
      if (!hasBlockGrant(policy)) return null;

      const authFlows = (policy.conditions as Record<string, unknown>)
        .authenticationFlows as
        | { transferMethods?: string }
        | null
        | undefined;
      if (!authFlows?.transferMethods) return null;

      return {
        detail:
          "Policy blocks device code authentication flow for all users. " +
          "This prevents remote sign-in (microsoft.com/devicelogin) for Teams Android devices, " +
          "Teams phones, and Teams panels. These devices rely on device code flow for initial setup.",
        impactedResources: [
          "Teams Rooms on Android",
          "Teams phones",
          "Teams panels",
          "Remote device sign-in scenarios",
        ],
      };
    },
    severity: "medium",
    docUrl:
      "https://learn.microsoft.com/microsoftteams/rooms/supported-ca-and-compliance-policies",
    remediation:
      "Exclude Teams device resource accounts from the device code flow blocking policy, " +
      "or create the block policy with a device filter that excludes Teams Android devices.",
  },

  // ═══════════════════════════════════════════════════════════════════════
  // SIGN-IN FREQUENCY
  // ═══════════════════════════════════════════════════════════════════════
  {
    id: "signin-freq-teams-rooms",
    title: "Sign-in Frequency: Causes Teams Rooms periodic sign-out",
    appliesWhen: "Policy uses sign-in frequency session control for all users",
    requirement:
      "Teams Rooms and Teams panels do NOT support sign-in frequency session controls. " +
      "Enabling sign-in frequency causes devices to periodically sign out, disrupting meetings.",
    detect: (policy) => {
      if (!isActivePolicy(policy)) return null;
      if (!targetsAllUsers(policy)) return null;

      const sif = policy.sessionControls?.signInFrequency;
      if (!sif?.isEnabled) return null;

      // Check if targeting all apps or M365 services
      if (targetsAllApps(policy)) {
        return {
          detail:
            `Policy enforces sign-in frequency (${sif.value} ${sif.type}) for all users. ` +
            "Teams Rooms, Teams phones, and Teams panels do NOT support this. " +
            "These devices will periodically sign out, disrupting scheduled meetings and room availability.",
          impactedResources: [
            "Teams Rooms on Windows",
            "Teams Rooms on Android",
            "Teams phones",
            "Teams panels",
          ],
        };
      }
      return null;
    },
    severity: "medium",
    docUrl:
      "https://learn.microsoft.com/microsoftteams/rooms/supported-ca-and-compliance-policies",
    remediation:
      "Exclude Teams Rooms and shared device resource accounts from sign-in frequency policies. " +
      "If you need sign-in frequency for admin roles, scope it specifically to admin roles instead of all users.",
  },

  // ═══════════════════════════════════════════════════════════════════════
  // MICROSOFT DEFENDER FOR ENDPOINT
  // ═══════════════════════════════════════════════════════════════════════
  {
    id: "defender-mobile-exclusion",
    title: "Defender Mobile: Must be excluded from restrictive CA policies",
    appliesWhen:
      "Broad block or restrictive CA policy targeting all apps",
    requirement:
      "The Microsoft Defender mobile app needs to constantly run in the background to report device security posture. " +
      "Restrictive CA policies (block policies, frequent sign-in, location blocks) can prevent Defender from reporting, " +
      "leading to devices appearing non-compliant.",
    detect: (policy) => {
      if (!isActivePolicy(policy)) return null;
      if (!targetsAllUsers(policy) || !targetsAllApps(policy)) return null;

      // Only check restrictive policies (block, location-based, sign-in frequency)
      const isRestrictive =
        hasBlockGrant(policy) ||
        (policy.conditions.locations &&
          policy.conditions.locations.includeLocations.length > 0 &&
          hasBlockGrant(policy));

      if (!isRestrictive) return null;

      const excludedApps =
        policy.conditions.applications.excludeApplications.map((a) =>
          a.toLowerCase()
        );
      const hasDefenderExclusion =
        excludedApps.includes(DEFENDER_ATP_XPLAT.toLowerCase()) &&
        excludedApps.includes(DEFENDER_TVM.toLowerCase());

      if (!hasDefenderExclusion) {
        return {
          detail:
            "Restrictive CA policy (block/location-based) targets all apps but does not exclude " +
            "Microsoft Defender for Endpoint mobile apps. This can prevent Defender from reporting " +
            "device posture, causing a compliance loop where devices appear non-compliant because " +
            "Defender can't communicate with its backend.",
          impactedResources: [
            `MicrosoftDefenderATP XPlat (${DEFENDER_ATP_XPLAT})`,
            `Microsoft Defender for Mobile TVM (${DEFENDER_TVM})`,
            "Mobile device compliance reporting",
          ],
        };
      }
      return null;
    },
    severity: "medium",
    docUrl:
      "https://learn.microsoft.com/defender-endpoint/mobile-resources-defender-endpoint#microsoft-defender-mobile-app-exclusion-from-conditional-access-ca-policies",
    remediation:
      `Exclude MicrosoftDefenderATP XPlat (${DEFENDER_ATP_XPLAT}) and ` +
      `Microsoft Defender for Mobile TVM (${DEFENDER_TVM}) from this policy. ` +
      "Create service principals for these apps if they don't exist, then add them to the exclusion list.",
  },

  // ═══════════════════════════════════════════════════════════════════════
  // AZURE VM SIGN-IN
  // ═══════════════════════════════════════════════════════════════════════
  {
    id: "azure-vm-signin-mfa",
    title:
      "Azure VM Sign-In: MFA via RDP requires special client support",
    appliesWhen:
      "Policy requires MFA or device compliance for all users and all cloud apps",
    requirement:
      "The Microsoft Azure Windows Virtual Machine Sign-In app (" +
      WINDOWS_CLOUD_LOGIN +
      ") requires the RDP client to supply the MFA claim. " +
      "Not all RDP clients or environments support interactive MFA. Windows Server devices cannot " +
      "satisfy device compliance rules when used as RDP clients. If Windows Hello for Business is " +
      "not deployed, Microsoft recommends excluding the Azure VM Sign-In app from MFA policies.",
    detect: (policy) => {
      if (!isActivePolicy(policy)) return null;
      if (!targetsAllUsers(policy) || !targetsAllApps(policy)) return null;
      if (!hasMfaGrant(policy) && !hasDeviceComplianceGrant(policy))
        return null;

      const excludedApps =
        policy.conditions.applications.excludeApplications.map((a) =>
          a.toLowerCase()
        );
      if (excludedApps.includes(WINDOWS_CLOUD_LOGIN.toLowerCase()))
        return null;

      return {
        detail:
          "Policy requires MFA or device compliance for all users and all cloud apps but does not exclude " +
          "the Microsoft Azure Windows Virtual Machine Sign-In app. Users connecting via RDP to Azure VMs " +
          "or Arc-enabled Windows Servers must supply MFA claims from the initiating device. " +
          "If Windows Hello for Business is not deployed, users may be unable to complete MFA during " +
          "RDP sessions. Windows Server devices cannot satisfy device compliance requirements as RDP clients.",
        impactedResources: [
          `Microsoft Azure Windows Virtual Machine Sign-In (${WINDOWS_CLOUD_LOGIN})`,
          "RDP connections to Azure VMs",
          "RDP connections to Arc-enabled Windows Servers",
          "Windows Server RDP client devices (device compliance unsupported)",
        ],
      };
    },
    severity: "medium",
    docUrl:
      "https://learn.microsoft.com/entra/identity/devices/howto-vm-sign-in-azure-ad-windows#missing-application",
    remediation:
      "If Windows Hello for Business is not deployed, exclude the Microsoft Azure Windows " +
      `Virtual Machine Sign-In app (${WINDOWS_CLOUD_LOGIN}) from MFA and device compliance policies. ` +
      "Alternatively, ensure all RDP clients support Windows Hello for Business or FIDO2 security " +
      "keys for MFA completion.",
  },

  // ═══════════════════════════════════════════════════════════════════════
  // CONTINUOUS ACCESS EVALUATION
  // ═══════════════════════════════════════════════════════════════════════
  {
    id: "cae-disabled",
    title: "CAE Disabled: Reduces real-time policy enforcement",
    appliesWhen: "Policy explicitly disables Continuous Access Evaluation",
    requirement:
      "Continuous access evaluation (CAE) enables real-time revocation of access tokens. " +
      "Disabling CAE means token revocation relies on token expiry (up to 1 hour), " +
      "creating a window of vulnerability after a security event.",
    detect: (policy) => {
      if (!isActivePolicy(policy)) return null;

      const cae = policy.sessionControls?.continuousAccessEvaluation;
      if (cae && cae.mode === "disabled") {
        return {
          detail:
            "Policy explicitly disables Continuous Access Evaluation (CAE). " +
            "This means access tokens remain valid for up to 1 hour after a security event " +
            "(user disabled, password changed, location change). Real-time token revocation is lost.",
          impactedResources: [
            "Real-time user session revocation",
            "Location-based policy enforcement",
            "Risk-based session termination",
          ],
        };
      }
      return null;
    },
    severity: "high",
    docUrl:
      "https://learn.microsoft.com/entra/identity/conditional-access/concept-continuous-access-evaluation",
    remediation:
      "Remove the CAE disable setting unless strict real-time evaluation is causing issues. " +
      "CAE is auto-enabled and should remain active for security. " +
      "Disabling only works when targeting All resources with no conditions.",
  },

  // ═══════════════════════════════════════════════════════════════════════
  // ADMIN SIGN-IN FREQUENCY ON INDIVIDUAL SERVICES
  // ═══════════════════════════════════════════════════════════════════════
  {
    id: "signin-freq-individual-services",
    title: "Sign-in Frequency: Targeting individual M365 services breaks Teams",
    appliesWhen:
      "Sign-in frequency is applied to specific M365 services rather than all apps",
    requirement:
      "Configuring sign-in frequency on individual Microsoft 365 services (Exchange, SharePoint, Teams) " +
      "can interrupt or stop the Teams device sign-in flow. Use all-apps targeting or admin portal targeting instead.",
    detect: (policy) => {
      if (!isActivePolicy(policy)) return null;
      const sif = policy.sessionControls?.signInFrequency;
      if (!sif?.isEnabled) return null;

      const apps = policy.conditions.applications.includeApplications;
      if (apps.includes("All")) return null; // All apps is fine

      // Check if targeting individual M365 service IDs
      const m365Services = [EXCHANGE_ONLINE, SHAREPOINT_ONLINE, TEAMS_SERVICE];
      const targetsIndividualM365 = apps.some((a) =>
        m365Services.includes(a)
      );

      if (targetsIndividualM365) {
        return {
          detail:
            "Sign-in frequency is configured on individual Microsoft 365 services rather than " +
            "all cloud apps. Microsoft documents that this can interrupt or stop the Teams device " +
            "sign-in flow and is not supported.",
          impactedResources: [
            "Teams sign-in flow",
            "Teams Rooms devices",
            "Teams desktop/mobile clients",
          ],
        };
      }
      return null;
    },
    severity: "medium",
    docUrl:
      "https://learn.microsoft.com/microsoftteams/rooms/supported-ca-and-compliance-policies",
    remediation:
      "Change the sign-in frequency policy to target all cloud apps or use Microsoft Admin Portals " +
      "as the target resource instead of individual M365 services.",
  },

  // ═══════════════════════════════════════════════════════════════════════
  // RESILIENCE DEFAULTS
  // ═══════════════════════════════════════════════════════════════════════
  {
    id: "resilience-disabled-impact",
    title: "Resilience Defaults Disabled: Users blocked during outages",
    appliesWhen: "Policy disables resilience defaults",
    requirement:
      "Disabling resilience defaults means users are denied access when existing sessions expire " +
      "during an Entra ID outage. This should only be done for high-security scenarios.",
    detect: (policy) => {
      if (!isActivePolicy(policy)) return null;
      if (!policy.sessionControls?.disableResilienceDefaults) return null;

      const scope = targetsAllUsers(policy) ? "ALL users" : "targeted users";
      return {
        detail:
          `Policy disables resilience defaults for ${scope}. During an Entra ID outage, ` +
          "users whose sessions expire will be DENIED access until the service recovers. " +
          "This could block productivity for hours during a major outage.",
        impactedResources: [
          "All users covered by this policy during Entra ID outages",
          "Business continuity during identity service disruptions",
        ],
      };
    },
    severity: "medium",
    docUrl:
      "https://learn.microsoft.com/entra/identity/conditional-access/resilience-defaults",
    remediation:
      "Only disable resilience defaults if your organization requires strict real-time policy " +
      "evaluation (e.g., regulated industries). For most organizations, keep resilience defaults enabled.",
  },

  // ═══════════════════════════════════════════════════════════════════════
  // ALL RESOURCES BEHAVIOR CHANGE (March 2026)
  // ═══════════════════════════════════════════════════════════════════════
  {
    id: "all-resources-exclusion-change",
    title: "All Resources: Low-privilege scope exemption ending March 2026",
    appliesWhen:
      'Policy targets "All resources" (All cloud apps) with app exclusions',
    requirement:
      "Microsoft is removing the legacy behavior where certain low-privilege scopes " +
      "(User.Read, openid, profile, email) were auto-excluded from All Resources policies " +
      "when app exclusions existed. Starting March 2026, these scopes WILL be enforced.",
    detect: (policy) => {
      if (!isActivePolicy(policy)) return null;
      if (!targetsAllApps(policy)) return null;

      const hasAppExclusions =
        policy.conditions.applications.excludeApplications.length > 0;
      if (!hasAppExclusions) return null;

      return {
        detail:
          'This policy targets "All cloud apps" with app exclusions. Microsoft is changing behavior ' +
          "starting March 2026: previously auto-excluded low-privilege scopes (User.Read, openid, profile, " +
          "email, offline_access) will now be enforced. Users who could previously access apps without CA " +
          "challenges may now be prompted. Review sign-in logs for impact.",
        impactedResources: [
          "Apps using User.Read scope",
          "Apps using openid/profile scopes",
          "Native clients and SPAs with basic Graph access",
        ],
      };
    },
    severity: "high",
    docUrl:
      "https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-cloud-apps#conditional-access-for-all-resources",
    remediation:
      "Review all policies targeting 'All cloud apps' with exclusions. Test the impact using report-only mode. " +
      "Consider removing app exclusions from the policy and creating separate targeted policies instead.",
  },

  // ═══════════════════════════════════════════════════════════════════════
  // DIRECTORY SYNC ACCOUNT / ENTRA CONNECT
  // ═══════════════════════════════════════════════════════════════════════
  {
    id: "dirsync-account-mfa",
    title: "Directory Sync Account: Entra Connect v2.5.79+ supports app-based auth",
    appliesWhen:
      "MFA policy targeting All Users excludes a Directory Synchronization Accounts role or service account",
    requirement:
      "Prior to Entra Connect v2.5.79, organizations excluded Directory Synchronization Accounts " +
      "from MFA policies because the sync engine used a service account that could not perform MFA. " +
      "Starting with Entra Connect v2.5.79 (released 2025), application-based authentication is supported, " +
      "eliminating the need for this exclusion. If your organization has upgraded to v2.5.79+, the " +
      "Directory Sync account exclusion should be reviewed and potentially removed to close this gap.",
    detect: (policy) => {
      if (!isActivePolicy(policy)) return null;
      if (!targetsAllUsers(policy)) return null;
      if (!hasMfaGrant(policy)) return null;

      // Directory Synchronization Accounts role ID
      const DIRSYNC_ROLE = "d29b2b05-8046-44ba-8758-1e26182fcf32";

      const excludedRoles = policy.conditions.users.excludeRoles ?? [];
      const hasDirSyncExclusion = excludedRoles.includes(DIRSYNC_ROLE);

      // Also check for excluded users/groups that might be sync accounts
      // by looking at the display name pattern (we can't resolve names here,
      // but we flag if there are role exclusions matching the DirSync role)
      if (!hasDirSyncExclusion) return null;

      return {
        detail:
          "This MFA policy excludes the Directory Synchronization Accounts role. " +
          "If your organization is running Entra Connect v2.5.79 or later, this exclusion " +
          "may no longer be necessary — v2.5.79 introduced application-based authentication " +
          "for the sync engine, meaning the sync service principal can authenticate without " +
          "a traditional user account. Review your Entra Connect version and migrate to " +
          "app-based auth to eliminate this MFA gap.",
        impactedResources: [
          "Directory Synchronization Accounts role",
          "Entra Connect sync service account",
          "Hybrid identity sync pipeline",
        ],
      };
    },
    severity: "medium",
    docUrl:
      "https://learn.microsoft.com/entra/identity/hybrid/connect/reference-connect-version-history",
    remediation:
      "Check your Entra Connect version (Azure Portal → Entra Connect → Version or see the " +
      "[version history](https://learn.microsoft.com/entra/identity/hybrid/connect/reference-connect-version-history)). " +
      "If running v2.5.79+, configure application-based authentication for the sync engine " +
      "and remove the Directory Synchronization Accounts role exclusion from your MFA policies. " +
      "If still on an older version, upgrade to v2.5.79+ and then migrate to app-based auth.",
  },
  // ═══════════════════════════════════════════════════════════════════════
  // EXTERNAL AUTHENTICATION METHOD (EAM) — DUO, THIRD-PARTY MFA
  // ═══════════════════════════════════════════════════════════════════════
  {
    id: "eam-external-user-impact",
    title: "External Authentication Method (EAM): May block guests and external vendors",
    appliesWhen:
      "MFA policy uses External Authentication Methods via custom auth factors or Authentication Strength " +
      "policies containing external method combinations (e.g. Cisco DUO EAM) and targets All Users or admin roles",
    requirement:
      "When a Conditional Access policy requires an External Authentication Method (EAM) like Cisco DUO, " +
      "RSA SecurID, or another third-party MFA provider, guest users, B2B collaborators, and external " +
      "service providers will be unable to fulfill the EAM claim because they are not enrolled in the " +
      "organization's third-party MFA solution. This effectively blocks external access even though " +
      "standard Entra ID MFA would have been sufficient. Microsoft recommends using authentication " +
      "strength policies with Entra ID native methods for broad user scopes, and scoping EAM " +
      "requirements only to internal users who are enrolled in the third-party provider.",
    detect: (policy, authStrengthPolicies) => {
      if (!isActivePolicy(policy)) return null;
      if (!targetsAllUsers(policy) && !hasAdminRoles(policy)) return null;

      // --- Detection path 1: Legacy custom authentication factors (old Custom Controls) ---
      const customFactors = policy.grantControls?.customAuthenticationFactors ?? [];
      const hasCustomFactors = customFactors.length > 0;

      // --- Detection path 2: Authentication Strength containing external methods ---
      let hasEamViaAuthStrength = false;
      let authStrengthName = "";
      let externalMethods: string[] = [];

      const authStrengthRef = policy.grantControls?.authenticationStrength;
      if (authStrengthRef?.id && authStrengthPolicies) {
        const asp = authStrengthPolicies.get(authStrengthRef.id);
        if (asp) {
          // External Authentication Methods appear in allowedCombinations as entries
          // containing "externalAuthenticationMethodConfiguration" (EAM identifier)
          externalMethods = (asp.allowedCombinations ?? []).filter((combo) =>
            combo.toLowerCase().includes("externalauthenticationmethod")
          );
          if (externalMethods.length > 0) {
            hasEamViaAuthStrength = true;
            authStrengthName = asp.displayName || authStrengthRef.displayName || "Unknown";
          }
        }
      }

      if (!hasCustomFactors && !hasEamViaAuthStrength) return null;

      // Check if guests/external users are NOT excluded
      const users = policy.conditions.users;
      const excludesGuests = users.excludeGuestsOrExternalUsers != null &&
        Object.keys(users.excludeGuestsOrExternalUsers as Record<string, unknown>).length > 0;

      // Build detail message based on detection path
      const eamSource = hasEamViaAuthStrength
        ? `an Authentication Strength policy ("${authStrengthName}") that includes External Authentication Method combinations: ${externalMethods.join(", ")}`
        : "custom authentication factors (legacy Custom Controls)";

      const detail = excludesGuests
        ? `This policy requires ${eamSource} for MFA. While guest users ` +
          "appear to be excluded, verify that ALL external identities are covered by the exclusion — " +
          "B2B direct connect users, service provider accounts, and cross-tenant sync accounts may " +
          "still be impacted if not explicitly excluded."
        : `This policy requires ${eamSource} for MFA and targets ` +
          "All Users without excluding guest or external users. External users (B2B guests, service " +
          "providers, managed service accounts) cannot enroll in your organization's third-party MFA " +
          "provider and will be blocked from accessing resources. Consider excluding external user " +
          "types or creating a separate policy for guests that uses Entra ID native MFA.";

      return {
        detail,
        impactedResources: [
          "B2B guest users",
          "External service providers and vendors",
          "Cross-tenant collaboration partners",
          "Managed service provider (MSP) accounts",
          ...(excludesGuests ? ["Verify: B2B direct connect and cross-tenant sync accounts"] : []),
          ...(hasEamViaAuthStrength ? [`Auth Strength: "${authStrengthName}" — ${externalMethods.length} external method combination(s)`] : []),
        ],
      };
    },
    severity: "high",
    docUrl:
      "https://learn.microsoft.com/entra/identity/authentication/how-to-authentication-external-method-manage",
    remediation:
      "Option 1: Exclude guest and external user types from the EAM policy and create a separate " +
      "CA policy for external users that requires standard Entra ID MFA. " +
      "Option 2: Use an authentication strength policy that accepts both the EAM and Entra ID " +
      "native MFA methods, allowing external users to satisfy the requirement with Microsoft MFA. " +
      "Option 3: Scope the EAM requirement to a security group containing only internal users " +
      "enrolled in the third-party MFA provider.",
  },

  // ─── Approved Client App Grant Retirement ─────────────────────────────────

  {
    id: "approved-client-app-retirement",
    title:
      "Approved Client App grant retiring — migrate to App Protection Policy",
    appliesWhen:
      "Policy uses the 'Require approved client app' grant control without the 'Require app protection policy' control",
    requirement:
      "Microsoft is retiring the 'Require approved client app' grant control in early March 2026. " +
      "Policies must transition to 'Require application protection policy' or use both controls with an OR operator.",
    detect: (policy) => {
      const grants = policy.grantControls?.builtInControls ?? [];
      const hasApprovedApp = grants.includes("approvedApplication");
      const hasAppProtection = grants.includes("compliantApplication");

      if (!hasApprovedApp) return null;

      // Only flag if using approved app without app protection policy
      if (hasAppProtection && policy.grantControls?.operator === "OR") {
        return null; // Already using both with OR — compliant migration path
      }

      if (hasAppProtection && policy.grantControls?.operator === "AND") {
        return {
          detail:
            `Policy "${policy.displayName}" uses both 'Require approved client app' AND 'Require app protection policy' ` +
            `with the AND operator. After the retirement, change the operator to OR so that app protection policy alone ` +
            `is sufficient, as approved client app will stop being enforced.`,
          impactedResources: [
            "Mobile device users on iOS and Android",
            "Users accessing M365 apps from mobile devices",
          ],
        };
      }

      return {
        detail:
          `Policy "${policy.displayName}" uses only the 'Require approved client app' grant control, ` +
          `which is being retired in early March 2026. After retirement, this policy will no longer enforce ` +
          `app-level controls on mobile devices, leaving them unprotected. Migrate to 'Require application ` +
          `protection policy' before the deadline.`,
        impactedResources: [
          "Mobile device users on iOS and Android",
          "Users accessing M365 apps from mobile devices",
          "Unmanaged BYOD devices",
        ],
      };
    },
    severity: "critical",
    docUrl:
      "https://learn.microsoft.com/entra/identity/conditional-access/migrate-approved-client-app",
    remediation:
      "Replace 'Require approved client app' with 'Require application protection policy' in the grant controls. " +
      "If you need a transition period, use both controls with the OR operator so either grant satisfies the requirement. " +
      "For new policies, only use 'Require application protection policy'.",
  },
];

// ─── Run all exclusion checks against a single policy ────────────────────────

export interface ExclusionFinding {
  exclusion: DocumentedExclusion;
  result: ExclusionCheckResult;
  policyId: string;
  policyName: string;
}

export function checkPolicyExclusions(
  policy: ConditionalAccessPolicy,
  authStrengthPolicies?: Map<string, AuthenticationStrengthPolicy>
): ExclusionFinding[] {
  const findings: ExclusionFinding[] = [];

  for (const exclusion of DOCUMENTED_EXCLUSIONS) {
    const result = exclusion.detect(policy, authStrengthPolicies);
    if (result) {
      findings.push({
        exclusion,
        result,
        policyId: policy.id,
        policyName: policy.displayName,
      });
    }
  }

  return findings;
}

export function checkAllPoliciesExclusions(
  policies: ConditionalAccessPolicy[],
  authStrengthPolicies?: Map<string, AuthenticationStrengthPolicy>
): ExclusionFinding[] {
  return policies.flatMap((p) => checkPolicyExclusions(p, authStrengthPolicies));
}
