/**
 * Enterprise App Descriptions
 *
 * Plain-English explanations of what each Microsoft first-party app does
 * and why an admin might commonly exclude it from Conditional Access.
 *
 * These descriptions add context to findings so admins understand the
 * business justification (or risk) of each exclusion.
 */

export interface AppDescription {
  appId: string;
  displayName: string;
  /** What the app does in plain English */
  purpose: string;
  /** Why it's commonly excluded from CA (if applicable) */
  commonExclusionReason: string;
  /** Risk level of excluding this app */
  exclusionRisk: "critical" | "high" | "medium" | "low";
}

const APP_DESCRIPTIONS: AppDescription[] = [
  // ─── Identity & Directory ──────────────────────────────────────────────────
  {
    appId: "00000002-0000-0000-c000-000000000000",
    displayName: "Windows Azure Active Directory",
    purpose:
      "The legacy Azure AD Graph API. Used by older applications to read and write directory data such as users, groups, and applications.",
    commonExclusionReason:
      "Sometimes excluded to allow legacy apps that haven't migrated to Microsoft Graph. Excluding it leaks basic profile scopes (User.Read, openid, profile, email) for ALL users.",
    exclusionRisk: "critical",
  },
  {
    appId: "00000003-0000-0000-c000-000000000000",
    displayName: "Microsoft Graph",
    purpose:
      "The unified API for all Microsoft 365 services. Used by virtually every Microsoft and third-party app to access mail, files, users, groups, Teams, and more.",
    commonExclusionReason:
      "Rarely has a valid exclusion reason. Excluding it leaks User.Read, People.Read, and OIDC scopes for all users — effectively bypassing the policy for basic profile access.",
    exclusionRisk: "critical",
  },
  {
    appId: "0000000c-0000-0000-c000-000000000000",
    displayName: "Microsoft App Access Panel",
    purpose:
      "The My Apps portal (myapps.microsoft.com). Users use it to discover and launch their assigned cloud applications.",
    commonExclusionReason:
      "Excluded to allow users to browse their app catalog without triggering MFA. Low risk since it only shows app links — actual app access still enforces CA on the target app.",
    exclusionRisk: "low",
  },
  {
    appId: "2793995e-0a7d-40d7-bd35-6968ba142197",
    displayName: "My Apps",
    purpose:
      "The newer My Apps experience for discovering and launching assigned applications. Works alongside the App Access Panel.",
    commonExclusionReason:
      "Excluded for the same reason as App Access Panel — to let users see their app list without MFA. Launching an app still triggers the target app's CA policy.",
    exclusionRisk: "low",
  },
  {
    appId: "8c59ead7-d703-4a27-9e55-c96a0054c8d2",
    displayName: "My Profile",
    purpose:
      "The My Account portal (myaccount.microsoft.com). Users manage their profile, security info, devices, and privacy settings.",
    commonExclusionReason:
      "Excluded to allow users to update their security info or manage MFA methods without being blocked by CA. Without this exclusion, users may be unable to register MFA methods.",
    exclusionRisk: "medium",
  },
  // ─── Azure & Infrastructure ────────────────────────────────────────────────
  {
    appId: "797f4846-ba00-4fd7-ba43-dac1f8f63013",
    displayName: "Azure Resource Manager",
    purpose:
      "The management plane for all Azure resources. Every Azure portal, CLI, and PowerShell operation goes through ARM.",
    commonExclusionReason:
      "Excluded to allow automation/service accounts to manage Azure resources. This is high risk — an attacker with credentials could manage your entire Azure subscription.",
    exclusionRisk: "critical",
  },
  {
    appId: "c44b4083-3bb0-49c1-b47d-974e53cbdf3c",
    displayName: "Azure Portal",
    purpose:
      "The Azure management portal (portal.azure.com). Provides GUI access to manage all Azure services.",
    commonExclusionReason:
      "Rarely excluded. Excluding it allows unauthenticated Azure portal access. Note: Azure Portal actually points to ARM, so CA on ARM covers the portal.",
    exclusionRisk: "critical",
  },
  {
    appId: "372140e0-b3b7-4226-8ef9-d57986796201",
    displayName: "Azure Windows VM Sign-In",
    purpose:
      "Enables Entra ID-based sign-in to Azure Windows VMs. Used when 'Login with Azure AD' extension is installed on VMs, allowing RDP sessions authenticated via Entra ID instead of local credentials.",
    commonExclusionReason:
      "Excluded from MFA policies because Azure VM RDP sign-in does not support interactive MFA prompts. " +
      "If MFA is required, users cannot complete the RDP login flow. Microsoft documents this as a known " +
      "limitation — exclude this app from MFA CA policies and rely on VM-level controls (NSG, Bastion, JIT) instead.",
    exclusionRisk: "medium",
  },
  // ─── Productivity & Office ─────────────────────────────────────────────────
  {
    appId: "00000002-0000-0ff1-ce00-000000000000",
    displayName: "Office 365 Exchange Online",
    purpose:
      "Exchange Online — email, calendars, and contacts. Used by Outlook, mobile mail apps, and third-party email clients.",
    commonExclusionReason:
      "Excluded to allow legacy mail protocols (POP/IMAP) that don't support modern auth. Should use 'Block legacy auth' policy instead of excluding Exchange.",
    exclusionRisk: "high",
  },
  {
    appId: "00000003-0000-0ff1-ce00-000000000000",
    displayName: "Office 365 SharePoint Online",
    purpose:
      "SharePoint Online and OneDrive for Business. Stores all Microsoft 365 files, team sites, and document libraries.",
    commonExclusionReason:
      "Excluded to allow file-sync clients or third-party integrations. High risk as it exposes all corporate files.",
    exclusionRisk: "high",
  },
  {
    appId: "cc15fd57-2c6c-4117-a88c-83b1d56b4bbe",
    displayName: "Microsoft Teams Services",
    purpose:
      "Microsoft Teams — chat, meetings, calling, and collaboration. The hub for teamwork in Microsoft 365.",
    commonExclusionReason:
      "Excluded to prevent MFA prompts during meetings or allow conference room devices. Consider using compliant device requirement instead.",
    exclusionRisk: "high",
  },
  // ─── Device Management ─────────────────────────────────────────────────────
  {
    appId: "0000000a-0000-0000-c000-000000000000",
    displayName: "Microsoft Intune",
    purpose:
      "Mobile device management (MDM) and mobile application management (MAM). Manages device compliance, app deployment, and configuration.",
    commonExclusionReason:
      "Excluded to allow device enrollment before compliance can be evaluated. Without this exclusion, devices can't enroll because they're not yet compliant — a chicken-and-egg problem.",
    exclusionRisk: "medium",
  },
  {
    appId: "d4ebce55-015a-49b5-a083-c84d1797ae8c",
    displayName: "Microsoft Intune Enrollment",
    purpose:
      "Handles the device enrollment flow for Intune. Used during Autopilot, BYOD enrollment, and device registration.",
    commonExclusionReason:
      "Excluded to allow initial device enrollment before compliance policies apply. This is a common and generally accepted exclusion for Intune deployments.",
    exclusionRisk: "low",
  },
  {
    appId: "0000000f-0000-0000-c000-000000000000",
    displayName: "Microsoft Intune API",
    purpose:
      "The Intune management API. Used by Intune admin tools, PowerShell modules, and Graph API calls for device management.",
    commonExclusionReason:
      "Excluded to allow automation scripts and management tools to interact with Intune. Consider service principal auth with limited scope instead.",
    exclusionRisk: "medium",
  },
  // ─── Security & Compliance ─────────────────────────────────────────────────
  {
    appId: "fc780465-2017-40d4-a0c5-307022471b92",
    displayName: "WindowsDefenderATP",
    purpose:
      "Microsoft Defender for Endpoint (MDE). Provides endpoint detection and response, threat hunting, and vulnerability management.",
    commonExclusionReason:
      "Excluded to allow Defender agents to report telemetry without MFA. Generally low risk since it's machine-to-service communication, but verify it's the agent — not portal access.",
    exclusionRisk: "medium",
  },
  {
    appId: "ea890292-c8c8-4433-b5ea-b09d0668e1a6",
    displayName: "Azure Credential Configuration Endpoint Service",
    purpose:
      "Manages federated identity credentials and certificate configurations for workload identities (managed identities, service principals).",
    commonExclusionReason:
      "Excluded to allow workload identity federation to function. This service is used by CI/CD pipelines (GitHub Actions, Azure DevOps) for keyless authentication.",
    exclusionRisk: "low",
  },
  // ─── Information Protection ────────────────────────────────────────────────
  {
    appId: "00000012-0000-0000-c000-000000000000",
    displayName: "Microsoft Rights Management Services",
    purpose:
      "Azure Information Protection (AIP) and sensitivity labels. Encrypts and protects documents and emails using Rights Management. Powers the protection in Office apps, Outlook, and SharePoint.",
    commonExclusionReason:
      "Excluded to prevent MFA prompts when opening encrypted documents or emails. When RMS is protected by MFA CA, every encrypted file/email triggers an MFA prompt, and messages are wrapped as rpmsg attachments — breaking the reading experience.",
    exclusionRisk: "low",
  },
  // ─── Approval & Workflows ─────────────────────────────────────────────────
  {
    appId: "65d91a3d-ab74-42e6-8a2f-0add61688c74",
    displayName: "Microsoft Approval Management",
    purpose:
      "Handles approval workflows across Microsoft 365 — including Teams Approvals, Power Automate approvals, and SharePoint content approvals.",
    commonExclusionReason:
      "Excluded to allow approval notifications and responses to flow without MFA interruption. Blocking this can prevent approval workflows from completing.",
    exclusionRisk: "low",
  },
  // ─── Reporting & Analytics ─────────────────────────────────────────────────
  {
    appId: "1b912ec3-a9dd-4c4d-a53e-76aa7adb28d7",
    displayName: "AADReporting",
    purpose:
      "The Entra ID (Azure AD) reporting backend. Powers sign-in logs, audit logs, and usage reports in the Entra admin center.",
    commonExclusionReason:
      "Excluded to allow monitoring tools and SIEM integrations to pull logs without triggering CA. The Graph API calls for reporting data go through this service principal.",
    exclusionRisk: "low",
  },
  // ─── Power Platform ───────────────────────────────────────────────────────
  {
    appId: "00000007-0000-0000-c000-000000000000",
    displayName: "Dataverse",
    purpose:
      "The data platform for Microsoft Power Platform. Stores data for Power Apps, Power Automate, and Dynamics 365.",
    commonExclusionReason:
      "Excluded to allow Power Platform flows and apps to access data. Consider using service principal connections instead of user delegation.",
    exclusionRisk: "medium",
  },
  {
    appId: "7df0a125-d3be-4c96-aa54-591f83ff541c",
    displayName: "Microsoft Flow Service",
    purpose:
      "Power Automate (formerly Microsoft Flow). Runs automated workflows across hundreds of connectors including SharePoint, Teams, and third-party services.",
    commonExclusionReason:
      "Excluded to allow cloud flows to run on behalf of users without interactive MFA. Flows using user connections will fail if this service is blocked.",
    exclusionRisk: "medium",
  },
  // ─── Developer Tools ──────────────────────────────────────────────────────
  {
    appId: "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
    displayName: "Microsoft Azure CLI",
    purpose:
      "The Azure command-line interface. Used by DevOps teams and administrators for scripting, automation, and Azure resource management.",
    commonExclusionReason:
      "Excluded to allow automation scripts to authenticate. Has 462 resources it can access. Prefer managed identity or service principal auth for automation instead of excluding.",
    exclusionRisk: "high",
  },
  {
    appId: "1950a258-227b-4e31-a9cf-717495945fc2",
    displayName: "Microsoft Azure PowerShell",
    purpose:
      "Azure PowerShell module. Used for Azure administration and automation with the broadest resource access of any non-FOCI app (649 resources).",
    commonExclusionReason:
      "Excluded to allow PowerShell automation. Very high risk — this app can access 649 resources. Use service principal or managed identity for automation instead.",
    exclusionRisk: "critical",
  },
  {
    appId: "1b730954-1685-4b74-9bfd-dac224a7b894",
    displayName: "Azure Active Directory PowerShell",
    purpose:
      "The legacy AzureAD PowerShell module. Used for directory operations like user/group management. Being deprecated in favor of Microsoft Graph PowerShell.",
    commonExclusionReason:
      "Excluded for legacy automation scripts. Should migrate to Microsoft Graph PowerShell SDK and use service principal auth.",
    exclusionRisk: "high",
  },
  {
    appId: "aebc6443-996d-45c2-90f0-388ff96faa56",
    displayName: "Visual Studio Code",
    purpose:
      "VS Code IDE. The Azure extensions authenticate using this app ID to access Azure resources, repos, and Copilot.",
    commonExclusionReason:
      "Excluded to allow developers to use Azure extensions. Consider requiring MFA but allowing it — VS Code supports modern auth including MFA.",
    exclusionRisk: "medium",
  },
  // ─── Sync & Hybrid Identity ───────────────────────────────────────────────
  {
    appId: "cb1056e2-e479-49de-ae31-7812af012ed8",
    displayName: "Microsoft Azure Active Directory Connect",
    purpose:
      "Entra Connect (formerly AAD Connect). Synchronizes on-premises Active Directory with Entra ID — users, groups, passwords, and device objects.",
    commonExclusionReason:
      "Excluded to allow the sync engine to operate. The sync service account must authenticate to Entra ID without interactive MFA. Use a dedicated service account with limited exclusion scope.",
    exclusionRisk: "medium",
  },
  // ─── Windows & OS Services ────────────────────────────────────────────────
  {
    appId: "dd762716-544d-4aeb-a526-687b73838a22",
    displayName: "Microsoft Device Registration Client",
    purpose:
      "Handles device registration and Entra ID join. Required for Workplace Join, Hybrid Entra ID Join, and Autopilot enrollment.",
    commonExclusionReason:
      "Excluded to allow devices to register with Entra ID. Only MFA grant control works for this app — location-based CA and compliant device requirements are bypassed by design (MSRC VULN-153600).",
    exclusionRisk: "medium",
  },
  {
    appId: "de50c81f-5f80-4771-b66b-cebd28ccdfc1",
    displayName: "Device Management Client",
    purpose:
      "The broadest service principal in any tenant with access to 1,590 resources. Used internally by Windows for device management operations.",
    commonExclusionReason:
      "Excluded for device management flows. Extremely high risk due to 1,590 resource access — this is the broadest app registration in any Microsoft tenant.",
    exclusionRisk: "critical",
  },
  {
    appId: "1b3c667f-cde3-4090-b60b-3d2abd0117f0",
    displayName: "Windows Spotlight",
    purpose:
      "Delivers lock screen images, tips, and suggestions on Windows devices. Contacts Microsoft services for personalized content.",
    commonExclusionReason:
      "Excluded because the Windows lock screen makes background calls that fail with MFA. Low sensitivity — only fetches display content.",
    exclusionRisk: "low",
  },
  // ─── Security Copilot ─────────────────────────────────────────────────────
  {
    appId: "826870f9-9fbb-4f23-81b8-3a957080dfa2",
    displayName: "Security Copilot",
    purpose:
      "Microsoft Security Copilot. AI assistant for security operations — threat investigation, incident response, and KQL query generation.",
    commonExclusionReason:
      "Excluded to allow SOC analysts to use Copilot without MFA interruptions during incident response. Consider allowing with compliant device requirement instead.",
    exclusionRisk: "high",
  },
  // ─── Device Registration Service (resource) ──────────────────────────────
  {
    appId: "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9",
    displayName: "Device Registration Service",
    purpose:
      "The backend service for Entra ID device registration. Processes device join, registration, and Autopilot operations.",
    commonExclusionReason:
      "Excluded because location-based CA and compliant device requirements don't work for this resource — only MFA can protect it (Microsoft confirmed by-design).",
    exclusionRisk: "medium",
  },
];

export const APP_DESCRIPTION_MAP = new Map<string, AppDescription>(
  APP_DESCRIPTIONS.map((a) => [a.appId.toLowerCase(), a])
);

/**
 * Get a plain-English description for an app, falling back to service principal
 * type info if the app isn't in our database.
 */
export function getAppDescription(
  appId: string,
  fallbackName?: string,
): { purpose: string; commonExclusionReason: string; exclusionRisk: string } | null {
  return APP_DESCRIPTION_MAP.get(appId.toLowerCase()) ?? null;
}
