/**
 * Conditional Access Bypass Database
 * Source: Fabian Bader & Dirk-jan Mollema research (TROOPERS25)
 *         https://cloudbrothers.info/en/conditional-access-bypasses/
 *         https://entrascopes.com
 *
 * Documents known resources, scopes, and app combinations that bypass
 * specific Conditional Access grant controls.
 */

// ─── Resources Completely Excluded from CA ───────────────────────────────────
// These resources NEVER have CA enforced (status: notApplied in SigninLogs)
// Ref: Fabian Bader - "Resources completely excluded from Conditional Access"

export interface CAImmuneResource {
  resourceId: string;
  displayName: string;
  risk: "high" | "medium" | "low";
  description: string;
}

export const CA_IMMUNE_RESOURCES: CAImmuneResource[] = [
  {
    resourceId: "26a4ae64-5862-427f-a9b0-044e62572a4f",
    displayName: "Microsoft Intune Checkin",
    risk: "medium",
    description:
      "Device check-in for Intune. CA always shows notApplied. Can be used for password verification without triggering MFA failure logs.",
  },
  {
    resourceId: "04436913-cf0d-4d2a-9cc6-2ffe7f1d3d1c",
    displayName: "Windows Notification Service",
    risk: "low",
    description: "Push notification service. CA enforcement not possible.",
  },
  {
    resourceId: "0a5f63c0-b750-4f38-a71c-4fc0d58b89e2",
    displayName: "Microsoft Mobile Application Management",
    risk: "medium",
    description:
      "MAM policy service. CA always notApplied. Any app with pre-consented permissions can access without CA.",
  },
  {
    resourceId: "1f5530b3-261a-47a9-b357-ded261e17918",
    displayName: "Azure Multi-Factor Auth Connector",
    risk: "medium",
    description:
      "MFA connector resource. Ironically cannot be protected by CA MFA requirement. Can be used for password spraying without 50074 errors.",
  },
  {
    resourceId: "c2ada927-a9e2-4564-aae2-70775a2fa0af",
    displayName: "OCaaS Client Interaction Service",
    risk: "low",
    description: "Office client interaction service. CA enforcement not possible.",
  },
  {
    resourceId: "ff9ebd75-fe62-434a-a6ce-b3f0a8592eaf",
    displayName: "Authenticator App",
    risk: "medium",
    description:
      "Authenticator app resource. CA always notApplied. Required for passwordless flows.",
  },
];

// ─── Known CA Bypass App IDs (Non-FOCI) ──────────────────────────────────────
// Apps with known CA bypasses that are NOT in the FOCI family

export interface CABypassApp {
  appId: string;
  displayName: string;
  isPublicClient: boolean;
  caBypassCount: number;
  description: string;
}

export const CA_BYPASS_APPS: CABypassApp[] = [
  {
    appId: "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
    displayName: "Microsoft Azure CLI",
    isPublicClient: true,
    caBypassCount: 1,
    description: "Azure CLI - 462 resources. Public client with CA bypass capability.",
  },
  {
    appId: "1950a258-227b-4e31-a9cf-717495945fc2",
    displayName: "Microsoft Azure PowerShell",
    isPublicClient: true,
    caBypassCount: 1,
    description: "Azure PowerShell - 649 resources. Broadest resource access of any non-FOCI app.",
  },
  {
    appId: "1b730954-1685-4b74-9bfd-dac224a7b894",
    displayName: "Azure Active Directory PowerShell",
    isPublicClient: true,
    caBypassCount: 1,
    description: "AAD PowerShell - 260 resources. Legacy module with broad directory access.",
  },
  {
    appId: "cb1056e2-e479-49de-ae31-7812af012ed8",
    displayName: "Microsoft Azure Active Directory Connect",
    isPublicClient: true,
    caBypassCount: 1,
    description: "AAD Connect - 262 resources. Hybrid identity sync with broad access.",
  },
  {
    appId: "aebc6443-996d-45c2-90f0-388ff96faa56",
    displayName: "Visual Studio Code",
    isPublicClient: true,
    caBypassCount: 1,
    description: "VS Code - 77 resources. IDE with Azure extension access.",
  },
  {
    appId: "fc0f3af4-6835-4174-b806-f7db311fd2f3",
    displayName: "Microsoft Intune Windows Agent",
    isPublicClient: true,
    caBypassCount: 1,
    description: "Intune agent - device enrollment bypasses compliant device requirement.",
  },
  {
    appId: "dd762716-544d-4aeb-a526-687b73838a22",
    displayName: "Microsoft Device Registration Client",
    isPublicClient: true,
    caBypassCount: 1,
    description: "Device registration - bypasses location-based CA. Only MFA can protect.",
  },
  {
    appId: "de50c81f-5f80-4771-b66b-cebd28ccdfc1",
    displayName: "Device Management Client",
    isPublicClient: true,
    caBypassCount: 0,
    description: "Device Management - 1590 resources! Broadest resource access of ANY app.",
  },
  {
    appId: "a672d62c-fc7b-4e81-a576-e60dc46e951d",
    displayName: "Microsoft Power Query for Excel",
    isPublicClient: true,
    caBypassCount: 1,
    description: "Power Query - 70 resources. Data connection with broad access.",
  },
  {
    appId: "cf710c6e-dfcc-4fa8-a093-d47294e44c66",
    displayName: "Azure Analysis Services Client",
    isPublicClient: true,
    caBypassCount: 1,
    description: "Analysis Services - 15 resources.",
  },
  {
    appId: "c58637bb-e2e1-4312-8a00-04b5ffcd3403",
    displayName: "SharePoint Online Client Extensibility",
    isPublicClient: true,
    caBypassCount: 1,
    description: "SPO extensibility - 22 resources.",
  },
  {
    appId: "268761a2-03f3-40df-8a8b-c3db24145b6b",
    displayName: "Universal Store Native Client",
    isPublicClient: true,
    caBypassCount: 1,
    description: "Windows Store - 21 resources.",
  },
  {
    appId: "1b3c667f-cde3-4090-b60b-3d2abd0117f0",
    displayName: "Windows Spotlight",
    isPublicClient: true,
    caBypassCount: 1,
    description: "Windows Spotlight - 17 resources.",
  },
];

// ─── Resource Exclusion Bypass (Legacy + Transitional) ────────────────────────
// IMPORTANT: Microsoft is rolling out enforcement changes March-June 2026.
// Previously, when ANY resource was excluded from an "All cloud apps" policy,
// certain low-privilege scopes were automatically excluded from CA enforcement.
// Microsoft is NOW enforcing CA on these scopes by mapping them to Azure AD
// Graph (00000002-0000-0000-c000-000000000000) as the enforcement audience.
//
// Ref: https://learn.microsoft.com/entra/identity/conditional-access/
//      concept-conditional-access-cloud-apps#legacy-conditional-access-behavior-
//      when-an-all-resources-policy-has-a-resource-exclusion
//
// Status: Rolling out March-June 2026 — some tenants may still have old behavior.

export interface ResourceExclusionBypass {
  resourceId: string;
  resourceName: string;
  bypassedScopes: string[];
  /** Scopes that were ALSO leaked for confidential clients (broader set) */
  confidentialClientScopes?: string[];
  description: string;
  /** Whether Microsoft has begun enforcing CA on these scopes (March 2026+) */
  enforcementStatus: "rolling-out" | "enforced" | "legacy";
  /** The enforcement audience resource these scopes now map to */
  enforcementAudience?: string;
}

export const RESOURCE_EXCLUSION_BYPASSES: ResourceExclusionBypass[] = [
  {
    resourceId: "00000002-0000-0000-c000-000000000000",
    resourceName: "Azure AD Graph (Windows Azure Active Directory)",
    bypassedScopes: ["email", "offline_access", "openid", "profile", "User.Read"],
    confidentialClientScopes: [
      "email", "offline_access", "openid", "profile",
      "User.Read", "User.Read.All", "User.ReadBasic.All",
    ],
    description:
      "LEGACY: Previously, excluding ANY resource from an 'All cloud apps' policy caused these Azure AD Graph scopes " +
      "to become unprotected. Microsoft is now enforcing CA on these scopes (rolling out March-June 2026). " +
      "Confidential clients had an even broader set of leaked scopes including User.Read.All and User.ReadBasic.All.",
    enforcementStatus: "rolling-out",
    enforcementAudience: "00000002-0000-0000-c000-000000000000",
  },
  {
    resourceId: "00000003-0000-0000-c000-000000000000",
    resourceName: "Microsoft Graph",
    bypassedScopes: [
      "email", "offline_access", "openid", "profile",
      "User.Read", "People.Read",
    ],
    confidentialClientScopes: [
      "email", "offline_access", "openid", "profile",
      "User.Read", "User.Read.All", "User.ReadBasic.All",
      "People.Read", "People.Read.All",
      "GroupMember.Read.All", "Member.Read.Hidden",
    ],
    description:
      "LEGACY: Previously, excluding ANY resource from an 'All cloud apps' policy caused these MS Graph scopes " +
      "to become unprotected. Confidential clients had an even broader leak including User.Read.All, People.Read.All, " +
      "GroupMember.Read.All, and Member.Read.Hidden — allowing directory enumeration without CA enforcement. " +
      "Microsoft is now enforcing CA on these scopes (rolling out March-June 2026).",
    enforcementStatus: "rolling-out",
    enforcementAudience: "00000002-0000-0000-c000-000000000000",
  },
];

// ─── Device Registration Bypass ──────────────────────────────────────────────

export const DEVICE_REGISTRATION_RESOURCE = {
  resourceId: "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9",
  displayName: "Device Registration Service",
  description:
    "Cannot be protected by location-based CA or compliant device requirement. ONLY MFA grant control works. An attacker could register a device from an untrusted location if MFA is not required. (MSRC VULN-153600 - confirmed by-design)",
};

// ─── Well-Known App Categories ───────────────────────────────────────────────
// Categorize common first-party Microsoft apps for the analyzer

export interface WellKnownApp {
  appId: string;
  displayName: string;
  category: string;
  sensitivity: "critical" | "high" | "medium" | "low";
}

export const WELL_KNOWN_APPS: WellKnownApp[] = [
  // Admin & Identity
  { appId: "00000003-0000-0000-c000-000000000000", displayName: "Microsoft Graph", category: "Identity & API", sensitivity: "critical" },
  { appId: "00000002-0000-0000-c000-000000000000", displayName: "Azure AD Graph (Legacy)", category: "Identity & API", sensitivity: "critical" },
  { appId: "797f4846-ba00-4fd7-ba43-dac1f8f63013", displayName: "Azure Resource Manager", category: "Azure Management", sensitivity: "critical" },
  { appId: "0000000a-0000-0000-c000-000000000000", displayName: "Microsoft Intune", category: "Device Management", sensitivity: "high" },
  // Productivity
  { appId: "00000002-0000-0ff1-ce00-000000000000", displayName: "Office 365 Exchange Online", category: "Productivity", sensitivity: "high" },
  { appId: "00000003-0000-0ff1-ce00-000000000000", displayName: "Office 365 SharePoint Online", category: "Productivity", sensitivity: "high" },
  { appId: "cc15fd57-2c6c-4117-a88c-83b1d56b4bbe", displayName: "Microsoft Teams Services", category: "Productivity", sensitivity: "high" },
  // Security
  { appId: "fc780465-2017-40d4-a0c5-307022471b92", displayName: "WindowsDefenderATP", category: "Security", sensitivity: "critical" },
  { appId: "826870f9-9fbb-4f23-81b8-3a957080dfa2", displayName: "Security Copilot", category: "Security", sensitivity: "critical" },
  // Power Platform
  { appId: "00000007-0000-0000-c000-000000000000", displayName: "Dataverse", category: "Power Platform", sensitivity: "medium" },
  { appId: "7df0a125-d3be-4c96-aa54-591f83ff541c", displayName: "Microsoft Flow Service", category: "Power Platform", sensitivity: "medium" },
];

export const WELL_KNOWN_APP_MAP = new Map<string, WellKnownApp>(
  WELL_KNOWN_APPS.map((app) => [app.appId.toLowerCase(), app])
);

// ─── Entra ID Sync Attack Vectors ────────────────────────────────────────────
// Source: Cloud-Architekt/AzureAD-Attack-Defense playbook
//         - AADCSyncServiceAccount.md (password-hash-sync service account attacks)
//         - EntraSyncAba.md (application-based auth attacks)
//
// These vectors document how Entra Connect / Cloud Sync identities
// can be abused to bypass Conditional Access and escalate privilege.

export interface SyncAttackVector {
  id: string;
  name: string;
  /** MITRE ATT&CK technique IDs */
  mitreTtp: string[];
  target: "service-account" | "service-principal" | "hybrid-admin" | "connector-account";
  severity: "critical" | "high" | "medium";
  description: string;
  /** Tools known to exploit this vector */
  tools: string[];
  /** How Conditional Access can mitigate (or why it cannot) */
  caMitigation: string;
  /** Source playbook file */
  source: string;
}

export const ENTRA_SYNC_ATTACK_VECTORS: SyncAttackVector[] = [
  // ── Service Account (Password Hash Sync) ──
  {
    id: "sync-credential-extraction",
    name: "Sync Account Credential Extraction from Entra Connect DB",
    mitreTtp: ["T1552.001"],
    target: "service-account",
    severity: "critical",
    description:
      "An attacker with local admin on the Entra Connect server can extract the plaintext MSOL_ / AADConnect sync service-account password " +
      "from the local ADSync database using tools like AADInternals (Get-AADIntSyncCredentials) or adconnectdump. " +
      "The sync account has DCSync-equivalent rights in Entra ID (Directory.ReadWrite.All).",
    tools: ["AADInternals", "adconnectdump", "ADSyncDump"],
    caMitigation:
      "Deploy a CA policy restricting the 'Directory Synchronization Accounts' role to trusted Entra Connect server IPs only. " +
      "The policy must target 'All Cloud Apps' for members of this directory role.",
    source: "AADCSyncServiceAccount.md",
  },
  {
    id: "sync-password-spray",
    name: "Password Spray on Sync Service Account",
    mitreTtp: ["T1110.003"],
    target: "service-account",
    severity: "high",
    description:
      "The MSOL_ sync service account uses a regular password. If the password is weak or has been reused, " +
      "an attacker can password-spray it from outside the network. Successful authentication grants DCSync-equivalent " +
      "access to read/reset passwords of any cloud user.",
    tools: ["MSOLSpray", "Spray", "Hydra"],
    caMitigation:
      "Deploy a CA policy restricting login to the sync account to trusted Entra Connect server IPs only. " +
      "The sync account cannot perform MFA, so location-based blocking is the only viable CA control.",
    source: "AADCSyncServiceAccount.md",
  },
  {
    id: "sync-tap-backdoor",
    name: "Temporary Access Pass Backdoor on Connector Account",
    mitreTtp: ["T1098.001"],
    target: "connector-account",
    severity: "high",
    description:
      "A Hybrid Identity Administrator can provision a Temporary Access Pass (TAP) on the on-premises connector account, " +
      "then use it to authenticate as the sync identity from any location. TAP bypasses standard credential requirements.",
    tools: ["Microsoft Graph API", "AADInternals"],
    caMitigation:
      "Restrict the connector account and Hybrid Identity Administrators via CA to trusted IPs. " +
      "Disable TAP for synchronization-related accounts in the Authentication Methods policy.",
    source: "AADCSyncServiceAccount.md",
  },
  // ── Service Principal (Application-Based Auth) ──
  {
    id: "sync-aba-certificate-backdoor",
    name: "Certificate Backdoor on Entra Connect ABA Service Principal",
    mitreTtp: ["T1098.001", "T1552.004"],
    target: "service-principal",
    severity: "critical",
    description:
      "Entra Connect ABA authenticates via a client certificate on the 'Microsoft Entra Connect Sync' service principal. " +
      "An attacker with Application Administrator or Hybrid Identity Administrator role can add a rogue certificate or client secret, " +
      "then use it to sign in from any IP. The SP has ADSynchronization.ReadWrite.All which allows password resets on any user.",
    tools: ["AADInternals (Set-AADIntESTSAuth)", "Azure Portal", "Microsoft Graph API"],
    caMitigation:
      "Deploy a Workload Identity CA policy blocking the service principal from non-trusted locations. " +
      "Requires Workload Identities Premium license. Use App Management Policy to block additional secrets/certificates.",
    source: "EntraSyncAba.md",
  },
  {
    id: "sync-aba-api-permission-abuse",
    name: "ADSynchronization API Permission Abuse (Set-AADIntUserPassword)",
    mitreTtp: ["T1528"],
    target: "service-principal",
    severity: "critical",
    description:
      "The Entra Connect service principal holds the ADSynchronization.ReadWrite.All permission which allows resetting " +
      "any Entra ID user's password (including Global Admins) using AADInternals Set-AADIntUserPassword. " +
      "This is by-design for password hash sync but is devastating if the SP credential is compromised.",
    tools: ["AADInternals (Set-AADIntUserPassword)", "Custom client-credential script"],
    caMitigation:
      "Block the service principal from signing in outside trusted IPs via Workload Identity CA. " +
      "Enable risk-based workload identity CA to detect anomalous sign-in behavior.",
    source: "EntraSyncAba.md",
  },
  {
    id: "sync-hybrid-admin-token-replay",
    name: "Hybrid Identity Administrator Token Replay",
    mitreTtp: ["T1528", "T1078.004"],
    target: "hybrid-admin",
    severity: "critical",
    description:
      "A compromised Hybrid Identity Administrator can create/modify Entra Connect configurations, provision TAPs, " +
      "and add backdoor certificates to the sync service principal. Their tokens can be replayed to perform all these " +
      "actions from any location if not restricted by CA.",
    tools: ["ROADtools", "TokenTactics", "AADInternals"],
    caMitigation:
      "Enforce phishing-resistant MFA (FIDO2/WHfB) and compliant device requirement for the Hybrid Identity Administrator role. " +
      "Restrict role activation to trusted IPs. Use PIM for just-in-time activation with approval.",
    source: "AADCSyncServiceAccount.md",
  },
  {
    id: "sync-soft-hard-match-takeover",
    name: "Soft/Hard Match Account Takeover via Sync",
    mitreTtp: ["T1078.004"],
    target: "service-account",
    severity: "high",
    description:
      "An attacker controlling the sync process can create or modify on-premises accounts that match cloud-only users " +
      "by UPN (soft match) or ImmutableId/sourceAnchor (hard match). When synced, the on-premises identity overwrites " +
      "the cloud user's password hash, taking over the account including Global Admins.",
    tools: ["AADInternals (Set-AADIntAzureADObject)", "Active Directory Users & Computers"],
    caMitigation:
      "CA cannot directly prevent sync-based takeover. Mitigate by restricting sync scope to specific OUs, " +
      "enabling hard match in tenant settings, and monitoring sync audit logs for unexpected user modifications.",
    source: "AADCSyncServiceAccount.md",
  },
  {
    id: "sync-aba-workload-risk-evasion",
    name: "Workload Identity Risk Evasion Without Premium License",
    mitreTtp: ["T1078.004"],
    target: "service-principal",
    severity: "high",
    description:
      "Without Workload Identities Premium, there are no risk detections for service principal sign-ins. " +
      "An attacker using a stolen ABA certificate can authenticate repeatedly without triggering Identity Protection alerts. " +
      "Anomalous credential usage, suspicious sign-in patterns, and compromised app indicators go undetected.",
    tools: ["Any OAuth 2.0 client-credential flow tool"],
    caMitigation:
      "Requires Workload Identities Premium for risk-based CA. Deploy a risk-based policy blocking medium/high risk " +
      "service principals. Without the license, location-based blocking is the only available CA control.",
    source: "EntraSyncAba.md",
  },
];

export const ENTRA_SYNC_ATTACK_MAP = new Map<string, SyncAttackVector>(
  ENTRA_SYNC_ATTACK_VECTORS.map((v) => [v.id, v])
);

export const CA_IMMUNE_RESOURCE_MAP = new Map<string, CAImmuneResource>(
  CA_IMMUNE_RESOURCES.map((r) => [r.resourceId.toLowerCase(), r])
);
