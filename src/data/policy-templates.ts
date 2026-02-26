/**
 * Policy Templates from Jhope188/ConditionalAccessPolicies
 *
 * These are recommended Conditional Access policy templates organized by category.
 * Each template defines the KEY structural elements that identify the policy —
 * the matcher uses these to compare against a tenant's existing policies.
 *
 * Source: https://github.com/Jhope188/ConditionalAccessPolicies
 */

// ─── Template Types ──────────────────────────────────────────────────────────

export type TemplateCategory =
  | "foundation"
  | "baseline"
  | "app-specific"
  | "intune"
  | "p2"
  | "ztca"
  | "agent";

export type ControlType = "BLOCK" | "GRANT" | "SESSION";

export type TemplatePriority = "critical" | "recommended" | "optional";

export interface PolicyTemplate {
  /** Unique slug identifier */
  id: string;
  /** Display name (uses IAC naming convention) */
  displayName: string;
  /** Category grouping */
  category: TemplateCategory;
  /** Block / Grant / Session */
  controlType: ControlType;
  /** Importance for a baseline deployment */
  priority: TemplatePriority;
  /** One-line summary of what the policy does */
  summary: string;
  /** Why this policy matters */
  rationale: string;
  /** CIS benchmark control IDs this template satisfies (if any) */
  cisControls?: string[];
  /** The matching fingerprint — used to detect if the tenant already has this */
  fingerprint: TemplateFingerprint;
  /** Full Graph-compatible JSON for deployment */
  deploymentJson: DeploymentPolicy;
}

export interface TemplateFingerprint {
  /** What apps are targeted: "All", specific app IDs, or user actions */
  includeApps: string[];
  /** What client app types are targeted */
  clientAppTypes?: string[];
  /** What grant controls are required */
  grantControls?: string[];
  /** Grant operator: AND or OR */
  grantOperator?: "AND" | "OR";
  /** Whether it targets all users */
  targetsAllUsers?: boolean;
  /** Target roles (role template IDs) */
  targetRoles?: string[];
  /** Risk levels targeted */
  userRiskLevels?: string[];
  signInRiskLevels?: string[];
  /** Session control signatures */
  sessionSignInFrequency?: boolean;
  sessionPersistentBrowser?: boolean;
  /** Platform conditions */
  platforms?: { include: string[]; exclude: string[] };
  /** Authentication flow conditions */
  authenticationFlows?: string[];
  /** User actions */
  includeUserActions?: string[];
  /** Location-based (uses named locations) */
  usesLocationCondition?: boolean;
  /** Targets guests/external users */
  targetsGuests?: boolean;
  /** Targets specific groups (conceptual — by group purpose, not ID) */
  targetGroupPurpose?: string;
}

export interface DeploymentPolicy {
  displayName: string;
  state: "disabled";
  conditions: {
    users: {
      includeUsers: string[];
      excludeUsers: string[];
      includeGroups: string[];
      excludeGroups: string[];
      includeRoles: string[];
      excludeRoles: string[];
      includeGuestsOrExternalUsers?: unknown;
    };
    applications: {
      includeApplications: string[];
      excludeApplications: string[];
      includeUserActions: string[];
    };
    clientAppTypes: string[];
    platforms?: {
      includePlatforms: string[];
      excludePlatforms: string[];
    };
    locations?: {
      includeLocations: string[];
      excludeLocations: string[];
    };
    userRiskLevels?: string[];
    signInRiskLevels?: string[];
    authenticationFlows?: { transferMethods?: string };
  };
  grantControls?: {
    operator: "AND" | "OR";
    builtInControls: string[];
  };
  sessionControls?: {
    signInFrequency?: {
      isEnabled: boolean;
      value: number | null;
      type: string | null;
      frequencyInterval: string;
      authenticationType: string;
    };
    persistentBrowser?: {
      isEnabled: boolean;
      mode: string;
    };
    applicationEnforcedRestrictions?: {
      isEnabled: boolean;
    };
    secureSignInSession?: {
      isEnabled: boolean;
    };
  };
}

// ─── Well-Known Admin Role Template IDs ──────────────────────────────────────

export const ADMIN_ROLE_IDS = {
  authenticationAdmin: "c4e39bd9-1100-46d3-8c65-fb160da0071f",
  billingAdmin: "b0f54661-2d74-4c50-afa3-1ec803f12efe",
  conditionalAccessAdmin: "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
  exchangeAdmin: "29232cdf-9323-42fd-ade2-1d097af3e4de",
  globalAdmin: "62e90394-69f5-4237-9190-012177145e10",
  helpdeskAdmin: "729827e3-9c14-49f7-bb1b-9608f156bbb8",
  securityAdmin: "194ae4cb-b126-40b2-bd5b-6091b380977d",
  sharePointAdmin: "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
  userAdmin: "fe930be7-5e62-47db-91af-98c3a49a38b1",
  applicationAdmin: "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
  cloudAppAdmin: "158c047a-c907-4556-b7ef-446551a6b5f7",
  passwordAdmin: "966707d0-3269-4727-9be2-8c3a10f19b9d",
  privilegedAuthAdmin: "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
  privilegedRoleAdmin: "e8611ab8-c189-46e8-94e1-60213ab1f814",
  directoryWriters: "9360feb5-f418-4baa-8175-e2a00bac4301",
  globalReader: "f2ef992c-3afb-46b9-b7cf-a126ee74c451",
  intunAdmin: "3a2c62db-5318-420d-8d74-23affee5d9d5",
  teamsAdmin: "69091246-20e8-4a56-aa4d-066075b2a7a8",
  windowsUpdateDeploymentAdmin: "32696413-001a-46ae-978c-ce0f6b3620d2",
};

const ALL_ADMIN_ROLES = Object.values(ADMIN_ROLE_IDS);

// ─── Template Definitions ────────────────────────────────────────────────────

export const POLICY_TEMPLATES: PolicyTemplate[] = [
  // ═══════════════════════════════════════════════════════════════════════
  // FOUNDATION POLICIES
  // ═══════════════════════════════════════════════════════════════════════
  {
    id: "foundation-mfa-all-users",
    displayName: "GLOBAL - GRANT - MFA - AllUsers",
    category: "foundation",
    controlType: "GRANT",
    priority: "critical",
    summary: "Require MFA for all users on all cloud apps",
    rationale:
      "The single most important CA policy. MFA blocks 99.9% of account compromise attacks. This is the foundation layer of the Swiss cheese model.",
    cisControls: ["6.2.1"],
    fingerprint: {
      includeApps: ["All"],
      grantControls: ["mfa"],
      targetsAllUsers: true,
    },
    deploymentJson: {
      displayName: "YOURORG - GLOBAL - GRANT - MFA - AllUsers",
      state: "disabled",
      conditions: {
        users: {
          includeUsers: ["All"],
          excludeUsers: [],
          includeGroups: [],
          excludeGroups: [],
          includeRoles: [],
          excludeRoles: [],
        },
        applications: {
          includeApplications: ["All"],
          excludeApplications: [],
          includeUserActions: [],
        },
        clientAppTypes: ["all"],
      },
      grantControls: {
        operator: "OR",
        builtInControls: ["mfa"],
      },
    },
  },
  {
    id: "foundation-mfa-all-admins",
    displayName: "GLOBAL - GRANT - MFA - AllAdmins",
    category: "foundation",
    controlType: "GRANT",
    priority: "critical",
    summary: "Require MFA for all privileged admin roles on all cloud apps",
    rationale:
      "Admin accounts are the highest-value targets. Even if the all-users MFA policy exists, a dedicated admin MFA policy ensures admins are never accidentally excluded.",
    cisControls: ["6.2.3"],
    fingerprint: {
      includeApps: ["All"],
      grantControls: ["mfa"],
      targetRoles: ALL_ADMIN_ROLES,
    },
    deploymentJson: {
      displayName: "YOURORG - GLOBAL - GRANT - MFA - AllAdmins",
      state: "disabled",
      conditions: {
        users: {
          includeUsers: [],
          excludeUsers: [],
          includeGroups: [],
          excludeGroups: [],
          includeRoles: ALL_ADMIN_ROLES,
          excludeRoles: [],
        },
        applications: {
          includeApplications: ["All"],
          excludeApplications: [],
          includeUserActions: [],
        },
        clientAppTypes: ["all"],
      },
      grantControls: {
        operator: "OR",
        builtInControls: ["mfa"],
      },
    },
  },
  {
    id: "foundation-block-devicecode",
    displayName: "GLOBAL - BLOCK - DeviceCodeAuthFlow",
    category: "foundation",
    controlType: "BLOCK",
    priority: "critical",
    summary: "Block the device code authentication flow for all users",
    rationale:
      "Device code phishing is a top attack vector. Attackers send victims a device code link, the victim authenticates, and the attacker gets the token. Block this flow unless explicitly needed.",
    cisControls: ["6.2.6"],
    fingerprint: {
      includeApps: ["All"],
      grantControls: ["block"],
      targetsAllUsers: true,
      authenticationFlows: ["authenticationTransfer"],
    },
    deploymentJson: {
      displayName: "YOURORG - GLOBAL - BLOCK - DeviceCodeAuthFlow",
      state: "disabled",
      conditions: {
        users: {
          includeUsers: ["All"],
          excludeUsers: [],
          includeGroups: [],
          excludeGroups: [],
          includeRoles: [],
          excludeRoles: [],
        },
        applications: {
          includeApplications: ["All"],
          excludeApplications: [],
          includeUserActions: [],
        },
        clientAppTypes: ["all"],
        authenticationFlows: { transferMethods: "deviceCodeFlow" },
      },
      grantControls: {
        operator: "OR",
        builtInControls: ["block"],
      },
    },
  },
  {
    id: "foundation-block-legacy",
    displayName: "GLOBAL - BLOCK - LegacyAuthentication",
    category: "foundation",
    controlType: "BLOCK",
    priority: "critical",
    summary: "Block legacy authentication protocols (EAS, other)",
    rationale:
      "Legacy auth protocols (IMAP, POP3, SMTP, Exchange ActiveSync) cannot perform MFA. They are the #1 vector for password spray attacks.",
    cisControls: ["6.2.7"],
    fingerprint: {
      includeApps: ["All"],
      grantControls: ["block"],
      targetsAllUsers: true,
      clientAppTypes: ["exchangeActiveSync", "other"],
    },
    deploymentJson: {
      displayName: "YOURORG - GLOBAL - BLOCK - LegacyAuthentication",
      state: "disabled",
      conditions: {
        users: {
          includeUsers: ["All"],
          excludeUsers: [],
          includeGroups: [],
          excludeGroups: [],
          includeRoles: [],
          excludeRoles: [],
        },
        applications: {
          includeApplications: ["All"],
          excludeApplications: [],
          includeUserActions: [],
        },
        clientAppTypes: ["exchangeActiveSync", "other"],
      },
      grantControls: {
        operator: "OR",
        builtInControls: ["block"],
      },
    },
  },
  {
    id: "foundation-block-countries",
    displayName: "GLOBAL - BLOCK - Countries-NotAllowed",
    category: "foundation",
    controlType: "BLOCK",
    priority: "critical",
    summary: "Block access from non-allowed countries",
    rationale:
      "Geo-blocking reduces your attack surface significantly. Most organizations operate in a small number of countries — block everything else.",
    cisControls: ["6.2.5"],
    fingerprint: {
      includeApps: ["All"],
      grantControls: ["block"],
      targetsAllUsers: true,
      usesLocationCondition: true,
    },
    deploymentJson: {
      displayName: "YOURORG - GLOBAL - BLOCK - Countries-NotAllowed",
      state: "disabled",
      conditions: {
        users: {
          includeUsers: ["All"],
          excludeUsers: [],
          includeGroups: [],
          excludeGroups: [],
          includeRoles: [],
          excludeRoles: [],
        },
        applications: {
          includeApplications: ["All"],
          excludeApplications: [],
          includeUserActions: [],
        },
        clientAppTypes: ["all"],
        locations: {
          includeLocations: ["All"],
          excludeLocations: [],
        },
      },
      grantControls: {
        operator: "OR",
        builtInControls: ["block"],
      },
    },
  },
  {
    id: "foundation-block-unsupported-platforms",
    displayName: "GLOBAL - BLOCK - UnsupportedDevicePlatforms",
    category: "foundation",
    controlType: "BLOCK",
    priority: "recommended",
    summary: "Block access from unsupported device platforms (Linux, ChromeOS, etc.)",
    rationale:
      "Only allow platforms your organization manages. Unsupported platforms can't be controlled via Intune and represent an unmanaged attack surface.",
    fingerprint: {
      includeApps: ["All"],
      grantControls: ["block"],
      targetsAllUsers: true,
      platforms: {
        include: ["all"],
        exclude: ["android", "iOS", "windows", "macOS"],
      },
    },
    deploymentJson: {
      displayName: "YOURORG - GLOBAL - BLOCK - UnsupportedDevicePlatforms",
      state: "disabled",
      conditions: {
        users: {
          includeUsers: ["All"],
          excludeUsers: [],
          includeGroups: [],
          excludeGroups: [],
          includeRoles: [],
          excludeRoles: [],
        },
        applications: {
          includeApplications: ["All"],
          excludeApplications: [],
          includeUserActions: [],
        },
        clientAppTypes: ["all"],
        platforms: {
          includePlatforms: ["all"],
          excludePlatforms: ["android", "iOS", "windows", "macOS"],
        },
      },
      grantControls: {
        operator: "OR",
        builtInControls: ["block"],
      },
    },
  },

  // ═══════════════════════════════════════════════════════════════════════
  // BASELINE POLICIES
  // ═══════════════════════════════════════════════════════════════════════
  {
    id: "baseline-mfa-guests",
    displayName: "GLOBAL - GRANT - MFA - External-Guest-Users",
    category: "baseline",
    controlType: "GRANT",
    priority: "recommended",
    summary: "Require MFA for all external/guest users",
    rationale:
      "Guest accounts have access to your tenant resources but are controlled by external identity providers. Always require MFA to ensure a baseline level of assurance.",
    cisControls: ["6.2.2"],
    fingerprint: {
      includeApps: ["All"],
      grantControls: ["mfa"],
      targetsGuests: true,
    },
    deploymentJson: {
      displayName: "YOURORG - GLOBAL - GRANT - MFA - External-Guest-Users",
      state: "disabled",
      conditions: {
        users: {
          includeUsers: [],
          excludeUsers: [],
          includeGroups: [],
          excludeGroups: [],
          includeRoles: [],
          excludeRoles: [],
          includeGuestsOrExternalUsers: {
            guestOrExternalUserTypes:
              "internalGuest,b2bCollaborationGuest,b2bCollaborationMember,b2bDirectConnectUser,otherExternalUser,serviceProvider",
            externalTenants: {
              membershipKind: "all",
            },
          },
        },
        applications: {
          includeApplications: ["All"],
          excludeApplications: [],
          includeUserActions: [],
        },
        clientAppTypes: ["all"],
      },
      grantControls: {
        operator: "OR",
        builtInControls: ["mfa"],
      },
    },
  },
  {
    id: "baseline-block-auth-transfer",
    displayName: "GLOBAL - BLOCK - Authentication Transfer",
    category: "baseline",
    controlType: "BLOCK",
    priority: "recommended",
    summary: "Block authentication transfer flows",
    rationale:
      "Authentication transfer allows a user to pass their authenticated session to another device. This can be abused by attackers who have access to a user's device or QR code.",
    fingerprint: {
      includeApps: ["All"],
      grantControls: ["block"],
      targetsAllUsers: true,
      authenticationFlows: ["authenticationTransfer"],
    },
    deploymentJson: {
      displayName: "YOURORG - GLOBAL - BLOCK - Authentication Transfer",
      state: "disabled",
      conditions: {
        users: {
          includeUsers: ["All"],
          excludeUsers: [],
          includeGroups: [],
          excludeGroups: [],
          includeRoles: [],
          excludeRoles: [],
        },
        applications: {
          includeApplications: ["All"],
          excludeApplications: [],
          includeUserActions: [],
        },
        clientAppTypes: ["all"],
        authenticationFlows: { transferMethods: "authenticationTransfer" },
      },
      grantControls: {
        operator: "OR",
        builtInControls: ["block"],
      },
    },
  },
  {
    id: "baseline-block-service-accounts",
    displayName: "GLOBAL - BLOCK - ServiceAccounts",
    category: "baseline",
    controlType: "BLOCK",
    priority: "recommended",
    summary: "Block interactive sign-in for service accounts except from trusted locations",
    rationale:
      "Service accounts should only authenticate from trusted networks. Blocking them from all other locations prevents credential abuse.",
    fingerprint: {
      includeApps: ["All"],
      grantControls: ["block"],
      targetGroupPurpose: "service-accounts",
      usesLocationCondition: true,
    },
    deploymentJson: {
      displayName: "YOURORG - GLOBAL - BLOCK - ServiceAccounts",
      state: "disabled",
      conditions: {
        users: {
          includeUsers: [],
          excludeUsers: [],
          includeGroups: [],
          excludeGroups: [],
          includeRoles: [],
          excludeRoles: [],
        },
        applications: {
          includeApplications: ["All"],
          excludeApplications: [],
          includeUserActions: [],
        },
        clientAppTypes: ["all"],
        locations: {
          includeLocations: ["All"],
          excludeLocations: [],
        },
      },
      grantControls: {
        operator: "OR",
        builtInControls: ["block"],
      },
    },
  },
  {
    id: "baseline-mfa-register-security-info",
    displayName: "GLOBAL - GRANT - MFA - RegisterSecurityInfo",
    category: "baseline",
    controlType: "GRANT",
    priority: "recommended",
    summary: "Require MFA when registering security info (MFA methods)",
    rationale:
      "An attacker who compromises a password can register their own MFA method. Requiring MFA during security info registration prevents MFA method hijacking.",
    cisControls: ["6.2.4"],
    fingerprint: {
      includeApps: [],
      grantControls: ["mfa"],
      targetsAllUsers: true,
      includeUserActions: ["urn:user:registersecurityinfo"],
    },
    deploymentJson: {
      displayName: "YOURORG - GLOBAL - GRANT - MFA - RegisterSecurityInfo",
      state: "disabled",
      conditions: {
        users: {
          includeUsers: ["All"],
          excludeUsers: [],
          includeGroups: [],
          excludeGroups: [],
          includeRoles: [],
          excludeRoles: [],
        },
        applications: {
          includeApplications: [],
          excludeApplications: [],
          includeUserActions: ["urn:user:registersecurityinfo"],
        },
        clientAppTypes: ["all"],
      },
      grantControls: {
        operator: "OR",
        builtInControls: ["mfa"],
      },
    },
  },
  {
    id: "baseline-session-admin-persistence",
    displayName: "GLOBAL - SESSION - Admin Persistence (1 Hour)",
    category: "baseline",
    controlType: "SESSION",
    priority: "recommended",
    summary: "Limit admin session persistence to 1 hour with no persistent browser",
    rationale:
      "Admin sessions should be short-lived. A 1-hour sign-in frequency forces re-authentication, limiting the window an attacker has if an admin session is compromised.",
    fingerprint: {
      includeApps: ["All"],
      targetRoles: ALL_ADMIN_ROLES,
      sessionSignInFrequency: true,
      sessionPersistentBrowser: true,
    },
    deploymentJson: {
      displayName: "YOURORG - GLOBAL - SESSION - Admin Persistence (1 Hour)",
      state: "disabled",
      conditions: {
        users: {
          includeUsers: [],
          excludeUsers: [],
          includeGroups: [],
          excludeGroups: [],
          includeRoles: ALL_ADMIN_ROLES,
          excludeRoles: [],
        },
        applications: {
          includeApplications: ["All"],
          excludeApplications: [],
          includeUserActions: [],
        },
        clientAppTypes: ["browser"],
      },
      sessionControls: {
        signInFrequency: {
          isEnabled: true,
          value: 1,
          type: "hours",
          frequencyInterval: "timeBased",
          authenticationType: "primaryAndSecondaryAuthentication",
        },
        persistentBrowser: {
          isEnabled: true,
          mode: "never",
        },
      },
    },
  },
  {
    id: "baseline-session-user-persistence",
    displayName: "GLOBAL - SESSION - User Persistence (9-12 Hours)",
    category: "baseline",
    controlType: "SESSION",
    priority: "optional",
    summary: "Limit all-user browser session persistence to 9-12 hours",
    rationale:
      "Requiring re-authentication every 9-12 hours balances security with usability for standard users, limiting exposure from stolen session cookies.",
    fingerprint: {
      includeApps: ["All"],
      targetsAllUsers: true,
      sessionSignInFrequency: true,
      clientAppTypes: ["browser"],
    },
    deploymentJson: {
      displayName: "YOURORG - GLOBAL - SESSION - User Persistence (9 Hours)",
      state: "disabled",
      conditions: {
        users: {
          includeUsers: ["All"],
          excludeUsers: [],
          includeGroups: [],
          excludeGroups: [],
          includeRoles: [],
          excludeRoles: [],
        },
        applications: {
          includeApplications: ["All"],
          excludeApplications: [],
          includeUserActions: [],
        },
        clientAppTypes: ["browser"],
      },
      sessionControls: {
        signInFrequency: {
          isEnabled: true,
          value: 9,
          type: "hours",
          frequencyInterval: "timeBased",
          authenticationType: "primaryAndSecondaryAuthentication",
        },
        persistentBrowser: {
          isEnabled: true,
          mode: "never",
        },
      },
    },
  },

  // ═══════════════════════════════════════════════════════════════════════
  // APP SPECIFIC POLICIES
  // ═══════════════════════════════════════════════════════════════════════
  {
    id: "app-block-sharepoint-nontrusted",
    displayName: "APP - BLOCK - SharePoint-OneDrive - NonTrustedLocations",
    category: "app-specific",
    controlType: "BLOCK",
    priority: "optional",
    summary: "Block SharePoint/OneDrive access from non-trusted locations",
    rationale:
      "SharePoint and OneDrive hold the majority of organizational data. Restricting access to trusted locations prevents data exfiltration from untrusted networks.",
    fingerprint: {
      includeApps: ["00000003-0000-0ff1-ce00-000000000000"],
      grantControls: ["block"],
      targetsAllUsers: true,
      usesLocationCondition: true,
    },
    deploymentJson: {
      displayName:
        "YOURORG - APP - BLOCK - SharePoint-OneDrive - NonTrustedLocations",
      state: "disabled",
      conditions: {
        users: {
          includeUsers: ["All"],
          excludeUsers: [],
          includeGroups: [],
          excludeGroups: [],
          includeRoles: [],
          excludeRoles: [],
        },
        applications: {
          includeApplications: ["00000003-0000-0ff1-ce00-000000000000"],
          excludeApplications: [],
          includeUserActions: [],
        },
        clientAppTypes: ["all"],
        locations: {
          includeLocations: ["All"],
          excludeLocations: ["AllTrusted"],
        },
      },
      grantControls: {
        operator: "OR",
        builtInControls: ["block"],
      },
    },
  },
  {
    id: "app-session-o365-timeout",
    displayName: "APP - SESSION - O365 - TimeoutSettings",
    category: "app-specific",
    controlType: "SESSION",
    priority: "optional",
    summary: "Enforce application-enforced restrictions for Office 365",
    rationale:
      "Application-enforced restrictions work with SharePoint admin settings to limit access to browser-only or read-only mode from unmanaged devices.",
    fingerprint: {
      includeApps: ["Office365"],
      targetsAllUsers: true,
    },
    deploymentJson: {
      displayName: "YOURORG - APP - SESSION - O365 - TimeoutSettings",
      state: "disabled",
      conditions: {
        users: {
          includeUsers: ["All"],
          excludeUsers: [],
          includeGroups: [],
          excludeGroups: [],
          includeRoles: [],
          excludeRoles: [],
        },
        applications: {
          includeApplications: ["Office365"],
          excludeApplications: [],
          includeUserActions: [],
        },
        clientAppTypes: ["browser"],
      },
      sessionControls: {
        applicationEnforcedRestrictions: {
          isEnabled: true,
        },
      },
    },
  },

  // ═══════════════════════════════════════════════════════════════════════
  // INTUNE POLICIES
  // ═══════════════════════════════════════════════════════════════════════
  {
    id: "intune-grant-mobile-desktop",
    displayName: "INTUNE - GRANT - Mobile Apps and Desktop Clients",
    category: "intune",
    controlType: "GRANT",
    priority: "recommended",
    summary: "Require compliant device for mobile apps and desktop clients",
    rationale:
      "Requiring device compliance for thick clients ensures that only managed, healthy devices can access organizational resources through native apps.",
    fingerprint: {
      includeApps: ["All"],
      grantControls: ["compliantDevice"],
      targetsAllUsers: true,
      clientAppTypes: ["mobileAppsAndDesktopClients"],
    },
    deploymentJson: {
      displayName:
        "YOURORG - INTUNE - GRANT - Mobile Apps and Desktop Clients",
      state: "disabled",
      conditions: {
        users: {
          includeUsers: ["All"],
          excludeUsers: [],
          includeGroups: [],
          excludeGroups: [],
          includeRoles: [],
          excludeRoles: [],
        },
        applications: {
          includeApplications: ["All"],
          excludeApplications: [],
          includeUserActions: [],
        },
        clientAppTypes: ["mobileAppsAndDesktopClients"],
      },
      grantControls: {
        operator: "OR",
        builtInControls: ["compliantDevice"],
      },
    },
  },
  {
    id: "intune-grant-mobile-access",
    displayName: "INTUNE - GRANT - Mobile Device Access Requirements",
    category: "intune",
    controlType: "GRANT",
    priority: "optional",
    summary:
      "Require compliant device or approved/compliant app for mobile access",
    rationale:
      "For mobile devices, requiring either compliance OR an approved app protection policy enables BYOD scenarios while maintaining data protection.",
    fingerprint: {
      includeApps: ["All"],
      grantControls: ["compliantDevice", "compliantApplication"],
      grantOperator: "OR",
      targetsAllUsers: true,
    },
    deploymentJson: {
      displayName:
        "YOURORG - INTUNE - GRANT - Mobile Device Access Requirements",
      state: "disabled",
      conditions: {
        users: {
          includeUsers: ["All"],
          excludeUsers: [],
          includeGroups: [],
          excludeGroups: [],
          includeRoles: [],
          excludeRoles: [],
        },
        applications: {
          includeApplications: ["All"],
          excludeApplications: [],
          includeUserActions: [],
        },
        clientAppTypes: ["all"],
      },
      grantControls: {
        operator: "OR",
        builtInControls: ["compliantDevice", "compliantApplication"],
      },
    },
  },

  // ═══════════════════════════════════════════════════════════════════════
  // P2 POLICIES (Require Entra ID P2 License)
  // ═══════════════════════════════════════════════════════════════════════
  {
    id: "p2-high-risk-signin",
    displayName: "P2 - GLOBAL - GRANT - High-Risk Sign-Ins",
    category: "p2",
    controlType: "GRANT",
    priority: "critical",
    summary:
      "Require phishing-resistant MFA for high-risk sign-ins",
    rationale:
      "Identity Protection high-risk sign-ins indicate likely compromise attempts. Requiring strong MFA (FIDO2, WHfB, certificate) blocks even MFA-bypass attacks like adversary-in-the-middle (AiTM).",
    cisControls: ["6.3.1"],
    fingerprint: {
      includeApps: ["All"],
      targetsAllUsers: true,
      signInRiskLevels: ["high"],
    },
    deploymentJson: {
      displayName: "YOURORG - P2 - GLOBAL - GRANT - High-Risk Sign-Ins",
      state: "disabled",
      conditions: {
        users: {
          includeUsers: ["All"],
          excludeUsers: [],
          includeGroups: [],
          excludeGroups: [],
          includeRoles: [],
          excludeRoles: [],
        },
        applications: {
          includeApplications: ["All"],
          excludeApplications: [],
          includeUserActions: [],
        },
        clientAppTypes: ["all"],
        signInRiskLevels: ["high"],
      },
      sessionControls: {
        signInFrequency: {
          isEnabled: true,
          value: null,
          type: null,
          frequencyInterval: "everyTime",
          authenticationType: "primaryAndSecondaryAuthentication",
        },
      },
    },
  },
  {
    id: "p2-medium-risk-signin",
    displayName: "P2 - GLOBAL - GRANT - Medium-Risk Sign-Ins",
    category: "p2",
    controlType: "GRANT",
    priority: "recommended",
    summary: "Require MFA for medium-risk sign-ins",
    rationale:
      "Medium-risk sign-ins may indicate token replay, unusual travel, or anomalous behavior. Requiring MFA provides a safety net.",
    cisControls: ["6.3.1"],
    fingerprint: {
      includeApps: ["All"],
      targetsAllUsers: true,
      signInRiskLevels: ["medium"],
    },
    deploymentJson: {
      displayName: "YOURORG - P2 - GLOBAL - GRANT - Medium-Risk Sign-Ins",
      state: "disabled",
      conditions: {
        users: {
          includeUsers: ["All"],
          excludeUsers: [],
          includeGroups: [],
          excludeGroups: [],
          includeRoles: [],
          excludeRoles: [],
        },
        applications: {
          includeApplications: ["All"],
          excludeApplications: [],
          includeUserActions: [],
        },
        clientAppTypes: ["all"],
        signInRiskLevels: ["medium"],
      },
      grantControls: {
        operator: "OR",
        builtInControls: ["mfa"],
      },
    },
  },
  {
    id: "p2-high-risk-user",
    displayName: "P2 - GLOBAL - GRANT - High-Risk Users",
    category: "p2",
    controlType: "GRANT",
    priority: "critical",
    summary:
      "Require MFA and password change for high-risk users",
    rationale:
      "High-risk users have confirmed compromised credentials (from dark web leaks or confirmed breaches). Forcing MFA + password change remediates the compromise.",
    cisControls: ["6.3.2"],
    fingerprint: {
      includeApps: ["All"],
      targetsAllUsers: true,
      userRiskLevels: ["high"],
      grantControls: ["mfa", "passwordChange"],
      grantOperator: "AND",
    },
    deploymentJson: {
      displayName: "YOURORG - P2 - GLOBAL - GRANT - High-Risk Users",
      state: "disabled",
      conditions: {
        users: {
          includeUsers: ["All"],
          excludeUsers: [],
          includeGroups: [],
          excludeGroups: [],
          includeRoles: [],
          excludeRoles: [],
        },
        applications: {
          includeApplications: ["All"],
          excludeApplications: [],
          includeUserActions: [],
        },
        clientAppTypes: ["all"],
        userRiskLevels: ["high"],
      },
      grantControls: {
        operator: "AND",
        builtInControls: ["mfa", "passwordChange"],
      },
      sessionControls: {
        signInFrequency: {
          isEnabled: true,
          value: null,
          type: null,
          frequencyInterval: "everyTime",
          authenticationType: "primaryAndSecondaryAuthentication",
        },
      },
    },
  },
  {
    id: "p2-medium-risk-user",
    displayName: "P2 - GLOBAL - GRANT - Medium-Risk Users",
    category: "p2",
    controlType: "GRANT",
    priority: "recommended",
    summary: "Require MFA and password change for medium-risk users",
    rationale:
      "Medium-risk users may have leaked credentials or suspicious activity patterns. Proactively requiring password change reduces exposure.",
    cisControls: ["6.3.2"],
    fingerprint: {
      includeApps: ["All"],
      targetsAllUsers: true,
      userRiskLevels: ["medium"],
      grantControls: ["mfa", "passwordChange"],
      grantOperator: "AND",
    },
    deploymentJson: {
      displayName: "YOURORG - P2 - GLOBAL - GRANT - Medium-Risk Users",
      state: "disabled",
      conditions: {
        users: {
          includeUsers: ["All"],
          excludeUsers: [],
          includeGroups: [],
          excludeGroups: [],
          includeRoles: [],
          excludeRoles: [],
        },
        applications: {
          includeApplications: ["All"],
          excludeApplications: [],
          includeUserActions: [],
        },
        clientAppTypes: ["all"],
        userRiskLevels: ["medium"],
      },
      grantControls: {
        operator: "AND",
        builtInControls: ["mfa", "passwordChange"],
      },
    },
  },
  {
    id: "p2-block-risky-security-registration",
    displayName: "P2 - GLOBAL - BLOCK - RiskyUsers - RegisterSecurityInfo",
    category: "p2",
    controlType: "BLOCK",
    priority: "recommended",
    summary:
      "Block risky users from registering new security info (MFA methods)",
    rationale:
      "If a user is flagged as medium/high risk, they should not be able to register new MFA methods — an attacker could register their own authenticator on a compromised account.",
    fingerprint: {
      includeApps: [],
      grantControls: ["block"],
      targetsAllUsers: true,
      userRiskLevels: ["high", "medium"],
      includeUserActions: ["urn:user:registersecurityinfo"],
    },
    deploymentJson: {
      displayName:
        "YOURORG - P2 - GLOBAL - BLOCK - RiskyUsers - RegisterSecurityInfo",
      state: "disabled",
      conditions: {
        users: {
          includeUsers: ["All"],
          excludeUsers: [],
          includeGroups: [],
          excludeGroups: [],
          includeRoles: [],
          excludeRoles: [],
        },
        applications: {
          includeApplications: [],
          excludeApplications: [],
          includeUserActions: ["urn:user:registersecurityinfo"],
        },
        clientAppTypes: ["all"],
        userRiskLevels: ["high", "medium"],
      },
      grantControls: {
        operator: "OR",
        builtInControls: ["block"],
      },
    },
  },

  // ═══════════════════════════════════════════════════════════════════════
  // ZTCA (Zero Trust Conditional Access) POLICIES
  // ═══════════════════════════════════════════════════════════════════════
  {
    id: "ztca-block-register-security-exclude-trusted",
    displayName: "ZTCA - BLOCK - RegisterSecurityInfo - ExcludeTrustedLocation",
    category: "ztca",
    controlType: "BLOCK",
    priority: "optional",
    summary: "Block security info registration except from trusted locations",
    rationale:
      "Restricting MFA registration to trusted locations (e.g., corporate network) prevents attackers from registering MFA methods remotely even if they have the password.",
    fingerprint: {
      includeApps: [],
      grantControls: ["block"],
      targetsAllUsers: true,
      includeUserActions: ["urn:user:registersecurityinfo"],
      usesLocationCondition: true,
    },
    deploymentJson: {
      displayName:
        "YOURORG - ZTCA - BLOCK - RegisterSecurityInfo - ExcludeTrustedLocation",
      state: "disabled",
      conditions: {
        users: {
          includeUsers: ["All"],
          excludeUsers: [],
          includeGroups: [],
          excludeGroups: [],
          includeRoles: [],
          excludeRoles: [],
        },
        applications: {
          includeApplications: [],
          excludeApplications: [],
          includeUserActions: ["urn:user:registersecurityinfo"],
        },
        clientAppTypes: ["all"],
        locations: {
          includeLocations: ["All"],
          excludeLocations: ["AllTrusted"],
        },
      },
      grantControls: {
        operator: "OR",
        builtInControls: ["block"],
      },
    },
  },

  // ═══════════════════════════════════════════════════════════════════════
  // AGENT POLICIES
  // ═══════════════════════════════════════════════════════════════════════
  {
    id: "agent-block-high-risk",
    displayName: "AGENT - BLOCK - HighRiskAgents",
    category: "agent",
    controlType: "BLOCK",
    priority: "optional",
    summary: "Block high-risk AI agents and service principals",
    rationale:
      "As organizations adopt AI agents, controlling their access is critical. Block agents flagged as high-risk by Identity Protection.",
    fingerprint: {
      includeApps: ["All"],
      grantControls: ["block"],
      signInRiskLevels: ["high"],
    },
    deploymentJson: {
      displayName: "YOURORG - AGENT - BLOCK - HighRiskAgents",
      state: "disabled",
      conditions: {
        users: {
          includeUsers: ["All"],
          excludeUsers: [],
          includeGroups: [],
          excludeGroups: [],
          includeRoles: [],
          excludeRoles: [],
        },
        applications: {
          includeApplications: ["All"],
          excludeApplications: [],
          includeUserActions: [],
        },
        clientAppTypes: ["all"],
        signInRiskLevels: ["high"],
      },
      grantControls: {
        operator: "OR",
        builtInControls: ["block"],
      },
    },
  },
  {
    id: "agent-token-protection",
    displayName: "GLOBAL - SESSION - Windows - TokenProtection",
    category: "agent",
    controlType: "SESSION",
    priority: "optional",
    summary: "Enable token protection (token binding) for Windows desktop clients",
    rationale:
      "Token protection binds tokens to the device, preventing token theft and replay attacks. This is especially important for Windows devices accessing sensitive resources.",
    fingerprint: {
      includeApps: ["All"],
      targetsAllUsers: true,
      clientAppTypes: ["mobileAppsAndDesktopClients"],
      platforms: { include: ["windows"], exclude: [] },
    },
    deploymentJson: {
      displayName: "YOURORG - GLOBAL - SESSION - Windows - TokenProtection",
      state: "disabled",
      conditions: {
        users: {
          includeUsers: ["All"],
          excludeUsers: [],
          includeGroups: [],
          excludeGroups: [],
          includeRoles: [],
          excludeRoles: [],
        },
        applications: {
          includeApplications: ["All"],
          excludeApplications: [],
          includeUserActions: [],
        },
        clientAppTypes: ["mobileAppsAndDesktopClients"],
        platforms: {
          includePlatforms: ["windows"],
          excludePlatforms: [],
        },
      },
      sessionControls: {
        secureSignInSession: {
          isEnabled: true,
        },
      },
    },
  },
];

// ─── Helpers ─────────────────────────────────────────────────────────────────

export function getTemplatesByCategory(
  category: TemplateCategory
): PolicyTemplate[] {
  return POLICY_TEMPLATES.filter((t) => t.category === category);
}

export function getTemplateById(id: string): PolicyTemplate | undefined {
  return POLICY_TEMPLATES.find((t) => t.id === id);
}

export const CATEGORY_META: Record<
  TemplateCategory,
  { label: string; description: string; icon: string }
> = {
  foundation: {
    label: "Foundation",
    description:
      "Critical policies every tenant MUST have. These block the most common attack vectors.",
    icon: "🏗️",
  },
  baseline: {
    label: "Baseline",
    description:
      "Recommended policies for a solid security posture beyond the basics.",
    icon: "🛡️",
  },
  "app-specific": {
    label: "App Specific",
    description:
      "Policies targeting specific applications like SharePoint, AVD, or O365.",
    icon: "📱",
  },
  intune: {
    label: "Intune / Device",
    description:
      "Device compliance and managed-device requirements via Intune.",
    icon: "💻",
  },
  p2: {
    label: "P2 / Identity Protection",
    description:
      "Risk-based policies requiring Entra ID P2 licenses.",
    icon: "⚡",
  },
  ztca: {
    label: "Zero Trust CA",
    description:
      "Advanced Zero Trust patterns for tighter security controls.",
    icon: "🔒",
  },
  agent: {
    label: "Agent / Token Protection",
    description:
      "Policies for AI agents and token-binding protection.",
    icon: "🤖",
  },
};
