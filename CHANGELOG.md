# Changelog

All notable changes to the CA Policy Analyzer will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.7.0] - 2026-04-11

### Changed
- **Resource Exclusion Bypass Check — Updated for March 2026 Enforcement Change**
  - Microsoft is rolling out CA enforcement for low-privilege scopes (March-June 2026) that were previously exempt
  - Updated check from "scopes are leaked" (HIGH) to transitional enforcement awareness (MEDIUM)
  - Previously excluded scopes (`User.Read`, `openid`, `profile`, `email`, `offline_access`, `People.Read`) are now enforced via Azure AD Graph as the enforcement audience
  - **Added missing confidential client scopes** that had a broader bypass (not previously tracked):
    - `User.Read.All`, `User.ReadBasic.All` — directory user enumeration
    - `People.Read.All` — organizational relationship data
    - `GroupMember.Read.All` — security group membership enumeration
    - `Member.Read.Hidden` — hidden group membership reads
  - Updated `RESOURCE_EXCLUSION_BYPASSES` data model with `enforcementStatus`, `enforcementAudience`, and `confidentialClientScopes` fields
  - Severity reduced from HIGH to MEDIUM since Microsoft is actively remediating the bypass
  - References: [CA behavior change](https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-cloud-apps#new-conditional-access-behavior-when-an-all-resources-policy-has-a-resource-exclusion)

### Added
- **Low-Privilege Scope Enforcement Tenant-Wide Check** — New finding category
  - Detects policies with "All resources" targeting that have app exclusions affected by the enforcement rollout
  - Identifies whether tenant has explicit Azure AD Graph policy coverage
  - Warns about apps that may receive unexpected CA challenges (MFA, device compliance) during rollout
  - Recommends reviewing Usage & Insights report and sign-in logs filtered by Azure AD Graph resource
  - Advises updating custom apps not designed for CA claims challenges
  - Added "Low-Privilege Scope Enforcement" category with yellow AlertTriangle icon

### Fixed
- **Workload Identity Premium License Detection** — Now detects both `AAD_WRKLDID_P1` and `AAD_WRKLDID_P2` service plan IDs
  - Previously only checked `84c289f0-efcb-486f-8581-07f44fc9efad` (P1 plan from `Workload_Identities_Premium_CN` SKU)
  - Now also checks `7dc0e92d-bf15-401d-907e-0884efe7c760` (P2 plan from `Workload_Identities_P2` SKU)
  - Tenants with the standalone `Microsoft Entra Workload ID` license were incorrectly showing "not detected"

## [1.6.0] - 2026-04-11

### Enhanced
- **Guest/External User Exclusion Check** - Improved clarity on guest type enforcement models
  - Now shows which specific guest types are excluded from policies
  - Clearly explains which types can be enforced in the resource tenant (B2B Collaboration guests/members) vs home tenant only (B2B Direct Connect users)
  - Categorizes excluded types by enforcement model: Resource tenant enforceable, Home tenant only, Other external users
  - Explains MFA trust requirements in Cross-Tenant Access Settings for B2B Collaboration guests
  - Notes that B2B Direct Connect users authenticate in their home tenant and cannot be directly controlled
  - More actionable recommendations based on which guest types are at risk

### Added
- **Comprehensive Break-Glass Account Review** - New tenant-wide analysis to validate emergency access protection
  - Automatically identifies break-glass accounts or groups by analyzing exclusion patterns across policies
  - Distinguishes between user-based and group-based break-glass strategies
  - Validates break-glass exclusions are present in all critical policies (MFA, blocks, security registration, protected actions)
  - Special handling for Microsoft managed policies: Allows omission of break-glass if policy is disabled
  - Three severity levels:
    - CRITICAL: No break-glass detected anywhere in tenant
    - HIGH: Break-glass identified but missing from some critical policies
    - INFO: Break-glass properly excluded from all critical policies ✓
  - Provides targeted guidance based on findings:
    - If no break-glass: Step-by-step instructions to create 2 emergency access accounts
    - If partial coverage: Lists specific policies missing break-glass exclusions
    - If full coverage: Ongoing maintenance recommendations
  - Includes best practices: Cloud-only accounts, 16+ char passwords, no mailboxes, Azure Monitor alerts, quarterly testing
  - Links to Microsoft Learn articles on emergency access account management
  - References: [Manage emergency access accounts](https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access)

## [1.5.0] - 2026-04-06

### Added
- **Identity Protection Risk-Based Checks** - New tenant-wide checks for Identity Protection integration
  - Detects missing user risk policies (high-risk users not blocked or required to change password)
  - Detects missing sign-in risk policies (risky sign-ins not requiring MFA)
  - Explains risk indicators: leaked credentials, anomalous behavior, TOR/VPN usage, impossible travel
  - Provides Azure AD Premium P2 requirements and policy configuration guidance
  - Severity: HIGH for missing risk-based policies
  - Reference: [Identity Protection Overview](https://learn.microsoft.com/entra/id-protection/overview-identity-protection)
- **High-Value Application Coverage Check** - Validates MFA/blocking policies for critical Microsoft apps
  - Detects unprotected access to Azure Management, Azure Portal, Microsoft Graph, Exchange, SharePoint
  - Flags applications by risk level: CRITICAL (Azure, Graph) and HIGH (Office 365 services)
  - Recommends phishing-resistant MFA for Azure management and API access
  - Provides app-specific policy configuration guidance
  - Severity: CRITICAL if Azure/Graph unprotected, HIGH for Office 365 apps
  - Reference: [Application-specific CA policies](https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-cloud-apps)
- **New Finding Categories**: "Identity Protection" and "Application Coverage" with ShieldAlert icon (red)

## [1.4.0] - 2026-04-04

### Added
- **Protected Actions Configuration Check** - New analyzer check that validates Protected Actions policies for security best practices
  - Detects policies using basic MFA instead of required authentication strength for Protected Actions
  - Identifies policies targeting "All users" instead of specific admin roles who perform protected actions
  - Recommends phishing-resistant MFA for sensitive operations (delete CA policies, role management, app changes)
  - Validates break-glass account exclusions to prevent emergency access lockouts
  - Identifies policies in report-only mode that should be enabled for enforcement
  - Provides detailed guidance on authentication strength requirements and admin role scoping
  - Reference: [Protected Actions for Conditional Access](https://learn.microsoft.com/entra/identity/conditional-access/how-to-policy-protected-actions)
- **New Finding Category** - "Protected Actions Configuration" with Shield icon (purple) in UI

- **Guest Authentication Strength Check** - New analyzer check that detects policies requiring authentication strength (especially phishing-resistant MFA) for guest/external users
  - Identifies when policies target guest users with MFA or authentication strength requirements
  - Warns that guest users authenticate in their home tenant and require Cross-Tenant Access Settings configuration
  - Distinguishes between B2B Collaboration guests, B2B Direct Connect users, and other guest types
  - Provides severity levels: HIGH for phishing-resistant requirements, MEDIUM for standard MFA
  - Includes detailed guidance on enabling inbound MFA trust in Cross-Tenant Access Settings
  - Links to Microsoft Learn documentation on B2B collaboration authentication and cross-tenant access
  - Reference: [Configure Cross-Tenant Access Settings](https://learn.microsoft.com/entra/external-id/cross-tenant-access-settings-b2b-collaboration)
- **New Finding Category** - "Guest Authentication Requirements" with AlertTriangle icon (orange) in UI

### Context

Guest users in Microsoft Entra authenticate in their home tenant, not the resource tenant. When Conditional Access policies require MFA or authentication strength for guests, the resource tenant must trust inbound MFA claims via Cross-Tenant Access Settings. Without this trust enabled, guest users will be blocked even if they completed MFA in their home tenant. This check helps organizations identify these configurations and provides step-by-step remediation guidance.

### Technical Details

- Added `checkGuestAuthenticationStrength()` function to `src/lib/analyzer.ts`
- Added `checkProtectedActions()` function to `src/lib/analyzer.ts`
- Updated `src/components/findings-list.tsx` with new category metadata
- Detects both authentication strength policies and standard MFA requirements targeting guests
- Analyzes `includeGuestsOrExternalUsers` conditions to identify specific guest types affected

---

## [1.3.0] - 2026-04-04

### Added

- **Windows Hello / Platform SSO Registration Constraint Check** - Identifies CA policies that may block Windows Hello for Business and macOS Platform SSO credential provisioning starting May 2026
  - Validates policies targeting "Register security info" user action
  - Flags report-only policies requiring activation before enforcement
  - Checks for overly restrictive location/compliance requirements incompatible with DRS
  - Severity adjusts based on policy state and control configuration


### Context

Starting May 2026, Microsoft will enforce Conditional Access policies targeting "Register security info" during Windows Hello for Business and macOS Platform SSO credential provisioning (not just sign-in). This update helps organizations prepare by identifying policies that may block legitimate device enrollment flows.

### Technical Details

- Added `checkCredentialRegistrationConstraints()` function to `src/lib/analyzer.ts`
- Updated `src/components/findings-list.tsx` with new category metadata
- Commit: `fc3c2b2` - feat: add May 2026 credential registration constraint check

---

## [1.2.0] - 2026-04-03

### Added

- **Privileged Role Exclusion Check** - Flags when high-privilege Entra ID roles (Global Admin, Privileged Role Admin, etc.) are excluded from CA policies
  - Detects 14 critical admin role exclusions
  - Provides attack scenarios based on policy context (security info registration, MFA bypass, block bypass)
  - Critical severity for Global Admin, Privileged Role Admin, Privileged Auth Admin, CA Admin exclusions
  - Tenant-wide check for policies excluding critical roles
  - Per-policy severity adjustments based on policy type and controls

- **Guest/External User Exclusion Check** - Flags when guest/external users are excluded from CA policies
  - Detects both simple ("GuestsOrExternalUsers") and structured guest exclusions
  - Parses 6 guest user types (b2bCollaborationGuest, b2bCollaborationMember, etc.)
  - Checks for compensating guest-specific policies
  - Adjusts severity based on presence of compensating policy
  - Tenant-wide gap analysis for guest coverage

- **New Finding Categories**
  - "Privileged Role Exclusion" with ShieldAlert icon (red)
  - "Guest/External User Exclusion" with AlertTriangle icon (orange)
  - "Guest/External User Coverage" with ShieldAlert icon (orange)

### Fixed

- Removed disabled-policy filtering from privileged role and guest exclusion checks
  - Rationale: Configuration issues like Global Admin exclusions are critical even on disabled policies (could be enabled without review)
  - Commit: `60d2052` - fix: flag privileged role and guest exclusions on disabled policies too

### Technical Details

- Added `checkPrivilegedRoleExclusions()` function with HIGH_PRIVILEGE_ROLE_IDS map
- Added `checkGuestExternalUserExclusions()` function with GUEST_TYPE_LABELS map
- Integrated checks into `analyzeAllPolicies()` call chain
- Updated findings-list.tsx with category metadata
- Commits: `4068d18`, `bac30ca`, `60d2052`

---

## [1.1.0] - 2026-02-26

### Added

- Device Registration Bypass check (pre-existing feature, discovered during deployment)
  - Flags when Device Registration Service (01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9) is targeted with location or compliance conditions
  - Based on MSRC VULN-153600: DRS ignores location/compliance conditions by design, only honors MFA grant controls
  - Recommends creating dedicated MFA-only policy for DRS resource

### Changed

- Improved findings display in both Findings and Policies tabs
- Category grouping with icons for better visual organization
- Repeat findings gathered together for cleaner UI

---

## Earlier Versions

For changes prior to February 2026, see git history.

---

## Categories Reference

The analyzer uses the following finding categories:

- **Privileged Role Exclusion** - High-privilege roles excluded from policies
- **Guest/External User Exclusion** - Guest/external users excluded from policies
- **Guest/External User Coverage** - Tenant-wide guest coverage gaps
- **Credential Registration Constraints** - Constraints that may block WHfB/Platform SSO setup
- **Device Registration Bypass** - DRS targeted with location/compliance conditions
- **FOCI Token Sharing** - FOCI family exclusions enabling token sharing
- **Resource Exclusion Bypass** - Resource exclusions creating bypass paths
- **CA-Immune Resources** - Resources immune to CA by design
- **User-Agent Bypass** - Platform/client app conditions enabling UA spoofing
- **Swiss Cheese Model** - Policy scope or control gaps
- **App Exclusion** - High-risk app exclusions
- **Policy Scope** - Policy targeting issues
- **Policy State** - Report-only or disabled policies
- **Resilience** - Session control and resilience issues
- **Location Configuration** - Named location configuration issues
- **Legacy Authentication** - Legacy auth blocking gaps
- **MFA Coverage** - MFA enforcement gaps
- **Break-Glass** - Break-glass account issues
- **MS Learn: Documented Exclusion** - Exclusions documented in MS Learn
- **Microsoft-Managed Policies** - Microsoft-managed policy issues

---

[Unreleased]: https://github.com/Jhope188/ca-policy-analyzer/compare/v1.7.0...HEAD
[1.7.0]: https://github.com/Jhope188/ca-policy-analyzer/compare/v1.6.0...v1.7.0
[1.6.0]: https://github.com/Jhope188/ca-policy-analyzer/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/Jhope188/ca-policy-analyzer/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/Jhope188/ca-policy-analyzer/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/Jhope188/ca-policy-analyzer/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/Jhope188/ca-policy-analyzer/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/Jhope188/ca-policy-analyzer/releases/tag/v1.1.0
