# Changelog

All notable changes to the CA Policy Analyzer will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.17.0] - 2026-09-02

### Added

- **New findings category: "Found missing service principals that bypasses your security gate"** - apps that signed in over the last 30 days but have no service principal. Such an app isn't in the Conditional Access app picker at all, so it can be neither included nor excluded; only a policy targeting *All resources* reaches it ([Microsoft docs](https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-cloud-apps)). Discovery diffs `/beta/auditLogs/signInEventsAppSummary` against your service principals; per app it shows the evidence from your own logs (last seen, Request ID, user, IP, client app, deep links to Graph Explorer and the Entra sign-in logs) and what Entra recorded in `appliedConditionalAccessPolicies` on that sign-in.
- **Policy impact evaluator** (`src/lib/policy-app-impact.ts`) - which policies would hit an app once it exists, as `willApply` / `mayApply` / `willNotApply`. Covers include/exclude by app ID, `None`, the `Office365` suite, application filters on custom security attributes, `clientAppTypes`, user scoping and workload identities; other conditions are reported as gates that must also match.
- **Phantom exclusion detection** - a policy excluding an app that has no service principal. The exclusion protects nothing today and becomes live the moment the app is created. Its own critical finding.
- **Generated PowerShell script** - `Register-MissingServicePrincipals.ps1`, downloadable from the finding. `-WhatIf`-first, and apps an enabled block policy would catch carry a `# BLOCKED BY: <policy>` comment on the line you'd delete.
- **The sign-in log scan is optional, and its scope is requested incrementally.** It is on by default; a *Scan sign-in logs* switch on the connect and Run Analysis screens turns it off, and the choice is remembered per browser. With it off the app only ever asks for the three base scopes, skips the heaviest step of the run, and the category reports itself as not scanned. `AuditLog.Read.All` is read-only but needs admin consent and Entra ID P1, so asking for it up front would block the whole analysis in tenants that can't grant it.
- **Step-by-step run progress** - the single spinning label inside the Run Analysis button is replaced by the actual step list for this run, with a progress bar and the skipped step named. The list comes from `src/lib/run-steps.ts`, which both the Graph client and the UI read, so an emitted label can't drift from the rendered one and leave the run looking frozen.
- **Completion panel** - score, grade, policies read, findings by severity and elapsed time when a run finishes, holding briefly before the dashboard takes over. Accent goes amber rather than green when critical findings are open. Offers a one-click re-scan with sign-in logs when the scan was skipped.
- **Offline mode** - the export script now emits a `signInApps` dataset. Older exports import fine.
- **Self-checks** - `check-policy-app-impact.ts` (24), `check-findings-render.tsx` (21), `check-links.ts`, `check-auth-url.ts` (6). Run with `npx tsx`.

### Changed

- **Interactive token fallback redirects instead of opening a popup** (`src/lib/graph-client.ts`) - requesting a scope the cached token doesn't cover makes this previously unreachable fallback fire, which is how incremental consent for the sign-in log scan is delivered. `acquireTokenPopup` leaves a `Popup`-type response in the URL that makes MSAL's `isInPopup()` true, after which every `acquireTokenSilent` throws `block_nested_popups` for the rest of the session.

**Upgrade note:** existing sessions are unaffected until the sign-in log scan is used. Switching it on triggers one consent redirect for `AuditLog.Read.All`.

## [1.16.3] - 2026-07-22

### Fixed

- **Locations — "not marked as trusted" warning is now context-aware** — check #4 previously fired a `Medium` warning for *any* IP-range location used by an enabled policy that wasn't marked as trusted, including locations like `_Blocked IPs` that are intentionally included in block policies where the trusted flag is irrelevant. The warning now only fires when the tenant has at least one policy using `"All trusted locations"` — because that is the only scenario where the `isTrusted` flag actually changes user behaviour (MFA bypass, reduced sign-in frequency, risk-policy exemptions). The warning text has been updated to explain the concrete impact (number of AllTrusted policies affected) and the recommendation now explicitly acknowledges block-list locations as a valid reason to dismiss the warning.

## [1.16.2] - 2026-07-22

### Fixed

- **Offline Export Instructions link 404 on GitHub Pages** — the "Offline Export Instructions" button on the landing screen used a plain `<a href="/offline-export">` tag. On GitHub Pages the site is served from `/ca-policy-analyzer/`, so the absolute path routed to `https://jhope188.github.io/offline-export` (missing the repo prefix) and returned a 404. Replaced with Next.js `<Link href="/offline-export">` which automatically prepends `basePath` at build time. Added a **← Back to analyzer** `<Link>` on the offline export guide page so users can return without the browser back button.

- **False "Present" for `APP - SESSION - O365 - TimeoutSettings`** — fingerprint now requires `sessionApplicationEnforcedRestrictions: true` (weight 25) and `requireSpecificApp: true`. Previously any policy targeting All Users + any app (e.g. "Require MFA for all users") scored 100 % because the distinctive session control was absent from the fingerprint. The check now only reports Present when the matched policy specifically targets Office 365 **and** has app-enforced restrictions enabled.

- **False "Present" for `APP - BLOCK - SharePoint-OneDrive - NonTrustedLocations`** — fingerprint now sets `requireSpecificApp: true`. Previously the app-targeting scorer gave full credit to any policy targeting "All" apps (e.g. a generic block-by-IP/country policy targeting all resources) because "All ⊇ SharePoint". This template now requires the policy to explicitly target the SharePoint Online app ID (`00000003-0000-0ff1-ce00-000000000000`) — generic all-apps block policies no longer match.

- **Template matcher — `requireSpecificApp` flag** — `src/lib/template-matcher.ts` now respects a new `requireSpecificApp?: boolean` fingerprint field. When set, a policy targeting `includeApplications: ["All"]` does **not** satisfy the app requirement; the policy must specifically list the app. The existing broader behaviour (All apps satisfies any template) is preserved for all templates that do not set this flag.

- **Template matcher — `sessionApplicationEnforcedRestrictions` scoring** — added a 25-point branch to `scorePolicyMatch()` for the app-enforced restrictions session control, enabling templates to fingerprint O365 browser-only / read-only settings policies accurately.

### Added

- **`.github/ISSUE_TEMPLATE/incorrect-check-report.md`** — structured bug-report template for incorrect template match or analyzer finding results. Captures: check name, expected vs actual status, policy JSON, screenshots, and browser/version info.
- **`.github/PULL_REQUEST_TEMPLATE.md`** — PR template covering root cause, per-file change summary, before/after status table, and a full checklist (TypeScript, build, regression fixture, CHANGELOG, category metadata).
- **`docs/FIXING-CHECKS.md`** — developer guide for fixing checks and template fingerprints. Covers fingerprint field reference table (all fields + weights), step-by-step fingerprint fix workflow, analyzer check function template, regression fixture instructions, and common pitfalls.
- **`README.md` Contributing section** — documents required information for bug reports and PRs (policy JSON, screenshot, expected status), links to the new guide, and sets expectations for incomplete issues.

## [1.16.1] - 2026-07-10

### Added

- **Offline mode — import CA policies from a PowerShell JSON export** ([@chrisfriday](https://github.com/chrisfriday), [PR #12](https://github.com/Jhope188/ca-policy-analyzer/pull/12)) — full analysis without direct tenant connectivity:
  - New **offline import parser** (`src/lib/offline-import.ts`) with broad Graph PowerShell v2/Beta compatibility — handles PascalCase keys, `AdditionalProperties`, single-object collections, null array fields, and null guest/auth-strength placeholders produced by real-world `ConvertTo-Json` exports.
  - New **`/offline-export` in-app guide page** — step-by-step PowerShell export instructions using the Graph PowerShell v2 Beta module.
  - **Redesigned opening screen** — two explicit paths: *Offline import* and *Direct tenant connection*. Header shows an "Offline mode" indicator when an import is active; clears on return to home.
  - **Security hardening**: 20 MB file-size limit enforced before parsing; 40-level recursion depth guard in key normalisation.
  - PowerShell export command: `Get-MgBetaIdentityConditionalAccessPolicy | ConvertTo-Json -Depth 10 | Out-File ca-export.json`

## [1.16.0] - 2026-07-10

### Changed

- **False-positive reduction — findings are now configuration- and context-aware** ([@dermo-blast](https://github.com/dermo-blast), [PR #18](https://github.com/Jhope188/ca-policy-analyzer/pull/18)) — 7 surgical fixes across `analyzer.ts` and `persona-coverage.ts`:
  1. **`checkGrantControlOperator`** — `compliantDevice OR domainJoinedDevice` and `approvedApplication OR compliantApplication` downgrade from High → Info. Both are Microsoft-recommended equivalent-strength patterns (hybrid device trust / MAM). Genuinely mixed-strength ORs (e.g. `mfa OR compliantDevice`) still flag High.
  2. **Break-glass checks skip workload/agent-identity policies** — `includeUsers: ["None"]` sentinel is now correctly identified as non-user-targeting via a shared `policyTargetsUsers()` helper, preventing workload policies from being flagged for missing break-glass exclusions and inflating tenant-wide coverage counts.
  3. **`checkAllUsersAllApps` is break-glass-aware** — break-glass is subtracted from the exclusion tally (it's expected hygiene, already praised by the dedicated break-glass check). App exclusions remain Medium; other non-break-glass group exclusions drop to Low; break-glass-only → suppressed.
  4. **`checkDeviceRegistrationBypass` is intent- and context-aware** — no longer fires on policies that already require MFA (DRS honors MFA); suppressed when a dedicated register-device MFA policy already exists (the documented mitigation); severity scales with whether registration is explicitly targeted vs. incidentally covered via "All apps".
  5. **`checkMissingMFA` is device/agent-aware** — skips agent-identity policies (can't do interactive MFA) and policies whose sole controls are strong device-trust/app-protection (valid standalone controls layered on a separate MFA baseline).
  6. **`checkUserAgentBypass` downgrades to Info** when a broad block-unknown-platforms companion policy already exists (the very thing its own remediation recommends). Still flags High when no companion exists.
  7. **Guest MFA finding: High → Info** — requiring MFA for guests is best practice; finding is now an operational advisory (configure cross-tenant trust) rather than a security gap. Low-privilege-scope de-dup: `all-resources-exclusion-change` no longer promoted to the main findings list (retained in exclusion-findings view). Built-in CA app groups (`Office365`, `MicrosoftAdminPortals`) now recognised instead of labelled "unrecognized app ID".
  8. **`persona-coverage` credits All-Users policies to Admins + Developers** — a tenant-wide policy now correctly reduces per-persona coverage gaps for admin and developer personas. Guest-targeting policies also credit Guest Admins.

## [1.15.21] - 2026-06-11

### Changed

- **Joey Verlinden preset updated to release 2026.6.1** — preset URL now points at the `2026.6.1` tag (`https://github.com/j0eyv/ConditionalAccessBaseline/tree/2026.6.1/Config`) instead of `main`. The new release ships 38 ConditionalAccess policies (down from 67 — several CA005/CA006 variants consolidated), 36 exclusion groups, and 3 named locations. Label updated to "Joey Verlinden — Conditional Access Baseline 2026.6.1".

## [1.15.20] - 2026-06-02

### Changed

- **Template Coverage header updates dynamically per selected baseline** — score ring, Present/Partial/Missing counts, and the applicable-policies subtitle now recalculate live based on whichever baseline is selected in the dropdown. Selecting **Lewis Barry - Baseline** shows scores and counts scoped to his 13 templates; switching back to **Jon Hope - Baseline** restores the original tenant-wide score.

## [1.15.19] - 2026-06-02

### Changed

- **Dropdown labels standardised** — both options now follow the same pattern: `🏠 Jon Hope - Baseline` and `🧰 Lewis Barry - Baseline`.

## [1.15.18] - 2026-06-02

### Changed

- **Lewis Barry template display names updated to match conditionalaccess.uk exactly** — all 13 templates renamed from the `LB - CA0X - ...` convention to the exact names on the site (e.g. `CA01: MFA all users all resources`, `CA02: Block Legacy Auth`, `CA06: Block Code Flow`, `CA08: User Risk - High - Reset PW`).

## [1.15.17] - 2026-06-02

### Fixed

- **Lewis Barry templates excluded from coverage score and counts** — `lewis-barry` category templates are now filtered out of `presentCount`, `partialCount`, `missingCount`, `totalTemplates`, and the weighted `coverageScore` in [src/lib/template-matcher.ts](src/lib/template-matcher.ts). They are a supplemental view only and must not affect the main tenant score.

### Changed

- **Built-in baselines dropdown default** — first option is now `🏠 Jon Hope - Baseline` (default); `🧰 Lewis Barry - Baseline` is the second option.

## [1.15.16] - 2026-06-02

### Changed

- **Lewis Barry templates hidden from main template list** — excluded from the default view and only shown when the dropdown is set to that baseline.
- **Built-in baselines UI changed to `<select>` dropdown** — replaces the toggle button. Selecting Lewis Barry filters the list and shows a "Clear" link.
- **Renamed to "Lewis Barry - Baseline"** — updated in `CATEGORY_META`, dropdown, and description.

## [1.15.15] - 2026-06-02

### Added

- **Lewis Barry built-in baseline — 13 templates** (`CA01`–`CA12` + `CA11B`) sourced from [conditionalaccess.uk](https://conditionalaccess.uk/blog/some-policies-i-use-in-conditional-access/) by Lewis Barry (Microsoft MVP). New `"lewis-barry"` `TemplateCategory` with `CATEGORY_META` entry (`🧰`). All templates carry a `prerequisites` field crediting Lewis with a link to his article.
- **`DeploymentPolicy.grantControls` extended** — added optional `authenticationStrength?: { id: string; displayName?: string }` for CA10 (FIDO2) and CA11B (TAP).

## [1.15.14] - 2026-06-02

### Removed

- **`intune-grant-mobile-desktop` template removed** — redundant with the separate `intune-grant-mobile` and `intune-grant-desktop` templates; caused duplicate matches and inflated coverage counts.

## [1.15.13] - 2026-06-02

### Fixed

- **`INTUNE - GRANT - Require App Protection (Mobile)` fingerprint fixed** — was cross-matching the compliant-device template. Now checks `builtInControls` for `"compliantApplication"` (weight 25) with a negative signal (weight −20) when `"compliantDevice"` is present without `"compliantApplication"`.

## [1.15.12] - 2026-06-02

### Added

- **`ZTCA - BLOCK - AuthTransfer` template** — covers policies that block the `authenticationTransfer` authentication flow.

## [1.15.11] - 2026-06-02

### Fixed

- **`ZTCA - BLOCK - DeviceCodeFlow` fingerprint no longer matches auth-transfer policies** — added explicit `deviceCodeFlow` assertion (weight 30) and a negative signal (weight −25) when `authenticationTransfer` is present without `deviceCodeFlow`.

## [1.15.10] - 2026-06-02

### Fixed

- **`AGENT - BLOCK - NonTrustedAgents` fingerprint corrected** — was checking `includeUsers: ["All"]` but the real policy uses `includeUsers: ["None"]` with scoping via `clientApplications`. Fixed fingerprint and deployment JSON.

## [1.15.9] - 2026-06-02

### Fixed

- **`P2 - USER RISK` template no longer cross-matches sign-in risk policy** — added `userRiskLevels` check (weight 30) with mutual negative signals between user-risk and sign-in risk templates.

## [1.15.8] - 2026-06-02

### Fixed

- **`AGENT - BLOCK - NonTrustedAgents` deployment JSON corrected** — `grantControls` was `null`; updated to `{ operator: "OR", builtInControls: ["block"] }`.

## [1.15.7] - 2026-06-02

### Fixed

- **`P2 - SIGN-IN RISK` fingerprint corrected** — was missing the `signInRiskLevels` check entirely, causing it to match the user-risk policy at higher confidence. Added `signInRiskLevels: ["high", "medium"]` (weight 30) with a negative signal when `userRiskLevels` is present without `signInRiskLevels`.

## [1.15.6] - 2026-06-02

### Fixed

- **App exclusion count now includes unrecognized app IDs** — `checkServicePrincipalExclusions` in [src/lib/analyzer.ts](src/lib/analyzer.ts) previously silently dropped any excluded app ID that was not found in the service principal map, `CA_BYPASS_APPS`, or `APP_DESCRIPTION_MAP`, causing the finding title to report fewer apps than the policy actually excluded (e.g. "4 app(s) excluded" when the policy had 5 excluded apps). The guard has been removed so every excluded app ID is always included in the finding. Unresolved IDs fall back to displaying the raw app ID as the name with a purpose of "Unrecognized app ID — not found in service principal list or known app catalog."

## [1.15.5] - 2026-06-02

### Fixed

- **`AGENT - BLOCK - HighRiskAgents` template corrected for the Graph API agent identity fields** — the fingerprint was matching wrong policies at 71% (Device Code, Legacy Auth, Countries) because it checked `signInRiskLevels: ["high"]`, which is a completely different Graph API field from the one used by agent CA policies. The real `IAC - AGENT - BLOCK - HighRiskAgent` policy in the Graph API uses `conditions.agentIdRiskLevels: "high"` (a preview field, string not array) and `conditions.clientApplications.includeAgentIdServicePrincipals: ["All"]`, with `conditions.users.includeUsers: ["None"]` since principal scoping is done via `clientApplications` not `users`. All four relevant files were updated:
  - **[src/lib/graph-client.ts](src/lib/graph-client.ts)** — added `agentIdRiskLevels?: string` to `ConditionalAccessConditionSet` and `includeAgentIdServicePrincipals?: string[]` / `excludeAgentIdServicePrincipals?: string[]` to `ClientApplications`; `agentIdRiskLevels` is now parsed in `parsePolicy`.
  - **[src/data/policy-templates.ts](src/data/policy-templates.ts)** — added `agentIdRiskLevels?: string[]` and `targetsAgentIdentities?: boolean` to `TemplateFingerprint`; added `agentIdRiskLevels?: string` to `DeploymentPolicy` conditions type; fixed the `agent-block-high-risk` fingerprint to use the new fields instead of `signInRiskLevels`; fixed `deploymentJson` to use `includeUsers: ["None"]` and `agentIdRiskLevels: "high"`.
  - **[src/lib/template-matcher.ts](src/lib/template-matcher.ts)** — added `targetsAgentIdentities` check (weight 15) reading `clientApplications.includeAgentIdServicePrincipals`; added `agentIdRiskLevels` check (weight 20) reading `conditions.agentIdRiskLevels`.
  - **[src/lib/github-templates.ts](src/lib/github-templates.ts)** — fingerprint builder now extracts `agentIdRiskLevels` and `includeAgentIdServicePrincipals` from GitHub policy JSON so custom-repo agent policies are fingerprinted correctly.

## [1.15.4] - 2026-06-02

### Added

- **Prerequisites field for templates with external dependencies** — `PolicyTemplate` in [src/data/policy-templates.ts](src/data/policy-templates.ts) now has an optional `prerequisites?: string` field. The `INTUNE - SESSION - Block File Downloads On Unmanaged Devices` template uses it to surface a visible warning that **Microsoft Defender for Cloud Apps (MDCA)** must be active and Office 365 apps onboarded before the policy can enforce file-download blocking. [src/components/templates-view.tsx](src/components/templates-view.tsx) renders the field as an amber ⚠ "Prerequisites" card between the "Why this matters" and "CIS Controls" sections.

### Fixed

- **GitHub template loader no longer recurses into `Test/` subdirectories** — `fetchJsonFiles` in [src/lib/github-templates.ts](src/lib/github-templates.ts) previously loaded policy files from every subdirectory of the configured repo, including `Test/` and `New/`. It now skips any directory whose name matches `test`, `tests`, `scratch`, `temp`, or `tmp` (case-insensitive), preventing test/draft policies from appearing as gap-analysis templates.

## [1.15.3] - 2026-05-30

### Added

- **Informational finding for safe "Register security info" policies (MC1326253)** — the credential-registration check in [src/lib/analyzer.ts](src/lib/analyzer.ts) previously stayed silent on policies targeting `urn:user:registersecurityinfo` that had no blocking constraints, so a well-configured registration policy (MFA / authentication strength only) surfaced *no* finding at all and gave no indication it would be affected by the July 2026 change. It now emits an **info-level** finding confirming the policy targets *Register security info*, that it will begin applying during **Windows Hello for Business** and **macOS Platform SSO** registration from **July 6, 2026** (complete July 13), and that it looks safe because it carries no device-compliance, trusted-location, approved/protected-app, or device-filter constraints. The message is report-only-aware (prompts to switch report-only policies to *On* before enforcement) and links to MC1326253. Policies that *do* carry blocking constraints continue to raise the existing medium/high finding.

## [1.15.2] - 2026-05-30

### Changed

- **"Register security info" credential-registration check updated for the confirmed MC1326253 rollout** — Microsoft has now published the official Message Center post **MC1326253** ("Conditional Access policies now apply to Windows Hello for Business and macOS Platform SSO registration"), superseding the earlier preliminary guidance. The `checkCredentialRegistrationConstraints` check in [src/lib/analyzer.ts](src/lib/analyzer.ts) was updated with the confirmed scope and dates: Conditional Access policies scoped to **Register security info** will be evaluated during **Windows Hello for Business** and **macOS Platform SSO** credential registration, closing the gap where these flows previously enforced MFA but did *not* evaluate registration-targeting CA policies (authentication strength, trusted locations, other Grant controls). Gradual rollout begins **July 6, 2026** and completes **July 13, 2026**. The finding title, description, report-only-mode guidance, and reference link (MC1326253 / [policy-all-users-security-info-registration](https://learn.microsoft.com/entra/identity/conditional-access/policy-all-users-security-info-registration)) were all updated from the previous "May 2026 / MC March 2026" placeholders.

## [1.15.1] - 2026-05-29

### Fixed

- **CIS §1.3.2 (Idle session timeout) now recognises 'Use app enforced restrictions'** — the check previously only matched a `signInFrequency` session control, so a correctly configured policy using the **app enforced restrictions** control (the canonical CIS mechanism) was incorrectly reported as *Fail* with "nothing is enforcing it". The official CIS v7.0.0 §1.3.2 audit looks for a CA policy with `ApplicationEnforcedRestrictions.IsEnabled` targeting **Office 365** with **browser** client apps — app enforced restrictions is what signals SharePoint/OWA to apply the admin-center idle timeout, and the protocol itself scopes the timeout to unmanaged (non-compliant, non-domain-joined) devices. [src/data/cis-benchmarks.ts](src/data/cis-benchmarks.ts) now passes on either (a) app enforced restrictions on Office 365 for All users, or (b) a sign-in-frequency ≤ 3h policy scoped to unmanaged devices. The description, remediation, and portal guidance were rewritten to describe the two-part control (admin-center timeout + CA policy) and note that the admin-center value is not readable via Graph.

## [1.15.0] - 2026-05-28

### Changed

- **CIS benchmark upgraded from v6.0.0 to v7.0.0** — CIS Microsoft 365 Foundations Benchmark v7.0.0 consolidated every Conditional Access recommendation into a single new section, **§5.2.2 Conditional Access** (under Entra ID → ID Protection), and renumbered them `5.2.2.1`–`5.2.2.17`. All controls in [src/data/cis-benchmarks.ts](src/data/cis-benchmarks.ts) were remapped to the new IDs, titles were updated to the official v7 wording, and the alignment score now reflects the v7 §5.2.2 set (plus the §1.3.2 idle-session control).
- **Level reassignments per v7:** phishing-resistant MFA for admins (`5.2.2.5`) → **L2**; exclusionary geographic controls (`5.2.2.15`) → **L2**; sign-in risk blocking (`5.2.2.8`) → **L2**; admin sign-in frequency (`5.2.2.4`) → **L1**; managed device for authentication (`5.2.2.9`) → **L1**.
- **`5.2.2.4` broadened** — now checks for limited admin sign-in frequency **and** documents the non-persistent browser requirement (`Never persistent`) that v7 adds to the control.
- **`5.2.2.12` device-code check tightened** — now matches only the `deviceCodeFlow` authentication-flow method, so it no longer overlaps with the new authentication-transfer control.

### Added

- **Four new v7 controls** in [src/data/cis-benchmarks.ts](src/data/cis-benchmarks.ts):
  - **`5.2.2.11`** (L1) — Sign-in frequency for **Microsoft Intune Enrollment** set to *Every time* (matches the `everyTime` interval on the Intune Enrollment resource, app ID `d4ebce55-015a-49b5-a083-c84d1797ae8c`).
  - **`5.2.2.13`** (L1) — **Periodic reauthentication** required for all users (sign-in frequency ≤ 7 days on All users → All resources).
  - **`5.2.2.14`** (L2) — At least one **trusted IP-range named location** defined (evaluated against the tenant's named locations).
  - **`5.2.2.17`** (L1) — **Authentication transfer** blocked (block grant with the `authenticationTransfer` flow condition).
- **Supplementary CA hardening tier** — five v6 controls with no v7 §5.2.2 equivalent (`5.3.3` guest/external MFA, `5.3.10` CAE not disabled, `5.3.11` unknown-platform block, `5.4.1` high-risk users blocked, `5.4.5` mobile app protection) are now flagged `supplementary: true`, grouped under a separate *"Supplementary — CA Hardening"* section, and **excluded from the official v7 alignment score** while still being evaluated and displayed.

### Fixed

- **CIS controls now render in numeric ID order** — [src/components/cis-view.tsx](src/components/cis-view.tsx) sorts controls with a natural comparator so `5.2.2.2` sorts before `5.2.2.10`, and supplementary `5.3.x`/`5.4.x` controls group after the §5.2.2 set. The L1/L2 breakdown tiles count only the official (non-supplementary) controls.
- Refreshed stale `CIS 5.3.11` references in [src/lib/analyzer.ts](src/lib/analyzer.ts), the benchmark file header, and README to reflect v7 numbering.

## [1.14.8] - 2026-05-08

### Changed

- **Built-in guest baseline split into two templates** — the legacy `baseline-mfa-guests` template (single `GLOBAL - GRANT - MFA - External-Guest-Users` covering all six external user types in one policy) was collapsing two distinct tenant policies into one entry. Replaced with two purpose-built templates that match Microsoft's two operational guest buckets:
  - **`baseline-mfa-b2b-guest`** — `GLOBAL - GRANT - MFA - B2B-Guest` covers `internalGuest, b2bCollaborationMember, b2bDirectConnectUser, serviceProvider` (first-party B2B partners + trusted service providers).
  - **`baseline-mfa-mixed-guests`** — `GLOBAL - GRANT - MFA - Mixed-Guests` covers `b2bCollaborationGuest, otherExternalUser` (invited collaboration guests + ad-hoc external identities).
- Together they still cover all six external user types but allow ops to apply different auth-strength / session controls per bucket. The `deploymentJson` for each template now matches the corresponding policy in [Jhope188/ConditionalAccessPolicies/Updated/Policies](https://github.com/Jhope188/ConditionalAccessPolicies/tree/main/Updated/Policies).
- Updated the analyzer's compensating-policy recommendation to reference both new template names instead of the retired `GuestsExternal` name.

### Note

- For the layered Inforcer baseline (Jon Hope preset shipped in v1.14.7) the JSON download already pulls each policy from `Updated/Policies/` first and falls back to `Policies/` when no Updated version exists — that's the layered fetcher's contract from v1.14.7. No further change required for custom-template downloads.

## [1.14.7] - 2026-05-08

### Added

- **Layered GitHub baselines (primary + fallback folder)** — staged-migration repos that publish updated policies in one folder while keeping the original exports in another are now fully supported. The new loader fetches both folders, dedups by `displayName` (with vendor prefix stripped — e.g. `IAC - …` and `ACME - …` collapse), and prefers the primary folder so the *Updated* version always wins.
  - New helper [fetchLayeredGitHubTemplates](src/lib/github-templates.ts) in `src/lib/github-templates.ts` runs the two fetches in parallel, merges bundles (groups, named locations, migration table), and reports a status string like `Loaded 50 unique policies (38 from primary + 12 fallback + 33 groups + 5 named locations).`
  - New `KnownBaseline.fallbackUrl` field in [src/lib/personas.ts](src/lib/personas.ts) opts a one-click baseline into the layered loader; the buttons in [src/components/templates-view.tsx](src/components/templates-view.tsx) automatically pass it through.
  - `localStorage["customRepoUrl"]` now stores `{ url, fallbackUrl }` JSON when a fallback is in play (legacy plain-string values still restore correctly).
- **Pre-loaded "Jon Hope — Inforcer baseline (Updated + fallback)" preset** — one-click load of [Jhope188/ConditionalAccessPolicies](https://github.com/Jhope188/ConditionalAccessPolicies) with `Updated/Policies/` as primary (newer two-category guest model: `B2B-Guest` + `Mixed-Guests`) and `Policies/` as fallback for any policy not yet migrated.

### Fixed

- **PowerShell PascalCase JSON exports now parse correctly** — `ConvertTo-Json | Out-File` emits `DisplayName`, `Conditions`, `GrantControls`, etc., whereas the Microsoft Graph API uses camelCase. Previously the loader silently classified these as `unknown` and skipped them. The fetch pipeline now runs every JSON payload through a recursive `normalizeKeys()` pass at ingest, so PascalCase and camelCase exports work interchangeably. `@odata.*` and `$`-prefixed keys are preserved verbatim.

## [1.14.6] - 2026-05-08

### Fixed

- **Persona detection — CamelCase tokens and `CA<nnn>` prefix mapping** — Joey Verlinden-style policy names like `CA300-ServiceAccounts-...`, `CA400-GuestUsers-...`, and `CA501-Agents-...` were landing in the *Unclassified* persona bucket. Two root causes:
  1. The token regexes used `\b` word boundaries, which don't fire on CamelCase joins (e.g. `\bguests?\b` does NOT match `GuestUsers` because there is no word boundary between `t` and `U`). Replaced with explicit start/end boundaries that treat any non-alphanumeric character OR an uppercase letter following lowercase as a token break.
  2. The token vocabulary was missing `ServiceAccounts` (Joey's CA300 series), `GuestUsers` (CA400 series), and `Agents` / `AIAgents` / `CopilotAgents` (CA500 series — Microsoft Entra Agent Identities are workload identities).
- Added a numeric `CA<nnn>` prefix fallback that maps unknown-but-numbered baselines: `CA0xx → global`, `CA1xx → admins`, `CA2xx → internals`, `CA3xx → corpserviceaccounts`, `CA4xx → externals`, `CA5xx → workloadidentities`. Token matches still take precedence so explicit names always win.
- Result: Joey's full baseline now classifies cleanly into the right persona buckets instead of falling through to *Unclassified*. Verified against `CA300-ServiceAccounts-...` → `corpserviceaccounts`, `CA400-GuestUsers-...` → `externals`, `CA501-Agents-...` → `workloadidentities`.

## [1.14.5] - 2026-05-08

### Changed

- **Phishing-resistant detection unified across all surfaces** — extracted the detection logic into a single shared module [src/lib/phishing-resistant.ts](src/lib/phishing-resistant.ts) so the Zero Trust scorecard, the Persona × Control matrix, and the per-policy analyzer findings (Guest Authentication Strength, Protected Actions) all use the same authoritative implementation.
  - Two additional displayName-only checks were converted to use the shared helper:
    - `checkGuestAuthenticationStrength()` — guest auth-strength severity classification (Phishing-resistant MFA → high vs other strengths → medium) previously matched only the displayName regex `phishing-resistant`. A custom strength like `Modern MFA + TAP` would have been downgraded to medium even though it enforces FIDO2.
    - `checkProtectedActions()` — the "consider phishing-resistant MFA" advisory finding for Protected Actions policies similarly missed custom strengths whose `allowedCombinations` are phishing-resistant. The advisory will no longer fire against policies that already enforce FIDO2 / WHfB / x509 cert MFA via a custom strength.
  - Both checks now resolve `authenticationStrength.id` against `TenantContext.authStrengthPolicies` and inspect `allowedCombinations` for the canonical tokens `fido2`, `windowsHelloForBusiness`, `x509CertificateMultiFactor`, `x509CertificateSingleFactor`, `deviceBoundPasskey`, `hardwareOath`.
  - The shared helper also matches the well-known built-in strength id `00000000-0000-0000-0000-000000000004` directly and retains the displayName regex as a defensive fallback for the case where the strength catalog isn't available.

## [1.14.4] - 2026-05-08

### Fixed

- **Persona × Control Coverage — `phishing-resistant-mfa` detector** — same root cause as v1.14.2 but in a different code path. The Personas tab and the persona-driven *Critical: Admins missing Phishing-resistant MFA* finding both relied on `hasPhishingResistantMfa()` in [src/lib/persona-coverage.ts](src/lib/persona-coverage.ts), which only inspected the auth-strength **displayName** with a regex. A custom strength named `Modern MFA + TAP` whose `allowedCombinations` are `[windowsHelloForBusiness, fido2, x509CertificateMultiFactor, temporaryAccessPassOneTime, temporaryAccessPassMultiUse]` was misclassified as **Missing** for the Admins persona, and the Admins persona then surfaced a critical "missing Phishing-resistant MFA" finding.
  - Detector signature changed to `(policy, context?) => boolean` so it can resolve the strength id against `TenantContext.authStrengthPolicies` and inspect `allowedCombinations` directly. Tokens treated as phishing-resistant: `fido2`, `windowsHelloForBusiness`, `x509CertificateMultiFactor`, `x509CertificateSingleFactor`, `deviceBoundPasskey`, `hardwareOath`.
  - Also matches the well-known built-in **Phishing-resistant MFA** strength id `00000000-0000-0000-0000-000000000004` directly.
  - The displayName regex (on both the strength and the policy) is kept as a defensive fallback.
  - `analyzePersonaCoverage()` now threads `context` through to every detector call so future detectors can use catalog data without further refactor.

## [1.14.3] - 2026-05-08

### Fixed

- **Tenant-wide MFA Coverage finding — report-only awareness** — the *"No policy requires MFA for All Users"* finding under `checkTenantWideGaps()` previously fired as **critical** whenever no `state === "enabled"` policy targeted All Users with MFA, even when a fully-formed **report-only** (`enabledForReportingButNotEnforced`) policy already covered the case. Operators with policies like `IAC - GLOBAL - GRANT - MFA - AllUsers` running in report-only mode were getting a misleading critical finding that read *"No enabled policy was found..."*.
  - Check now scans both `enabled` and `enabledForReportingButNotEnforced` states.
  - When only a report-only policy covers MFA-for-All-Users, the finding is rewritten as **"MFA for All Users exists but is Report-only"**, severity is downgraded **critical → medium**, the finding now references the actual policy id and name (instead of `tenant-wide`), and the recommendation guides the operator to promote after 7–14 days of telemetry observation.
  - The original critical finding still fires when neither enabled nor report-only coverage exists.
- Helper `isMfaForAll(policy)` extracted in [src/lib/analyzer.ts](src/lib/analyzer.ts) so the check is reused for both the enabled and report-only scans.

## [1.14.2] - 2026-05-08

### Fixed

- **Zero Trust scorecard — phishing-resistant MFA detection** — the "Phishing-resistant MFA in use" signal under the *Verify Explicitly* pillar previously only matched the `displayName` of the authentication strength against a regex. Custom strengths (e.g. `Modern MFA + TAP`) that **contain** FIDO2 / Windows Hello for Business / x509 certificate MFA combinations were missed even though they are phishing-resistant.
  - The detection now resolves the policy's `authenticationStrength.id` against the tenant's authentication-strength catalog (`TenantContext.authStrengthPolicies`) and inspects `allowedCombinations` directly. Tokens treated as phishing-resistant: `fido2`, `windowsHelloForBusiness`, `x509CertificateMultiFactor`, `x509CertificateSingleFactor`, `deviceBoundPasskey`, `hardwareOath`.
  - Also matches the well-known built-in **Phishing-resistant MFA** strength id `00000000-0000-0000-0000-000000000004` directly.
  - The displayName regex is kept as a defensive fallback for snapshots where the strength catalog hadn't loaded.
  - Evidence string now names the matching strength, e.g. *"1 policy uses a phishing-resistant auth strength (e.g. \"Modern MFA + TAP\")."*
- New helper `policyUsesPhishingResistant(policy, context)` in [src/lib/zero-trust-scorecard.ts](src/lib/zero-trust-scorecard.ts).

## [1.14.1] - 2026-05-08

### Changed — Phase 5 deployment plan now ships as a ZIP bundle

- The "Download deployment plan" button on the **Baseline Gap** tab now produces a **ZIP bundle** (`ca-deployment-plan-<baseline>-<date>.zip`) instead of a single JSON file. The ZIP contains:
  - `README.md` — human-readable instructions, ordered by **Zero Trust criticality** (Critical → High → Medium → Low). Within each tier, personas appear in the canonical Zero Trust order from `PERSONA_ORDER` (Global → Admins → Internals → Externals → Guest Admins → Developers → CorpServiceAccounts → WorkloadIdentities). Each policy entry links to its own JSON file on disk.
  - `deployment-plan.json` — the original machine-readable manifest (unchanged shape, schema v1) — useful for scripted iteration in PowerShell.
  - `policies/<persona>/<template>.json` — one Graph-ready `ConditionalAccessPolicy` body per file, suitable for direct upload via Graph PowerShell, DCToolbox, `Invoke-MgGraphRequest`, or `curl`.
- `src/lib/deployment-plan.ts` adds `downloadDeploymentBundle(plan)` which builds the ZIP via [JSZip](https://stuk.github.io/jszip/) and triggers a browser download. The legacy single-file `downloadDeploymentPlan()` is still exported for any consumers that prefer raw JSON, but the UI button no longer uses it.
- The README inside the bundle bakes in **four auto-import recipes** (Microsoft Graph PowerShell SDK, DCToolbox, `Invoke-MgGraphRequest`, and Bash + curl + jq) so the operator can pick whichever fits their workflow without leaving the bundle.
- Bundle layout is documented in the README's "Bundle layout" section so the operator can selectively deploy a single persona by importing only that subdirectory.

### Dependencies
- Add **`jszip ^3.10.1`** for ZIP creation in the browser.

## [1.14.0] - 2026-05-08

### Added — Zero Trust Persona Framework — Phases 5 & 6

#### Phase 5 — Deployment Plan Generator
- New module [src/lib/deployment-plan.ts](src/lib/deployment-plan.ts) converts the **Baseline Gap** report into a Graph-ready import bundle:
  - `buildDeploymentPlan(gaps, templateResult, baselineLabel)` — emits a `DeploymentPlan` (schemaVersion 1) containing every *missing* and *drift* entry with the template's full `deploymentJson` body (conditions / grantControls / sessionControls), the originating persona, severity, and the reason for inclusion
  - **Every body's `state` is forced to `disabled`** before write — operators must explicitly enable each policy in their tenant after review
  - Bundles built-in **PowerShell + DCToolbox import recipes** in `PLAN_INSTRUCTIONS` so the JSON is self-documenting
  - `deploymentPlanToFileMap(plan)` produces a `{path: content}` map ready for future ZIP packaging (`deployment-plan.json`, `README.md`, `policies/<persona>/<id>.json`)
  - Tenant-only entries are skipped (nothing to deploy from a custom tenant policy back into a baseline)
- **"Download deployment plan"** button added to [src/components/baseline-gap-view.tsx](src/components/baseline-gap-view.tsx) — visible only when both a template result is loaded and at least one missing/drift entry exists; clicking exports a single JSON via `Blob` + `URL.createObjectURL`

#### Phase 6 — Persona-aware PowerPoint export
- [src/lib/export-utils.ts](src/lib/export-utils.ts) `exportToPowerPoint` now accepts optional `personaResult`, `scorecard`, and `baselineGap` arguments and inserts new slides between the policy slides and the CIS slide:
  - **Zero Trust Scorecard slide** — three rounded-rect pillar cards (Verify Explicitly / Least Privilege / Assume Breach) with the pillar score color-coded (green ≥80, yellow ≥50, red <50) and the top 5 signals listed underneath each pillar with score + evidence
  - **Persona × Control Coverage summary slide** — table of every persona that has at least one assigned policy with columns *Persona / Policies / Score / Present / Partial / Missing*
  - **Per-persona detail slides** — one slide per persona that has assigned policies *or* baseline gaps, each showing the persona's score badge, a 5-card stat strip (Assigned / Enabled / Present / Partial / Missing), a left-column table listing the persona's controls (sorted missing → partial → present, top 10) and a right-column gap section with Missing / Drift / Tenant-only counts plus the top 6 gap entries sorted by severity
  - **Baseline Gap slide** — top stat row (Missing / Drift / Tenant-only / Coverage %) plus per-persona table *Persona / Missing / Drift / Tenant-only / Total*
- The full Zero Trust framework story (pillars → persona summary → per-persona deep-dives → baseline gap) now flows through to the executive deck automatically when the source data is available
- Wired into [src/app/page.tsx](src/app/page.tsx) PPTX export call

### Changed
- `runAnalysis` in [src/app/page.tsx](src/app/page.tsx) now tracks the active template result in a local `activeTemplates` variable so subsequent analysis steps (composite scoring, baseline gap) consume the most recent template set without waiting for React state to flush
- `BaselineGapView` accepts a new optional `templateResult` prop; the deployment-plan download button only appears when this prop is supplied

## [1.13.0] - 2026-05-08

### Added
- **Zero Trust Persona Framework — Phase 4: Baseline Gap Analysis** — new top-level **Baseline Gap** tab that diffs the live tenant against a *loaded* Zero Trust baseline (Kenneth, Joey, custom GitHub repo, or the built-in template set):
  - New analyzer [src/lib/baseline-gap.ts](src/lib/baseline-gap.ts) reclassifies the existing `TemplateAnalysisResult` into three actionable buckets:
    - **Missing** — baseline policy with no tenant equivalent (severity tracks the template priority: critical/recommended/optional → critical/high/medium)
    - **Drift** — baseline policy is partially matched in the tenant; differences are surfaced inline (closest tenant policy name + every diff the matcher already detected)
    - **Tenant-only** — enabled tenant policy that doesn’t map to any baseline template (potential custom policy, drift, or coverage gap in the baseline itself)
  - **Persona-bucketed output** — every gap is grouped by Zero Trust persona using the same `detectPersona` heuristics as Phase 1–3, so the operator sees “Admins is missing 3 baseline policies and has 2 unaccounted-for tenant policies” at a glance
  - **Coverage score** 0–100 = `(present + 0.5 × partial) / applicable_templates` — a single number that tracks how closely the tenant follows the loaded baseline
  - New view component [src/components/baseline-gap-view.tsx](src/components/baseline-gap-view.tsx) with toggleable Missing/Drift/Tenant-only filters, persona-grouped expandable cards, severity badges, and per-entry evidence drawers
  - Lazy-derived via `useMemo` from `(context, templateResult)` — zero extra Graph calls; recomputes automatically when the user loads a different baseline via “Compare Custom Repo”
  - Tab is hidden until both context and a template result are available, so the surface area only appears when there’s something to diff

### Changed
- New tab key `baseline` (between `templates` and `cis`) added to `ViewTab`; `lucide-react` `GitCompareArrows` icon used as the tab affordance

## [1.12.0] - 2026-05-08

### Added
- **Zero Trust Persona Framework — Phase 3: Zero Trust Scorecard** — new dashboard widget that scores the tenant against [Microsoft's three Zero Trust principles](https://learn.microsoft.com/security/zero-trust/zero-trust-overview):
  - New analyzer [src/lib/zero-trust-scorecard.ts](src/lib/zero-trust-scorecard.ts) — rolls up evidence from `analyzeAllPolicies` + `analyzePersonaCoverage` into 15 weighted signals across 3 pillars (no extra Graph calls, no double-counting)
  - **Verify Explicitly** (5 signals): MFA coverage of enabled policies, phishing-resistant authentication strengths in use, compliant/Hybrid-joined device requirements, risk signals consumed (sign-in/user/named-locations), Admins MFA per persona coverage
  - **Use Least Privilege** (5 signals): persona segmentation (admins vs internals vs externals), privileged-role exclusions (inverse of analyzer findings), policy scope (penalizes `users=All ∧ apps=All ∧ no-controls`), break-glass account presence, FOCI / token-theft risk findings (inverse)
  - **Assume Breach** (5 signals): legacy auth blocked, sign-in risk policies, user risk policies, session controls (sign-in frequency / persistent browser), open critical+high findings backlog (inverse)
  - Each signal has a 0–100 score, a weight (1–3), an evidence string, and a status (good ≥80, warn ≥50, bad <50, n/a when not applicable)
  - Pillar score = weighted average of non-N/A signals; Overall = simple average of the three pillars
  - New view component [src/components/zero-trust-scorecard.tsx](src/components/zero-trust-scorecard.tsx) — three pillar cards with color-coded score, progress bar, and click-to-expand signal breakdown showing every input that fed the pillar
  - Renders at the top of the **Dashboard** tab so posture against the three principles is the first thing you see after analysis

### Changed
- `Dashboard` component now accepts an optional `scorecard` prop and renders the Zero Trust card above the existing score ring + finding-severity breakdown
- `runAnalysis` in [src/app/page.tsx](src/app/page.tsx) calls `buildZeroTrustScorecard(ctx, mergedResult, persona)` after composite scoring so the persona-merged finding set feeds the Assume-Breach backlog signal

## [1.11.0] - 2026-05-07

### Added
- **Zero Trust Persona Framework — Phase 2: Persona × Control Coverage** — new top-level **Personas** tab that scores the tenant against the required-control matrix defined in [src/lib/personas.ts](src/lib/personas.ts):
  - New analyzer [src/lib/persona-coverage.ts](src/lib/persona-coverage.ts) buckets every CA policy into one or more personas (by displayName, plus structural fallbacks: `includeUsers=All` → Global+Internals, `includeRoles` populated → Admins, `includeGuestsOrExternalUsers` → Externals)
  - Detects 10 required controls per persona — `block-legacy-auth`, `require-mfa`, `require-compliant-device`, `sign-in-risk`, `user-risk`, `session-sif`, `block-countries`, `phishing-resistant-mfa`, `block-non-corp-network`, `block-high-risk-apps`
  - Each control gets a status of **Present** (enabled policy enforces it), **Report-only** (only enforced in report-only mode), **Missing**, or **N/A**
  - Per-persona score card with overall coverage ring, expandable control breakdown, and a list of every policy assigned to that persona (with state)
  - **Critical gaps surface as findings** in the Findings tab and exports — Admins missing MFA → critical; Internals missing user-risk → medium; etc. Severity is tuned per persona × control pair
- New view component [src/components/persona-view.tsx](src/components/persona-view.tsx) with persona cards, status badges, and expandable per-control evidence (which policies enforce / report-only enforce each control)

### Changed
- `analyzeAllPolicies` results now include the persona-coverage findings merged into `result.findings` so every existing surface (Findings list, Excel/PowerPoint export, dashboard counts) sees the new gap detections without duplicate analyzer runs

## [1.10.2] - 2026-05-07

### Fixed
- **Joey Verlinden baseline now actually loads (real fix)** — files were UTF-16 LE, not UTF-8 with BOM. The fetcher now reads response bodies as `ArrayBuffer` and sniffs the BOM to pick the right `TextDecoder` (UTF-16 LE / UTF-16 BE / UTF-8 with or without BOM). PowerShell `ConvertTo-Json | Out-File` on Windows defaults to UTF-16 LE, which produced mojibake when decoded as UTF-8.

### Added
- **Restore-bundle awareness** — the GitHub loader now recognizes the full DCToolbox-style export structure (CA policies + `Groups/` + `NamedLocations/` + `MigrationTable.json`):
  - Each fetched JSON is classified as `capolicy`, `group`, `namedlocation`, `migrationtable`, or `unknown` based on file path, `@odata.type`, `@odata.context`, and shape — companion files no longer get reported as "invalid CA policy exports"
  - Companion artifacts are collected into a `BaselineBundle` (group id → displayName, named-location id → displayName, migration-table presence) returned alongside the templates for future GUID-resolution work
  - Status message now reports the full bundle, e.g. `Loaded 67 policies + 33 groups + 2 named locations + migration table.`
- New exported types: `BaselineBundle`, extended `GitHubTemplateResult` with optional `bundle` field

### Changed
- **Joey Verlinden preset now points at [`Config/`](https://github.com/j0eyv/ConditionalAccessBaseline/tree/main/Config)** (parent folder) instead of `Config/ConditionalAccess` so the loader picks up the full restore bundle automatically

## [1.10.1] - 2026-05-07

### Fixed
- **Joey Verlinden baseline now loads correctly** — github-templates fetcher now strips UTF-8 BOM (PowerShell `ConvertTo-Json | Out-File` writes a leading BOM that broke `JSON.parse`)
- **Broader CA policy validation** — accept any export with `displayName` + `conditions` object (previously required non-null `conditions.users` or `conditions.applications`, which rejected baselines with minimal condition blocks)
- Joey Verlinden preset URL now deep-links to [`Config/ConditionalAccess`](https://github.com/j0eyv/ConditionalAccessBaseline/tree/main/Config/ConditionalAccess)

### Changed
- **Removed Claus Jespersen preset button** — repo is the canonical Zero Trust framework reference but is no longer actively maintained as a deployable baseline. Credited as a guidance reference in [docs/zero-trust-persona-framework.md](docs/zero-trust-persona-framework.md) only.

## [1.10.0] - 2026-05-07

### Added
- **Zero Trust Persona Framework (Phase 1)** — Adds persona-based intelligence to the Templates tab, aligned with [Claus Jespersen's Microsoft framework](https://github.com/microsoft/ConditionalAccessforZeroTrustResources) and the [Welkasworld design guide](https://www.welkasworld.com/post/conditional-access-naming-conventions-personas-design-process)
  - **Persona detection** from policy `displayName`: Global, Admins, Internals, Externals, GuestAdmins, Developers, CorpServiceAccounts, WorkloadIdentities, Microsoft365ServiceAccounts
  - **One-click baseline loading** — Three preset buttons in the GitHub repo input load community Zero Trust baselines:
    - Kenneth van Surksum — [`cabaseline202510`](https://github.com/kennethvs/cabaseline202510)
    - Joey Verlinden — [`ConditionalAccessBaseline`](https://github.com/j0eyv/ConditionalAccessBaseline)
    - Claus Jespersen — [`ConditionalAccessforZeroTrustResources`](https://github.com/microsoft/ConditionalAccessforZeroTrustResources)
  - **Persona-based grouping** — When a loaded repo uses persona naming (Admins, Internals, Externals, Workload, etc.), policies group by persona automatically with persona descriptions and expected control hints. Falls back to existing CAD/CAL/CAP prefix grouping otherwise.
  - **New reference doc** — [docs/zero-trust-persona-framework.md](docs/zero-trust-persona-framework.md) consolidating persona taxonomy, naming conventions, expected control bundle per persona, and references to Welkasworld, Claus Jespersen, and community baselines.

### Roadmap
- **Phase 2** — Persona × required-control coverage matrix as a tenant-wide analyzer finding
- **Phase 3** — Zero Trust pillar scorecard (Verify Explicitly / Least Privilege / Assume Breach) on the dashboard
- **Phase 4** — Gap analysis comparing tenant against a chosen baseline (Kenneth / Joey / Claus)

## [1.9.0] - 2026-04-17

### Added
- **Custom GitHub Template Comparison** — Compare your tenant policies against any public GitHub repository containing CA policy JSON exports
  - New "Compare Custom Repo" button on the Templates tab
  - Accepts GitHub URLs (`https://github.com/owner/repo`) or shorthand (`owner/repo`)
  - Supports deep links to specific branches/paths (`/tree/main/Policies`)
  - Auto-detects JSON files in root or common subdirectories (`Policies/`, `policies/`, `CA/`)
  - Converts Graph API CA policy JSON into templates with auto-generated fingerprints
  - Re-runs the template matching engine against custom templates
  - Shows custom repo attribution with "Back to default" reset button
- **Persistent custom repo across refreshes** — Selected GitHub repo URL saved to localStorage and auto-restored on next analysis run
- **Prefix-based grouping for custom repos** — Custom repo templates grouped by naming prefix (CAD, CAL, CAP…) instead of Foundation/Baseline categories, sorted numerically within each group

### Changed
- **Privileged Role Exclusion check now detects compensating policies** — When admin roles are excluded from an MFA policy, the analyzer checks if another enabled policy covers those roles with MFA or authentication strength. If covered, severity drops from critical/high to info with a note identifying the covering policy.

### Fixed
- **Break-glass severity for disabled/report-only policies** — Disabled policies missing break-glass raised from info → **low**, report-only raised from info → **medium**
- **Entra Connect version corrected** — DirSync app-based auth was introduced in v2.5.76.0, not v2.5.79
- **DirSync check now links to version history** — `docUrl` updated to the [Entra Connect version history](https://learn.microsoft.com/entra/identity/hybrid/connect/reference-connect-version-history) article

## [1.8.0] - 2026-04-11

### Added
- **Per-Policy Break-Glass Annotations** — Every Conditional Access policy now shows whether the break-glass account/group is excluded
  - Fires on ALL policies in the tenant, not just the 7 critical policy types
  - Severity-aware annotations:
    - **Info**: Break-glass excluded ✓ (positive confirmation)
    - **High**: NOT excluded on block + all users + all apps policies
    - **Medium**: NOT excluded on MFA / compliance + all users policies
    - **Low**: NOT excluded on other enabled policies
    - **Medium**: NOT excluded on report-only policies (will block break-glass once switched to enabled)
    - **Low**: NOT excluded on disabled policies (will block break-glass if enabled without adding exclusion)
    - **Info**: Disabled Microsoft managed policies show guidance to add before enabling
  - Skips workload-identity-only policies (no user targeting)
  - Resolves display names for break-glass accounts/groups from directory objects

### Changed
- **Tenant-Wide Break-Glass Summary — Now shows total policy coverage counts**
  - Title shows "X of Y policies" with total tenant policy count
  - Description includes full breakdown: total policies, user-targeting policies, with/without break-glass counts
  - Lists specific policies missing break-glass exclusions
  - Extracted break-glass identification into reusable `identifyBreakGlass()` helper shared by per-policy and tenant-wide checks
  - Removed duplicate identification logic (Steps 1–5) from tenant-wide section

### Fixed
- **CIS MS Learn Link Audit — 7 controls had wrong articles** (links were shifted between neighboring controls)
  - **5.3.3** (Guest MFA): Was "Block legacy auth" → Now [Require MFA for external users](https://learn.microsoft.com/entra/identity/conditional-access/policy-guest-mfa-strength)
  - **5.3.5** (MFA for device registration): Was "Sign-in risk" → Now [Require MFA for device registration](https://learn.microsoft.com/entra/identity/conditional-access/policy-all-users-device-registration)
  - **5.3.6** (Sign-in risk): Was "User risk" → Now [Sign-in risk-based CA policy](https://learn.microsoft.com/entra/identity/conditional-access/policy-risk-based-sign-in)
  - **5.3.9** (Legacy auth block): Was "Require MFA for device registration" → Now [Block legacy authentication](https://learn.microsoft.com/entra/identity/conditional-access/policy-block-legacy-authentication)
  - **5.3.12** (Device code flow): Was "Compliant device for admins" → Now [Block device code flow](https://learn.microsoft.com/entra/identity/conditional-access/policy-block-device-code-flow)
  - **5.4.1** (High-risk users): Was linking to sign-in risk article → Now [Block access for high-risk users](https://learn.microsoft.com/entra/identity/conditional-access/policy-risk-based-user)
  - **5.4.2** (High-risk sign-ins): Was linking to user risk article → Now [Block access for high-risk sign-ins](https://learn.microsoft.com/entra/identity/conditional-access/policy-risk-based-sign-in)
  - **5.4.5** (App protection): Was linking to device-compliance URL → Now [Require app protection policy](https://learn.microsoft.com/entra/identity/conditional-access/policy-all-users-app-protection)

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

#### Guest / External User MFA Enforcement Model

> 📘 **Full reference:** see [docs/external-user-mfa-reference.md](docs/external-user-mfa-reference.md) for per-type detail, supported method tables, and authentication strength matrix.

Where MFA completes depends on **two** things: (1) whether the user authenticates via Entra ID, and (2) whether inbound cross-tenant MFA trust is configured. Without trust, even Entra-backed B2B guests complete MFA at the resource tenant — the home tenant path is opt-in.

| CA External User Type | Identity Provider | MFA Enforced By | Auth Strength Support | Cross-Tenant Trust Required |
|---|---|---|---|---|
| **Local / Internal Guest** (`internalGuest`) | Your own tenant | Resource tenant — always | ✅ Full method set | No |
| **B2B Collab Guest** (`b2bCollaborationGuest`) — Entra-backed | External Entra tenant | Either (trust-dependent) | ✅ Supported | Optional (enables home tenant path) |
| **B2B Collab Guest** (`b2bCollaborationGuest`) — non-Entra | Google / OTP / SAML / WS-Fed | Resource tenant — always | ❌ NOT supported (use basic `mfa`) | N/A |
| **B2B Collab Member** (`b2bCollaborationMember`) | External Entra tenant | Either (trust-dependent) | ✅ Supported | Optional (enables home tenant path) |
| **B2B Direct Connect** (`b2bDirectConnectUser`) | External Entra tenant | Home tenant — mandatory | ✅ Supported (home methods only) | **REQUIRED** (else blocked) |
| **Service Provider** (`serviceProvider`) — GDAP/CSP | Partner Entra tenant | Home tenant — always | Partial (home methods only) | Auto-trusted by Microsoft |
| **Other External** (`otherExternalUser`) | Non-Entra | Resource tenant — always | ❌ NOT supported (use basic `mfa`) | N/A |

> ⚠️ **Heterogeneity warning:** `b2bCollaborationGuest` contains BOTH Entra-backed and non-Entra guests. CA cannot filter within this type by IdP. If your guest population is mixed, use the basic `mfa` grant control — authentication strength will **block** non-Entra guests instead of prompting them.
>
> ⚠️ **Auth strength hard line:** non-Entra IdP users (Google, email OTP, SAML/WS-Fed) cannot satisfy authentication strength regardless of which CA user type they land under. Phishing-resistant methods (FIDO2, WHfB, CBA, OATH hardware) are only usable from the **home tenant** — inbound MFA trust must be configured to use them.

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

[Unreleased]: https://github.com/Jhope188/ca-policy-analyzer/compare/v1.9.0...HEAD
[1.9.0]: https://github.com/Jhope188/ca-policy-analyzer/compare/v1.8.0...v1.9.0
[1.8.0]: https://github.com/Jhope188/ca-policy-analyzer/compare/v1.7.0...v1.8.0
[1.7.0]: https://github.com/Jhope188/ca-policy-analyzer/compare/v1.6.0...v1.7.0
[1.6.0]: https://github.com/Jhope188/ca-policy-analyzer/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/Jhope188/ca-policy-analyzer/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/Jhope188/ca-policy-analyzer/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/Jhope188/ca-policy-analyzer/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/Jhope188/ca-policy-analyzer/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/Jhope188/ca-policy-analyzer/releases/tag/v1.1.0
