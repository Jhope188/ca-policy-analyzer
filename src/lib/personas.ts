/**
 * Zero Trust Persona Framework
 *
 * Based on Claus Jespersen's Conditional Access for Zero Trust persona model:
 * - https://github.com/microsoft/ConditionalAccessforZeroTrustResources
 * - https://learn.microsoft.com/entra/identity/conditional-access/plan-conditional-access
 *
 * Community baselines that follow this framework:
 * - Kenneth van Surksum: https://github.com/kennethvs/cabaseline202510
 * - Joey Verlinden:      https://github.com/j0eyv/ConditionalAccessBaseline
 *
 * The framework segments identities into ~8 personas, each with its own bundle
 * of CA policies. Naming conventions typically encode the persona in the policy
 * displayName (e.g. "CA101-Admins-Identity-MFA-AnyApp", "CA201-Internals-...").
 */

export type Persona =
  | "global"
  | "admins"
  | "internals"
  | "externals"
  | "guestadmins"
  | "developers"
  | "corpserviceaccounts"
  | "workloadidentities"
  | "microsoft365serviceaccounts"
  | "unknown";

export interface PersonaMeta {
  id: Persona;
  label: string;
  shortLabel: string;
  emoji: string;
  /** Color hint for UI (Tailwind class fragment) */
  color: string;
  /** What this persona covers and why it matters */
  description: string;
  /** Controls expected to be present for this persona */
  expectedControls: PersonaControl[];
}

export type PersonaControl =
  | "block-legacy-auth"
  | "require-mfa"
  | "require-compliant-device"
  | "sign-in-risk"
  | "user-risk"
  | "session-sif"
  | "block-countries"
  | "phishing-resistant-mfa"
  | "block-non-corp-network"
  | "block-high-risk-apps";

export const PERSONA_ORDER: Persona[] = [
  "global",
  "admins",
  "internals",
  "externals",
  "guestadmins",
  "developers",
  "corpserviceaccounts",
  "workloadidentities",
  "microsoft365serviceaccounts",
  "unknown",
];

export const PERSONA_META: Record<Persona, PersonaMeta> = {
  global: {
    id: "global",
    label: "Global",
    shortLabel: "Global",
    emoji: "🌐",
    color: "blue",
    description:
      "Tenant-wide baseline policies that apply to all users (block legacy auth, country blocks, terms of use).",
    expectedControls: ["block-legacy-auth", "block-countries"],
  },
  admins: {
    id: "admins",
    label: "Admins (Privileged Roles)",
    shortLabel: "Admins",
    emoji: "🛡️",
    color: "red",
    description:
      "Privileged directory role holders. Should require phishing-resistant MFA, compliant device, and tight session controls.",
    expectedControls: [
      "require-mfa",
      "phishing-resistant-mfa",
      "require-compliant-device",
      "sign-in-risk",
      "user-risk",
      "session-sif",
    ],
  },
  internals: {
    id: "internals",
    label: "Internals (Employees)",
    shortLabel: "Internals",
    emoji: "👤",
    color: "emerald",
    description:
      "Standard internal members. MFA, compliant device, sign-in risk and user risk policies expected.",
    expectedControls: [
      "require-mfa",
      "require-compliant-device",
      "sign-in-risk",
      "user-risk",
    ],
  },
  externals: {
    id: "externals",
    label: "Externals (B2B Guests)",
    shortLabel: "Externals",
    emoji: "🤝",
    color: "amber",
    description:
      "B2B collaboration guests and members from partner Entra tenants. MFA via auth strength (when home tenant trusts it) or basic MFA grant.",
    expectedControls: ["require-mfa"],
  },
  guestadmins: {
    id: "guestadmins",
    label: "Guest Admins (External Privileged)",
    shortLabel: "GuestAdmins",
    emoji: "🛡️🤝",
    color: "orange",
    description:
      "External admins (GDAP/CSP, partner privileged users). Require strong auth and tight session controls.",
    expectedControls: [
      "require-mfa",
      "phishing-resistant-mfa",
      "session-sif",
    ],
  },
  developers: {
    id: "developers",
    label: "Developers",
    shortLabel: "Developers",
    emoji: "💻",
    color: "purple",
    description:
      "Higher-privilege internal developers. Often need access to dev/test tenants and tooling - requires its own MFA + compliant device set.",
    expectedControls: [
      "require-mfa",
      "require-compliant-device",
      "user-risk",
    ],
  },
  corpserviceaccounts: {
    id: "corpserviceaccounts",
    label: "Corporate Service Accounts",
    shortLabel: "CorpSvc",
    emoji: "⚙️",
    color: "cyan",
    description:
      "User-mode service accounts that run automation. Should be locked to specific networks/locations and excluded from interactive MFA.",
    expectedControls: ["block-non-corp-network"],
  },
  workloadidentities: {
    id: "workloadidentities",
    label: "Workload Identities",
    shortLabel: "Workload",
    emoji: "🤖",
    color: "violet",
    description:
      "Service principals and managed identities. Require Workload Identities Premium and CA policies targeting servicePrincipals.",
    expectedControls: ["block-non-corp-network", "sign-in-risk"],
  },
  microsoft365serviceaccounts: {
    id: "microsoft365serviceaccounts",
    label: "Microsoft 365 Service Accounts",
    shortLabel: "M365Svc",
    emoji: "🔧",
    color: "slate",
    description:
      "Sync accounts (Entra Connect, on-prem hybrid). Excluded from MFA but locked to known locations.",
    expectedControls: ["block-non-corp-network"],
  },
  unknown: {
    id: "unknown",
    label: "Unclassified",
    shortLabel: "Unclassified",
    emoji: "❓",
    color: "gray",
    description:
      "Policies that do not match any known persona naming convention.",
    expectedControls: [],
  },
};

// ─── Detection ───────────────────────────────────────────────────────────────

/**
 * Token patterns that map to each persona. Order matters - more specific
 * patterns (e.g. "GuestAdmin") are tested before broader ones ("Guest").
 *
 * Match is case-insensitive. Tokens are bounded by `(?<=^|[^A-Za-z0-9])` /
 * `(?=$|[^a-z0-9])` so they fire on hyphen / underscore / space separators
 * AND on CamelCase boundaries (e.g. "GuestUsers" → matches "Guest", and
 * "ServiceAccounts" → matches "ServiceAccounts").
 */
const TB = "(?<=^|[^A-Za-z0-9])"; // token-start boundary (start, or non-alnum)
const TE = "(?=$|[^a-z0-9])"; // token-end boundary (end, or uppercase/non-alnum → CamelCase aware)

const PERSONA_PATTERNS: Array<{ persona: Persona; patterns: RegExp[] }> = [
  // Most specific first
  {
    persona: "microsoft365serviceaccounts",
    patterns: [
      new RegExp(
        `${TB}(microsoft365serviceaccounts?|m365service|m365svc|directorysynchronization|aadc?onnect|entraconnect)${TE}`,
        "i"
      ),
    ],
  },
  {
    persona: "workloadidentities",
    patterns: [
      // Includes "Agents" (Microsoft Entra Agent Identities / AI agents are
      // workload identities) and "ServicePrincipals" / "ManagedIdentities".
      new RegExp(
        `${TB}(workload[\\s_-]?identit(?:y|ies)|workloadid|serviceprincipals?|managedidentit(?:y|ies)|agents?|aiagents?|copilotagents?)${TE}`,
        "i"
      ),
    ],
  },
  {
    persona: "corpserviceaccounts",
    patterns: [
      // "ServiceAccounts" alone (Joey's CA300 series) maps here. The
      // microsoft365serviceaccounts and workloadidentities matchers above are
      // tested first, so they win when their more-specific tokens are present.
      new RegExp(
        `${TB}(corp(?:orate)?[\\s_-]?serviceaccounts?|corpservice|corpsvc|svcaccounts?|service[\\s_-]?accounts?)${TE}`,
        "i"
      ),
    ],
  },
  {
    persona: "guestadmins",
    patterns: [
      new RegExp(
        `${TB}(guestadmins?|externaladmins?|gdap|cspadmins?|partneradmins?)${TE}`,
        "i"
      ),
    ],
  },
  {
    persona: "admins",
    patterns: [
      new RegExp(
        `${TB}(admins?|privilegedusers?|privrole|priv[\\s_-]?roles?)${TE}`,
        "i"
      ),
    ],
  },
  {
    persona: "developers",
    patterns: [new RegExp(`${TB}(developers?|devs?|engineers?)${TE}`, "i")],
  },
  {
    persona: "externals",
    patterns: [
      // "GuestUsers" (Joey's CA400 series) and "Externals" / "B2B" all map here.
      new RegExp(
        `${TB}(externals?|guests?|guestusers?|b2b|external[\\s_-]?users?|externalcollabs?)${TE}`,
        "i"
      ),
    ],
  },
  {
    persona: "internals",
    patterns: [
      new RegExp(
        `${TB}(internals?|employees?|members?|staff|users?[\\s_-]?internal)${TE}`,
        "i"
      ),
    ],
  },
  {
    persona: "global",
    patterns: [
      new RegExp(
        `${TB}(global|alluser|tenantwide|baseline|allapps?|allcloudapps?)${TE}`,
        "i"
      ),
    ],
  },
];

/**
 * Numeric "CA<number>" prefix → persona fallback for baselines (e.g. Joey's)
 * that follow a strict numeric block convention. Only consulted when no token
 * match was found, so explicit naming always wins.
 *
 *   CA0xx / CA00x → Global   (tenant-wide baseline policies)
 *   CA1xx         → Admins   (privileged role policies)
 *   CA2xx         → Internals (employee/member policies)
 *   CA3xx         → Corp Service Accounts
 *   CA4xx         → Externals / Guests
 *   CA5xx         → Workload Identities / Agents
 */
const CA_PREFIX_BLOCKS: Array<{ persona: Persona; range: [number, number] }> = [
  { persona: "global", range: [0, 99] },
  { persona: "admins", range: [100, 199] },
  { persona: "internals", range: [200, 299] },
  { persona: "corpserviceaccounts", range: [300, 399] },
  { persona: "externals", range: [400, 499] },
  { persona: "workloadidentities", range: [500, 599] },
];

function detectPersonaByCaPrefix(displayName: string): Persona | null {
  // Match a leading "CA" followed by 2-4 digits, optionally separated from the
  // rest by hyphen/underscore/space. e.g. "CA300-ServiceAccounts-...".
  const m = /^[\s_-]*CA0*(\d{1,4})\b/i.exec(displayName);
  if (!m) return null;
  const n = parseInt(m[1], 10);
  if (Number.isNaN(n)) return null;
  for (const block of CA_PREFIX_BLOCKS) {
    if (n >= block.range[0] && n <= block.range[1]) return block.persona;
  }
  return null;
}

/**
 * Detect the persona for a given policy displayName by inspecting common
 * naming-convention tokens. Falls back to a numeric "CA<nnn>" prefix block
 * mapping (Joey's framework). Returns "unknown" if neither matches.
 */
export function detectPersona(displayName: string): Persona {
  if (!displayName) return "unknown";
  for (const { persona, patterns } of PERSONA_PATTERNS) {
    if (patterns.some((p) => p.test(displayName))) return persona;
  }
  const byPrefix = detectPersonaByCaPrefix(displayName);
  if (byPrefix) return byPrefix;
  return "unknown";
}

// ─── Known Baselines ─────────────────────────────────────────────────────────

export interface KnownBaseline {
  id: string;
  label: string;
  author: string;
  repoUrl: string;
  /**
   * Optional fallback URL. When set, the loader fetches `repoUrl` first and
   * fills in any missing policies (matched by `displayName`) from this URL -
   * used for staged-migration repos that publish updated policies in one
   * folder while older originals remain in another.
   */
  fallbackUrl?: string;
  description: string;
  source: "claus" | "kenneth" | "joey" | "jhope";
}

/**
 * Curated list of well-known community CA baselines that follow the persona
 * framework. Surfaced as one-click "Load baseline" buttons in the Templates view.
 */
export const KNOWN_BASELINES: KnownBaseline[] = [
  {
    id: "kennethvs",
    label: "Kenneth van Surksum - Baseline 2025.10",
    author: "Kenneth van Surksum (MVP)",
    repoUrl: "https://github.com/kennethvs/cabaseline202510",
    description:
      "Community-maintained Zero Trust persona baseline, refreshed quarterly. Strong reference for production-grade tenants.",
    source: "kenneth",
  },
  {
    id: "joeyv",
    label: "Joey Verlinden - Conditional Access Baseline 2026.6.1",
    author: "Joey Verlinden (MVP)",
    // Point at the Config/ root so the loader picks up the full restore bundle:
    // ConditionalAccess/ (38 policies) + Groups/ (36 exclusion groups) +
    // NamedLocations/ (allowed-countries lists) + MigrationTable.json.
    repoUrl:
      "https://github.com/j0eyv/ConditionalAccessBaseline/tree/2026.6.1/Config",
    description:
      "Persona-based baseline aligned with Microsoft's Zero Trust guidance and Claus Jespersen's framework. Includes a full DCToolbox-style restore bundle (policies + exclusion groups + named locations + migration table).",
    source: "joey",
  },
  {
    id: "jhope188",
    label: "Jon Hope - Inforcer baseline (Updated + fallback)",
    author: "Jon Hope (Inforcer)",
    // Primary: refreshed policies with the two-category guest split
    // (B2B-Guest + Mixed-Guests). Fallback fills in any policy not yet
    // migrated from the original ACME-prefixed exports.
    repoUrl:
      "https://github.com/Jhope188/ConditionalAccessPolicies/tree/main/Updated/Policies",
    fallbackUrl:
      "https://github.com/Jhope188/ConditionalAccessPolicies/tree/main/Policies",
    description:
      "Inforcer-maintained persona baseline. Loader prefers the Updated/Policies/ folder (newer, two-category guest model) and falls back to the original Policies/ folder for any policy not yet migrated.",
    source: "jhope",
  },
];

/**
 * Reference-only sources (not loaded as baselines, credited in docs).
 * Claus Jespersen's repo is the canonical framework reference but is no longer
 * actively maintained as a deployable baseline - cite for guidance only.
 */
export const REFERENCE_SOURCES = [
  {
    id: "clajes",
    label: "Claus Jespersen - Microsoft Zero Trust framework (reference)",
    author: "Claus Jespersen (Microsoft)",
    repoUrl:
      "https://github.com/microsoft/ConditionalAccessforZeroTrustResources",
    description:
      "Original Microsoft persona framework reference. Cite for guidance - not actively maintained as a deployable baseline.",
  },
] as const;
