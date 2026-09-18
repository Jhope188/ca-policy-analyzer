/**
 * Microsoft Graph Client
 *
 * Fetches Conditional Access policies, named locations, service principals,
 * and directory objects for the connected tenant.
 */

import { Client } from "@microsoft/microsoft-graph-client";
import {
  AccountInfo,
  InteractionRequiredAuthError,
  IPublicClientApplication,
} from "@azure/msal-browser";
import { scopesFor } from "./msal-config";
import { RUN_STEPS } from "./run-steps";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ConditionalAccessPolicy {
  id: string;
  templateId?: string | null;
  displayName: string;
  state: "enabled" | "disabled" | "enabledForReportingButNotEnforced";
  createdDateTime: string;
  modifiedDateTime: string;
  conditions: {
    users: {
      includeUsers: string[];
      excludeUsers: string[];
      includeGroups: string[];
      excludeGroups: string[];
      includeRoles: string[];
      excludeRoles: string[];
      includeGuestsOrExternalUsers?: unknown;
      excludeGuestsOrExternalUsers?: unknown;
    };
    applications: {
      includeApplications: string[];
      excludeApplications: string[];
      includeUserActions: string[];
      includeAuthenticationContextClassReferences: string[];
      applicationFilter?: { mode: string; rule: string };
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
    userRiskLevels: string[];
    signInRiskLevels: string[];
    servicePrincipalRiskLevels?: string[];
    devices?: {
      deviceFilter?: { mode: string; rule: string };
    };
    clientApplications?: {
      includeServicePrincipals: string[];
      excludeServicePrincipals: string[];
      servicePrincipalFilter?: { mode: string; rule: string };
      /** Agent identity principal scoping (Preview) */
      includeAgentIdServicePrincipals?: string[];
      excludeAgentIdServicePrincipals?: string[];
    };
    /** Agent identity risk levels (Preview) - separate from signInRiskLevels */
    agentIdRiskLevels?: string;
    insiderRiskLevels?: string;
    authenticationFlows?: {
      transferMethods?: string;
    };
  };
  grantControls?: {
    operator: "AND" | "OR";
    builtInControls: string[];
    customAuthenticationFactors: string[];
    termsOfUse: string[];
    authenticationStrength?: {
      id: string;
      displayName: string;
    };
  };
  sessionControls?: {
    applicationEnforcedRestrictions?: { isEnabled: boolean };
    cloudAppSecurity?: { isEnabled: boolean; cloudAppSecurityType: string };
    signInFrequency?: {
      isEnabled: boolean;
      value: number;
      type: string;
      frequencyInterval: string;
    };
    persistentBrowser?: { isEnabled: boolean; mode: string };
    continuousAccessEvaluation?: { mode: string };
    disableResilienceDefaults?: boolean;
    secureSignInSession?: { isEnabled: boolean };
  };
}

export interface NamedLocation {
  id: string;
  displayName: string;
  isTrusted?: boolean;
  "@odata.type": string;
  ipRanges?: { cidrAddress: string }[];
  countriesAndRegions?: string[];
  countryLookupMethod?: string;
  includeUnknownCountriesAndRegions?: boolean;
}

export interface ServicePrincipal {
  id: string;
  appId: string;
  displayName: string;
  servicePrincipalType: string;
  appOwnerOrganizationId?: string;
  tags?: string[];
}

export interface DirectoryObject {
  id: string;
  displayName: string;
  "@odata.type": string;
}

/**
 * As the sign-in log recorded it - Entra's verdict, not our prediction.
 * `conditionsNotSatisfied` containing "application" is the bypass, evidenced.
 */
export interface AppliedCaPolicy {
  id: string;
  displayName: string;
  /** success | failure | notApplied | notEnabled | reportOnly* | unknown */
  result: string;
  enforcedGrantControls: string[];
  enforcedSessionControls: string[];
  /** Comma-separated multi-valued enum, e.g. "application,users" */
  conditionsSatisfied?: string;
  conditionsNotSatisfied?: string;
}

export interface UnregisteredSignInApp {
  appId: string;
  signInCount: number;
  displayName?: string;
  seenIn?: string;
  signInEventType?: SignInEventType;
  lastSeen?: string;
  requestId?: string;
  userPrincipalName?: string;
  ipAddress?: string;
  clientAppUsed?: string;
  resourceDisplayName?: string;
  conditionalAccessStatus?: string;
  appliedPolicies?: AppliedCaPolicy[];
  isWorkloadIdentity: boolean;
  logQueryUrl: string;
}

export interface UnregisteredSignInAppsResult {
  apps: UnregisteredSignInApp[];
  /** Hit the endpoint's 1000-row ceiling - the list may be incomplete. */
  truncated: boolean;
  /** Beyond the enrichment cap: listed, but without an evidence row. */
  evidenceCapped: number;
  windowStart: string;
}

/**
 * A single sign-in event attributed to one policy via
 * `appliedConditionalAccessPolicies`. `status` reflects Entra's own verdict
 * for that policy on that event - "blocked" for an enabled policy that denied
 * access, "wouldBlock" for a report-only policy that would have.
 */
export interface PolicySignInMatch {
  id: string;
  createdDateTime: string;
  userPrincipalName?: string;
  ipAddress?: string;
  location?: string;
  clientAppUsed?: string;
  status: "blocked" | "wouldBlock";
  /** Human-readable reason derived from conditionsNotSatisfied / grant controls */
  failureReason?: string;
  failureDetail?: string;
}

export interface PolicySignInMatches {
  matches: PolicySignInMatch[];
  /** More matches exist for this policy than we kept (capped per policy). */
  truncated: boolean;
}

export interface PolicySignInLogResult {
  /** Keyed by Conditional Access policy ID */
  byPolicy: Map<string, PolicySignInMatches>;
  windowStart: string;
  /** Hit the overall scan row cap - some recent sign-ins may not be reflected. */
  scanTruncated: boolean;
  /** Total sign-in rows actually read from Graph across all pages fetched -
   * surfaced so "0 matches" is distinguishable from "the scan barely ran". */
  rowsScanned: number;
  /** Of rowsScanned, how many came back with appliedConditionalAccessPolicies
   * missing/empty. Per Microsoft's docs Graph silently omits this field (no
   * error) when the caller can read sign-ins but not CA data - if this equals
   * rowsScanned, every policy will show 0 matches regardless of what actually
   * happened in the tenant, and that's a permissions problem, not a bug here. */
  rowsMissingCaData: number;
  /** Set when a request failed/errored and ended the scan early (timeout,
   * permission error, throttling, etc). Undefined when the scan ran to
   * completion (row cap and time budget are reported via scanTruncated,
   * not this field - only unexpected failures set it). */
  scanError?: string;
  /**
   * Empirical evidence that a policy is already being evaluated against the
   * Windows Azure AD Graph ("baseline scopes") audience - keyed by policy ID,
   * value is the most recent sign-in's createdDateTime where this policy
   * appeared in appliedConditionalAccessPolicies for a sign-in whose resource
   * was Windows Azure Active Directory. Reuses the same scanned rows as
   * byPolicy, so this costs nothing extra.
   *
   * Why this exists: Microsoft's Low-Privilege Scope Enforcement rollout
   * (MC1223829) is a *silent* tenant default once it lands - it writes no
   * record to `advancedSettings.baselineScopes`, so that field reads
   * identically (null) whether the rollout hasn't reached the tenant yet, or
   * whether it has already completed and enforcement is live. The tenant
   * setting alone cannot tell those two states apart; only observed sign-in
   * evidence can. See https://mikecrowley.us/2026/08/03/ca-baseline-scopes-enforcement-impact/
   */
  baselineAudienceEvidence: Map<string, string>;
}

export interface AuthenticationStrengthPolicy {
  id: string;
  displayName: string;
  description: string;
  policyType: "builtIn" | "custom" | "unknownFutureValue";
  /** Authentication method mode combinations, e.g. "password,sms", "fido2", "externalAuthenticationMethodConfiguration,…" */
  allowedCombinations: string[];
  requirementsSatisfied: "none" | "mfa" | "unknownFutureValue";
}

// ─── Tenant Context ──────────────────────────────────────────────────────────

export type LicenseRequirement = "entraIdP1" | "entraIdP2" | "intunePlan1" | "workloadIdPremium";

export interface TenantLicenses {
  hasEntraIdP1: boolean;
  hasEntraIdP2: boolean;
  hasIntunePlan1: boolean;
  hasWorkloadIdPremium: boolean;
}

/** Well-known service plan IDs */
const SERVICE_PLAN_IDS: Record<string, string> = {
  entraIdP1: "41781fb2-bc02-4b7c-bd55-b576c07bb09d",
  entraIdP2: "eec0eb4f-6444-4f95-aba0-50c24d67f998",
  intunePlan1: "c1ec4a95-1f05-45b3-a911-aa3fa01094f5",
  // AAD_WRKLDID_P1 - included in Workload_Identities_Premium_CN SKU
  workloadIdPremiumP1: "84c289f0-efcb-486f-8581-07f44fc9efad",
  // AAD_WRKLDID_P2 - included in Workload_Identities_P2 and Workload_Identities_Premium_CN SKUs
  workloadIdPremiumP2: "7dc0e92d-bf15-401d-907e-0884efe7c760",
};

export interface TenantContext {
  /** Entra ID tenant display name (from /organization) */
  tenantDisplayName: string;
  /** Entra ID tenant ID */
  tenantId: string;
  policies: ConditionalAccessPolicy[];
  namedLocations: NamedLocation[];
  servicePrincipals: Map<string, ServicePrincipal>;
  directoryObjects: Map<string, DirectoryObject>;
  licenses: TenantLicenses;
  /** Authentication strength policies (built-in + custom) - used to detect EAM usage */
  authStrengthPolicies: Map<string, AuthenticationStrengthPolicy>;
  /** Undefined when the scan was skipped - no AuditLog.Read.All, no P1, or an
   * offline export that predates this dataset. */
  unregisteredSignInApps?: UnregisteredSignInAppsResult;
  /** Per-policy sign-in log matches (blocked / would-block). Undefined when
   * the sign-in log scan was skipped, same conditions as unregisteredSignInApps. */
  policySignInMatches?: PolicySignInLogResult;
  /**
   * Tenant-wide Conditional Access settings (identity/conditionalAccess/settings).
   * Null when the tenant has no advancedSettings saved, or when the fetch
   * failed/was not permitted (e.g. missing Policy.Read.All).
   */
  conditionalAccessSettings?: ConditionalAccessSettings | null;
}

/**
 * GET /identity/conditionalAccess/settings (beta) - single $entity, not a
 * collection. advancedSettings.baselineScopes.resourceAppId indicates the
 * Low-Privilege Scope Enforcement ("baseline") audience:
 *   - 00000002-0000-0000-c000-000000000000 => enforcement enabled for
 *     Windows Azure Active Directory (Azure AD Graph)
 *   - 00000000-0000-0000-0000-000000000000 => enforcement explicitly disabled
 *   - any other GUID => enforcement customized to that app
 *   - advancedSettings: null => no selection has ever been saved
 */
export interface ConditionalAccessSettings {
  advancedSettings: {
    baselineScopes?: {
      resourceAppId?: string | null;
    } | null;
    [key: string]: unknown;
  } | null;
  modifiedDateTime?: string | null;
  [key: string]: unknown;
}

// ─── Graph Client Factory ────────────────────────────────────────────────────

function createGraphClient(
  msalInstance: IPublicClientApplication,
  account: AccountInfo,
  scopes: string[]
): Client {
  return Client.init({
    authProvider: async (done) => {
      try {
        const response = await msalInstance.acquireTokenSilent({
          scopes,
          account,
        });
        done(null, response.accessToken);
      } catch (error) {
        // Redirect, never popup: a Popup-type auth response left in the URL
        // makes MSAL's isInPopup() true, after which every acquireTokenSilent
        // throws block_nested_popups for the rest of the session.
        if (error instanceof InteractionRequiredAuthError) {
          try {
            await msalInstance.acquireTokenRedirect({
              scopes,
              account,
            });
            done(
              new Error(
                "Additional permissions are required. Redirecting to Microsoft to grant them…"
              ),
              null
            );
          } catch (redirectError) {
            done(redirectError as Error, null);
          }
        } else {
          done(error as Error, null);
        }
      }
    },
  });
}

// ─── Data Fetching ───────────────────────────────────────────────────────────

async function fetchAllPages<T>(
  client: Client,
  url: string,
  apiVersion?: string
): Promise<T[]> {
  const results: T[] = [];
  let nextLink: string | undefined = url;

  while (nextLink) {
    let req = client.api(nextLink);
    if (apiVersion) req = req.version(apiVersion);
    // Request evolvable enum members (e.g. riskRemediation) that would
    // otherwise be returned as "unknownFutureValue" by the beta endpoint
    if (apiVersion === "beta") {
      req = req.header("Prefer", "include-unknown-enum-members");
    }
    const response = await req.get();
    results.push(...(response.value ?? []));
    nextLink = response["@odata.nextLink"];
  }

  return results;
}

export async function fetchConditionalAccessPolicies(
  client: Client
): Promise<ConditionalAccessPolicy[]> {
  // Use the beta endpoint to ensure policies using preview features
  // (time-based conditions, agents scope, etc.) are included
  return fetchAllPages<ConditionalAccessPolicy>(
    client,
    "/identity/conditionalAccess/policies",
    "beta"
  );
}

export async function fetchNamedLocations(
  client: Client
): Promise<NamedLocation[]> {
  return fetchAllPages<NamedLocation>(
    client,
    "/identity/conditionalAccess/namedLocations"
  );
}

export async function fetchServicePrincipals(
  client: Client
): Promise<ServicePrincipal[]> {
  return fetchAllPages<ServicePrincipal>(
    client,
    "/servicePrincipals?$select=id,appId,displayName,servicePrincipalType,appOwnerOrganizationId,tags&$top=999"
  );
}

export async function fetchAuthenticationStrengthPolicies(
  client: Client
): Promise<AuthenticationStrengthPolicy[]> {
  return fetchAllPages<AuthenticationStrengthPolicy>(
    client,
    "/policies/authenticationStrengthPolicies?$select=id,displayName,description,policyType,allowedCombinations,requirementsSatisfied",
    "beta"
  );
}

// ─── Unregistered Sign-In Apps ───────────────────────────────────────────────

/** All-zero GUID means "unknown app" in the sign-in logs. */
const NULL_GUID = "00000000-0000-0000-0000-000000000000";

/** signInEventsAppSummary tops out at 1000 rows and covers a fixed 30 days. */
const APP_SUMMARY_MAX_ROWS = 1000;
const DISCOVERY_WINDOW_DAYS = 30;

// ponytail: fixed evidence cap, surfaced as `evidenceCapped` so the UI never
// implies full coverage. Make it a user control if anyone actually hits it.
const EVIDENCE_LOOKUP_CAP = 60;
const EVIDENCE_BATCH_SIZE = 20;

/**
 * `/auditLogs/signIns` returns `interactiveUser` unless another type is named
 * in the filter, so an app that only signs in non-interactively - or as a
 * service principal or managed identity - is invisible to an unqualified query.
 */
export type SignInEventType =
  | "interactiveUser"
  | "nonInteractiveUser"
  | "servicePrincipal"
  | "managedIdentity";

export const SIGNIN_EVENT_TYPE_LABELS: Record<SignInEventType, string> = {
  interactiveUser: "Interactive",
  nonInteractiveUser: "Non-interactive",
  servicePrincipal: "Service principal",
  managedIdentity: "Managed identity",
};

/** Interactive first: most common, and needs no filter clause. */
const EVIDENCE_PROBE_ORDER: SignInEventType[] = [
  "interactiveUser",
  "nonInteractiveUser",
  "servicePrincipal",
  "managedIdentity",
];

/**
 * Graph Explorer permalink returning exactly this app's sign-in log entries.
 * `headers` is base64 of `[{name,value}]`; without the `Prefer` header the beta
 * endpoint returns `unknownFutureValue` for the newer `conditionsNotSatisfied`
 * members - the ones that evidence a bypass. No `/en-us/` in the path, so the
 * page opens in the visitor's own locale.
 */
export function buildSignInLogQueryUrl(
  appId: string,
  windowStart: string,
  eventType?: SignInEventType
): string {
  let filter = `appId eq '${appId}' and createdDateTime ge ${windowStart}`;
  if (eventType && eventType !== "interactiveUser") {
    filter += ` and signInEventTypes/any(t: t eq '${eventType}')`;
  }
  const request = `auditLogs/signIns?$filter=${filter}&$top=50`;
  const headers = btoa(
    JSON.stringify([{ name: "Prefer", value: "include-unknown-enum-members" }])
  );

  return (
    "https://developer.microsoft.com/graph/graph-explorer" +
    `?request=${encodeURIComponent(request)}` +
    "&method=GET&version=beta" +
    `&GraphUrl=${encodeURIComponent("https://graph.microsoft.com")}` +
    `&headers=${encodeURIComponent(headers)}`
  );
}

/**
 * Graph Explorer permalink for "the rest" of a policy's sign-in matches
 * beyond what the UI shows inline - same time window and `$select` as the
 * scan itself (so the `appliedConditionalAccessPolicies` column is present),
 * capped at a larger `$top` for manual review.
 *
 * Deliberately does NOT filter server-side by policy id:
 * `appliedConditionalAccessPolicies` is not documented as a filterable
 * property on `/auditLogs/signIns` (only `createdDateTime`, `appId`,
 * `signInEventTypes/any(...)` and a few others are), and a previous attempt
 * to filter on the sibling `conditionalAccessStatus` property was silently
 * rejected by Graph, producing an empty-looking scan instead of an error.
 * Given that history, this link intentionally stays on the known-supported
 * `createdDateTime` filter and asks the admin to locate this policy by name
 * within the `appliedConditionalAccessPolicies` column of the results,
 * rather than risk the same failure mode for a "convenience" filter.
 */
export function buildPolicySignInLogQueryUrl(
  policyDisplayName: string,
  windowStart: string
): string {
  // Left unencoded here, same as buildSignInLogQueryUrl above - the whole
  // `request` string gets encodeURIComponent'd once below when it's placed
  // into the outer URL's query string. Encoding it here too would double-
  // encode (e.g. a literal space becomes %2520 instead of %20).
  const request =
    `auditLogs/signIns?$filter=createdDateTime ge ${windowStart}` +
    `&$select=${POLICY_SIGNIN_SELECT}` +
    `&$orderby=createdDateTime desc` +
    `&$top=200`;
  const headers = btoa(
    JSON.stringify([{ name: "Prefer", value: "include-unknown-enum-members" }])
  );

  return (
    "https://developer.microsoft.com/graph/graph-explorer" +
    `?request=${encodeURIComponent(request)}` +
    "&method=GET&version=beta" +
    `&GraphUrl=${encodeURIComponent("https://graph.microsoft.com")}` +
    `&headers=${encodeURIComponent(headers)}` +
    // Not consumed by Graph Explorer itself - harmless, but documents intent
    // in the URL for anyone inspecting it, and is a no-op if stripped.
    `&note=${encodeURIComponent(
      `Find "${policyDisplayName}" in appliedConditionalAccessPolicies`
    )}`
  );
}

/**
 * Graph Explorer permalink scoped to ONE specific sign-in match - the closest
 * this app gets to "show me just this failed sign-in". Unlike
 * buildPolicySignInLogQueryUrl (date-only, because policy attribution isn't
 * filterable), this filters by `userPrincipalName eq` and a narrow
 * `createdDateTime` window bracketing the exact match - both are documented
 * as filterable on `/auditLogs/signIns`:
 *   https://learn.microsoft.com/en-us/graph/api/resources/signin
 *     userPrincipalName: "Supports $filter (eq, startsWith)"
 *     createdDateTime:   "Supports $orderby, $filter (eq, le, and ge)"
 * This is real, documented filter support - not a repeat of the
 * appliedConditionalAccessPolicies/conditionalAccessStatus mistakes from
 * earlier in this project's history. Still can't filter by policy directly,
 * so the result may include other sign-ins from the same user that day; the
 * exact match is easy to spot since the window is only +/-2 hours.
 *
 * Falls back to `undefined` for matches with no userPrincipalName (e.g. a
 * workload identity / service principal sign-in) - there's no equally
 * reliable narrow filter for those today, so callers should fall back to
 * buildPolicySignInLogQueryUrl in that case rather than get a link that
 * silently returns nothing useful.
 */
export function buildSignInMatchLogQueryUrl(
  match: Pick<PolicySignInMatch, "userPrincipalName" | "createdDateTime">
): string | undefined {
  if (!match.userPrincipalName) return undefined;

  const matchTime = new Date(match.createdDateTime).getTime();
  if (Number.isNaN(matchTime)) return undefined;

  const isoNoMillis = (ms: number) =>
    new Date(ms).toISOString().replace(/\.\d{3}Z$/, ".000Z");
  const WINDOW_MS = 2 * 60 * 60 * 1000; // +/-2h - narrow, but tolerant of clock/paging skew
  const rangeStart = isoNoMillis(matchTime - WINDOW_MS);
  const rangeEnd = isoNoMillis(matchTime + WINDOW_MS);

  // userPrincipalName values from Graph are always lowercase per the docs
  // ("This value is always in lowercase"); escape a literal single quote per
  // OData string-literal syntax ('' inside the quoted string) just in case.
  const upn = match.userPrincipalName.toLowerCase().replace(/'/g, "''");

  const request =
    `auditLogs/signIns?$filter=` +
    `userPrincipalName eq '${upn}' and createdDateTime ge ${rangeStart} and createdDateTime le ${rangeEnd}` +
    `&$select=${POLICY_SIGNIN_SELECT}` +
    `&$orderby=createdDateTime desc` +
    `&$top=25`;
  const headers = btoa(
    JSON.stringify([{ name: "Prefer", value: "include-unknown-enum-members" }])
  );

  return (
    "https://developer.microsoft.com/graph/graph-explorer" +
    `?request=${encodeURIComponent(request)}` +
    "&method=GET&version=beta" +
    `&GraphUrl=${encodeURIComponent("https://graph.microsoft.com")}` +
    `&headers=${encodeURIComponent(headers)}`
  );
}

/**
 * Captured from a live page; Microsoft documents no deep link. A fragment never
 * reaches the server, so a wrong blade looks fine from the outside - hence
 * scripts/check-links.ts pins this one.
 */
export const ENTRA_SIGNIN_LOGS_URL =
  "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/SignInLogsList.ReactView" +
  "/timeRangeType/last24hours/showApplicationSignIns~/true";

export const ENTRA_SIGNIN_LOGS_PATH =
  "Entra ID > Monitoring & health > Sign-in logs";

function normalizeAppliedPolicies(
  raw: unknown
): AppliedCaPolicy[] | undefined {
  if (!Array.isArray(raw) || raw.length === 0) return undefined;
  return raw.map((entry) => {
    const p = (entry ?? {}) as Partial<AppliedCaPolicy>;
    return {
      id: p.id ?? "",
      displayName: p.displayName ?? "(unnamed policy)",
      result: p.result ?? "unknown",
      enforcedGrantControls: p.enforcedGrantControls ?? [],
      enforcedSessionControls: p.enforcedSessionControls ?? [],
      conditionsSatisfied: p.conditionsSatisfied,
      conditionsNotSatisfied: p.conditionsNotSatisfied,
    };
  });
}

const EVIDENCE_SELECT = [
  "id",
  "createdDateTime",
  "userPrincipalName",
  "ipAddress",
  "appDisplayName",
  "clientAppUsed",
  "resourceDisplayName",
  "servicePrincipalId",
  "conditionalAccessStatus",
  "appliedConditionalAccessPolicies",
].join(",");

/**
 * Newest sign-in for one app. `$top=1` with no `$orderby` relies on the
 * endpoint's default newest-first ordering - combining the two is unreliable.
 */
async function fetchAppEvidence(
  client: Client,
  appId: string,
  windowStart: string
): Promise<Partial<UnregisteredSignInApp>> {
  for (const eventType of EVIDENCE_PROBE_ORDER) {
    let filter = `appId eq '${appId}' and createdDateTime ge ${windowStart}`;
    if (eventType !== "interactiveUser") {
      filter += ` and signInEventTypes/any(t: t eq '${eventType}')`;
    }
    try {
      const response = await client
        .api("/auditLogs/signIns")
        .version("beta")
        .header("Prefer", "include-unknown-enum-members")
        .filter(filter)
        .select(EVIDENCE_SELECT)
        .top(1)
        .get();

      const row = response?.value?.[0];
      if (!row) continue;

      return {
        displayName: row.appDisplayName || undefined,
        signInEventType: eventType,
        seenIn: SIGNIN_EVENT_TYPE_LABELS[eventType],
        lastSeen: row.createdDateTime,
        requestId: row.id,
        userPrincipalName: row.userPrincipalName || undefined,
        ipAddress: row.ipAddress || undefined,
        clientAppUsed: row.clientAppUsed || undefined,
        resourceDisplayName: row.resourceDisplayName || undefined,
        conditionalAccessStatus: row.conditionalAccessStatus || undefined,
        appliedPolicies: normalizeAppliedPolicies(
          row.appliedConditionalAccessPolicies
        ),
        isWorkloadIdentity:
          eventType === "servicePrincipal" ||
          eventType === "managedIdentity" ||
          !row.userPrincipalName,
        logQueryUrl: buildSignInLogQueryUrl(appId, windowStart, eventType),
      };
    } catch {
      // Not fatal - the app is still listed, without evidence
    }
  }

  return {};
}

/**
 * Apps that signed in over the last 30 days with no service principal.
 * `signInEventsAppSummary` gives one row per app in one request; paging raw
 * sign-in logs for 30 days is not viable from a browser.
 * Requires `AuditLog.Read.All` and Entra ID P1.
 */
export async function fetchUnregisteredSignInApps(
  client: Client,
  servicePrincipals: Map<string, ServicePrincipal>
): Promise<UnregisteredSignInAppsResult> {
  const windowStart = new Date(
    Date.now() - DISCOVERY_WINDOW_DAYS * 24 * 60 * 60 * 1000
  )
    .toISOString()
    .replace(/\.\d{3}Z$/, ".000Z");

  const summary = await fetchAllPages<{ appId: string; signInCount: number }>(
    client,
    "/auditLogs/signInEventsAppSummary",
    "beta"
  );

  const candidates = summary
    .filter(
      (row) =>
        row.appId &&
        row.appId !== NULL_GUID &&
        !servicePrincipals.has(row.appId.toLowerCase())
    )
    .sort((a, b) => (b.signInCount ?? 0) - (a.signInCount ?? 0));

  const apps: UnregisteredSignInApp[] = candidates.map((row) => ({
    appId: row.appId,
    signInCount: row.signInCount ?? 0,
    isWorkloadIdentity: false,
    // No evidence row yet, so leave the event-type clause off rather than
    // asserting "interactive".
    logQueryUrl: buildSignInLogQueryUrl(row.appId, windowStart),
  }));

  const toEnrich = apps.slice(0, EVIDENCE_LOOKUP_CAP);
  for (let i = 0; i < toEnrich.length; i += EVIDENCE_BATCH_SIZE) {
    const batch = toEnrich.slice(i, i + EVIDENCE_BATCH_SIZE);
    const results = await Promise.allSettled(
      batch.map((app) => fetchAppEvidence(client, app.appId, windowStart))
    );
    results.forEach((result, index) => {
      if (result.status === "fulfilled") {
        Object.assign(batch[index], result.value);
      }
    });
  }

  return {
    apps,
    truncated: summary.length >= APP_SUMMARY_MAX_ROWS,
    evidenceCapped: Math.max(0, apps.length - toEnrich.length),
    windowStart,
  };
}

/** Cap on total sign-in rows scanned per run - bounds request volume for tenants
 * with heavy sign-in traffic. Surfaced as `scanTruncated`. */
const POLICY_SIGNIN_SCAN_ROW_CAP = 500;
/**
 * `appliedConditionalAccessPolicies` is documented-expensive to populate per
 * row - Graph evaluates every applicable policy against the sign-in to fill
 * it in. That cost scales with how many CA policies the tenant has, not just
 * the page size: a tenant with 50+ policies can blow past the per-request
 * timeout on the very first page even at 100 rows (observed in production -
 * "Request timed out after 15000ms" on row 1, 0 rows scanned). 100 was only
 * ever validated against tenants with far fewer policies. Dropped to 50 and
 * paired with a per-request retry (see fetchWithRetry below) that halves the
 * page size on a timeout instead of giving up outright, so heavier tenants
 * degrade to smaller/slower pages rather than reporting zero matches.
 */
const POLICY_SIGNIN_PAGE_SIZE = 50;
/** Floor for the retry-with-smaller-page-size fallback - below this it's not
 * worth halving again, just let the timeout end the scan. */
const POLICY_SIGNIN_MIN_PAGE_SIZE = 10;
/** Cap on matches kept per policy - the UI only needs a representative sample. */
const POLICY_SIGNIN_MATCHES_PER_POLICY_CAP = 25;
/**
 * Wall-clock budget for the whole scan and a per-request timeout, so a slow
 * tenant (this endpoint's `appliedConditionalAccessPolicies` select is
 * documented-expensive) can't leave the run stuck on this step indefinitely.
 * Either limit hitting ends the scan early with `scanTruncated: true`.
 * Both raised alongside the smaller page size above - a tenant with enough
 * policies to make 50 rows expensive needs more per-request headroom than
 * 15s, and the retry-on-timeout fallback needs room in the overall budget
 * to actually get a second attempt in before giving up.
 */
const POLICY_SIGNIN_SCAN_TIME_BUDGET_MS = 45_000;
const POLICY_SIGNIN_REQUEST_TIMEOUT_MS = 25_000;

/** Rejects if `promise` hasn't settled within `ms` - bounds a single Graph call. */
function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`Request timed out after ${ms}ms`)),
      ms
    );
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        clearTimeout(timer);
        reject(error);
      }
    );
  });
}

/** True for the specific timeout error `withTimeout` throws (not a real Graph
 * error/400) - only this case is worth retrying with a smaller page. */
function isTimeoutError(error: unknown): boolean {
  return error instanceof Error && /timed out after \d+ms/.test(error.message);
}

/** Rewrites (or adds) `$top=N` on a request URL - used to retry a page at a
 * smaller size. Works on both the initial hand-built URL and a Graph
 * `@odata.nextLink` (which already carries its own `$top` alongside an
 * opaque `$skiptoken` that must be left untouched). */
function withPageSize(url: string, pageSize: number): string {
  if (/([?&])\$top=\d+/.test(url)) {
    return url.replace(/([?&])\$top=\d+/, `$1$top=${pageSize}`);
  }
  return `${url}${url.includes("?") ? "&" : "?"}$top=${pageSize}`;
}

interface SignInPageResponse {
  value?: Array<Record<string, unknown>>;
  "@odata.nextLink"?: string;
}

/**
 * Fetches one page of sign-ins, halving `pageSize` and retrying on a timeout
 * instead of giving up immediately. `appliedConditionalAccessPolicies` cost
 * scales with how many CA policies a tenant has, so a page size tuned for
 * most tenants can still be too slow for a heavier one - this lets that case
 * degrade to smaller/slower pages rather than reporting zero matches.
 * `urlForPageSize` rebuilds the request URL for a given page size (needed
 * because a `nextLink` from Graph already has its own `$top` baked in).
 */
async function fetchSignInPageWithRetry(
  client: Client,
  urlForPageSize: (pageSize: number) => string,
  pageSize: number
): Promise<{ response: SignInPageResponse; pageSizeUsed: number }> {
  let currentPageSize = pageSize;
  // eslint-disable-next-line no-constant-condition
  while (true) {
    try {
      const request = client
        .api(urlForPageSize(currentPageSize))
        .version("beta")
        .header("Prefer", "include-unknown-enum-members")
        .get();
      const response = await withTimeout(request, POLICY_SIGNIN_REQUEST_TIMEOUT_MS);
      return { response, pageSizeUsed: currentPageSize };
    } catch (error) {
      if (isTimeoutError(error) && currentPageSize > POLICY_SIGNIN_MIN_PAGE_SIZE) {
        const halved = Math.max(
          POLICY_SIGNIN_MIN_PAGE_SIZE,
          Math.floor(currentPageSize / 2)
        );
        console.warn(
          `[fetchPolicySignInMatches] page of ${currentPageSize} timed out after ` +
            `${POLICY_SIGNIN_REQUEST_TIMEOUT_MS}ms - retrying at ${halved} rows`
        );
        currentPageSize = halved;
        continue;
      }
      throw error;
    }
  }
}

const POLICY_SIGNIN_SELECT = [
  "id",
  "createdDateTime",
  "userPrincipalName",
  "ipAddress",
  "location",
  "clientAppUsed",
  "resourceDisplayName",
  "appliedConditionalAccessPolicies",
].join(",");

/**
 * Entra's own display name for the Windows Azure AD Graph resource
 * (00000002-0000-0000-c000-000000000000) - the audience the Low-Privilege
 * Scope Enforcement ("baseline scopes") change re-routes low-privilege
 * requests to. Matched case-insensitively against `resourceDisplayName`.
 */
const WINDOWS_AZURE_AD_RESOURCE_DISPLAY_NAME = "windows azure active directory";

/** A policy actually evaluated the sign-in - not skipped as notApplied/notEnabled/unknown. */
function policyWasEvaluated(result: string): boolean {
  return (
    result === "success" ||
    result === "failure" ||
    result === "reportOnlySuccess" ||
    result === "reportOnlyFailure"
  );
}

function formatSignInLocation(location: unknown): string | undefined {
  const loc = location as
    | { city?: string; state?: string; countryOrRegion?: string }
    | undefined;
  if (!loc) return undefined;
  const parts = [loc.city, loc.state, loc.countryOrRegion].filter(Boolean);
  return parts.length > 0 ? parts.join(", ") : undefined;
}

/** Best-effort friendly reason from the enum fields Entra records. */
function describeFailureReason(
  applied: AppliedCaPolicy
): { reason?: string; detail?: string } {
  if (applied.conditionsNotSatisfied) {
    const first = applied.conditionsNotSatisfied.split(",")[0]?.trim();
    return {
      reason: first ? `${first} condition not satisfied` : undefined,
      detail: `conditionsNotSatisfied: ${applied.conditionsNotSatisfied}`,
    };
  }
  if (applied.enforcedGrantControls?.length) {
    return {
      reason: "Blocked by Conditional Access",
      detail: `Enforced grant controls: ${applied.enforcedGrantControls.join(", ")}`,
    };
  }
  return {};
}

/**
 * Scans recent sign-ins and attributes each to the Conditional Access
 * policies it matched, keeping only the ones a policy blocked (enabled) or
 * would have blocked (report-only). Requires `AuditLog.Read.All`.
 *
 * `appliedConditionalAccessPolicies` is a documented-expensive field to
 * include in `$select` - Microsoft Graph evaluates every applicable policy
 * per row to populate it, so this endpoint can be materially slower per page
 * than a typical sign-in log query, especially in tenants with heavy sign-in
 * volume. Two safeguards bound the wait so this step can never hang the run:
 * a wall-clock time budget across the whole scan, and a per-request timeout
 * so a single slow/stalled page can't block indefinitely. Either one hitting
 * ends the scan early with whatever was collected and sets `scanTruncated`.
 */
export async function fetchPolicySignInMatches(
  client: Client,
  policies: ConditionalAccessPolicy[]
): Promise<PolicySignInLogResult> {
  const windowStart = new Date(
    Date.now() - DISCOVERY_WINDOW_DAYS * 24 * 60 * 60 * 1000
  )
    .toISOString()
    .replace(/\.\d{3}Z$/, ".000Z");

  const knownPolicyIds = new Set(policies.map((p) => p.id));
  const byPolicy = new Map<string, PolicySignInMatches>();
  const baselineAudienceEvidence = new Map<string, string>();
  let scanTruncated = false;
  let scanError: string | undefined;
  let rowsScanned = 0;
  // Rows where appliedConditionalAccessPolicies came back missing/empty -
  // per Microsoft's docs this happens when the caller has AuditLog.Read.All
  // (can read sign-ins) but not Policy.Read.All/Policy.Read.ConditionalAccess
  // (can't read CA data), in which case Graph *silently omits* the field
  // instead of erroring. If this equals rowsScanned, that's the real story
  // behind an all-zero result, not a logic bug in this scan.
  let rowsMissingCaData = 0;
  const scanStart = Date.now();
  let nextLink: string | undefined =
    `/auditLogs/signIns?$filter=${encodeURIComponent(
      `createdDateTime ge ${windowStart}`
    )}&$select=${POLICY_SIGNIN_SELECT}&$top=${POLICY_SIGNIN_PAGE_SIZE}`;

  while (
    nextLink &&
    rowsScanned < POLICY_SIGNIN_SCAN_ROW_CAP &&
    Date.now() - scanStart < POLICY_SIGNIN_SCAN_TIME_BUDGET_MS
  ) {
    let response: SignInPageResponse | undefined;
    try {
      const currentLink = nextLink;
      const result = await fetchSignInPageWithRetry(
        client,
        (pageSize) => withPageSize(currentLink, pageSize),
        POLICY_SIGNIN_PAGE_SIZE
      );
      response = result.response;
    } catch (error) {
      // Either a real error (e.g. an unsupported $filter clause returning
      // 400) or a timeout that persisted even after retrying at the minimum
      // page size - stop rather than hang or retry indefinitely; whatever
      // was collected so far is still valid. Logged (not swallowed) so this
      // is visible in the console instead of silently producing a scan that
      // looks like "zero matches everywhere".
      console.warn("[fetchPolicySignInMatches] request failed:", error);
      scanError = error instanceof Error ? error.message : String(error);
      scanTruncated = true;
      break;
    }


    const rows: Array<Record<string, unknown>> = response?.value ?? [];
    for (const row of rows) {
      rowsScanned++;
      const applied = normalizeAppliedPolicies(
        row.appliedConditionalAccessPolicies
      );
      if (!applied) {
        rowsMissingCaData++;
        continue;
      }

      const isBaselineAudience =
        typeof row.resourceDisplayName === "string" &&
        row.resourceDisplayName.trim().toLowerCase() ===
          WINDOWS_AZURE_AD_RESOURCE_DISPLAY_NAME;

      for (const ap of applied) {
        if (!ap.id || !knownPolicyIds.has(ap.id)) continue;

        // Evidence collection: regardless of match status, if this policy was
        // actually evaluated (not notApplied/notEnabled) against a sign-in
        // whose resource was Windows Azure AD Graph, that's proof the tenant
        // is already routing baseline-scope requests through this policy -
        // even if advancedSettings.baselineScopes still reads null/unset.
        if (isBaselineAudience && policyWasEvaluated(ap.result)) {
          const existing = baselineAudienceEvidence.get(ap.id);
          const createdDateTime = row.createdDateTime as string;
          if (!existing || createdDateTime > existing) {
            baselineAudienceEvidence.set(ap.id, createdDateTime);
          }
        }

        const status: "blocked" | "wouldBlock" | null =
          ap.result === "failure"
            ? "blocked"
            : ap.result === "reportOnlyFailure"
            ? "wouldBlock"
            : null;
        if (!status) continue;

        let entry = byPolicy.get(ap.id);
        if (!entry) {
          entry = { matches: [], truncated: false };
          byPolicy.set(ap.id, entry);
        }
        if (entry.matches.length >= POLICY_SIGNIN_MATCHES_PER_POLICY_CAP) {
          entry.truncated = true;
          continue;
        }

        const { reason, detail } = describeFailureReason(ap);
        entry.matches.push({
          id: `${row.id}-${ap.id}`,
          createdDateTime: row.createdDateTime as string,
          userPrincipalName: (row.userPrincipalName as string) || undefined,
          ipAddress: (row.ipAddress as string) || undefined,
          location: formatSignInLocation(row.location),
          clientAppUsed: (row.clientAppUsed as string) || undefined,
          status,
          failureReason: reason,
          failureDetail: detail,
        });
      }
    }

    nextLink = response?.["@odata.nextLink"];
    if (rowsScanned >= POLICY_SIGNIN_SCAN_ROW_CAP && nextLink) {
      scanTruncated = true;
    }
    if (
      nextLink &&
      Date.now() - scanStart >= POLICY_SIGNIN_SCAN_TIME_BUDGET_MS
    ) {
      scanTruncated = true;
    }
  }

  // Always logged (not just on error) so a "why is everything 0" report can
  // be diagnosed from the browser console without adding instrumentation
  // after the fact - this step has broken silently more than once.
  console.info(
    `[fetchPolicySignInMatches] scanned ${rowsScanned} row(s), ` +
      `${rowsMissingCaData} missing CA data, ${byPolicy.size} policy(ies) with matches, ` +
      `truncated=${scanTruncated}` +
      (scanError ? `, error="${scanError}"` : "")
  );
  if (rowsScanned > 0 && rowsMissingCaData === rowsScanned) {
    console.warn(
      "[fetchPolicySignInMatches] every scanned sign-in was missing appliedConditionalAccessPolicies. " +
        "Per Microsoft's docs, Graph omits this field (rather than erroring) when the caller can read " +
        "sign-in logs (AuditLog.Read.All) but not Conditional Access data (Policy.Read.All / " +
        "Policy.Read.ConditionalAccess). If sign-ins are showing 0 matches for every policy, check that " +
        "the signed-in account still holds a supported Entra role (Global Reader, Security Reader, " +
        "Security Administrator, or Conditional Access Administrator) - this can silently regress if a " +
        "role assignment is removed or expires, even though the sign-in itself keeps working."
    );
  }

  return {
    byPolicy,
    windowStart,
    scanTruncated,
    rowsScanned,
    rowsMissingCaData,
    scanError,
    baselineAudienceEvidence,
  };
}

/**
 * GET /identity/conditionalAccess/settings (beta) - returns a single $entity
 * describing tenant-wide baseline enforcement (Low-Privilege Scope
 * Enforcement) status. Requires Policy.Read.All. No query params/paging.
 */
export async function fetchConditionalAccessSettings(
  client: Client
): Promise<ConditionalAccessSettings> {
  return client.api("/identity/conditionalAccess/settings").version("beta").get();
}

async function resolveDirectoryObject(
  client: Client,
  id: string
): Promise<DirectoryObject | null> {
  try {
    const obj = await client.api(`/directoryObjects/${id}`).get();
    return {
      id: obj.id,
      displayName: obj.displayName ?? id,
      "@odata.type": obj["@odata.type"] ?? "unknown",
    };
  } catch {
    return null;
  }
}

// ─── Batch Resolution ────────────────────────────────────────────────────────

function collectObjectIds(policies: ConditionalAccessPolicy[]): Set<string> {
  const ids = new Set<string>();
  const guidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

  for (const policy of policies) {
    const { users } = policy.conditions;
    [
      ...users.includeUsers,
      ...users.excludeUsers,
      ...users.includeGroups,
      ...users.excludeGroups,
      ...users.includeRoles,
      ...users.excludeRoles,
    ].forEach((id) => {
      if (guidPattern.test(id)) ids.add(id);
    });
  }

  return ids;
}

export async function resolveDirectoryObjects(
  client: Client,
  policies: ConditionalAccessPolicy[]
): Promise<Map<string, DirectoryObject>> {
  const objectIds = collectObjectIds(policies);
  const map = new Map<string, DirectoryObject>();

  // Resolve in batches of 20
  const idArray = [...objectIds];
  for (let i = 0; i < idArray.length; i += 20) {
    const batch = idArray.slice(i, i + 20);
    const results = await Promise.allSettled(
      batch.map((id) => resolveDirectoryObject(client, id))
    );
    results.forEach((result, index) => {
      if (result.status === "fulfilled" && result.value) {
        map.set(batch[index], result.value);
      }
    });
  }

  return map;
}

// ─── License Detection ───────────────────────────────────────────────────────

async function fetchSubscribedSkus(
  client: Client
): Promise<TenantLicenses> {
  try {
    const skus = await fetchAllPages<{
      skuPartNumber: string;
      servicePlans: { servicePlanId: string; servicePlanName: string; appliesTo: string }[];
    }>(client, "/subscribedSkus");

    const allPlanIds = new Set(
      skus.flatMap((sku) =>
        sku.servicePlans.map((sp) => sp.servicePlanId.toLowerCase())
      )
    );

    return {
      hasEntraIdP1:
        allPlanIds.has(SERVICE_PLAN_IDS.entraIdP1) ||
        allPlanIds.has(SERVICE_PLAN_IDS.entraIdP2), // P2 implies P1
      hasEntraIdP2: allPlanIds.has(SERVICE_PLAN_IDS.entraIdP2),
      hasIntunePlan1: allPlanIds.has(SERVICE_PLAN_IDS.intunePlan1),
      hasWorkloadIdPremium: allPlanIds.has(SERVICE_PLAN_IDS.workloadIdPremiumP1) || allPlanIds.has(SERVICE_PLAN_IDS.workloadIdPremiumP2),
    };
  } catch (e) {
    console.warn(
      "Could not fetch subscribedSkus - falling back to policy-based inference.",
      e
    );
    return inferLicensesFromPolicies([]);
  }
}

/**
 * Fallback: infer licenses from the policies already present in the tenant.
 * If a tenant has risk-based policies, they very likely have P2.
 * If a tenant has compliantDevice policies, they likely have Intune.
 */
export function inferLicensesFromPolicies(
  policies: ConditionalAccessPolicy[]
): TenantLicenses {
  const enabled = policies.filter(
    (p) => p.state === "enabled" || p.state === "enabledForReportingButNotEnforced"
  );

  const hasP2 = enabled.some(
    (p) =>
      (p.conditions.signInRiskLevels?.length ?? 0) > 0 ||
      (p.conditions.userRiskLevels?.length ?? 0) > 0
  );

  const hasIntune = enabled.some((p) =>
    p.grantControls?.builtInControls.includes("compliantDevice")
  );

  const hasWorkloadIdPremium = enabled.some(
    (p) =>
      p.conditions.clientApplications?.includeServicePrincipals?.length !== undefined &&
      (p.conditions.clientApplications?.includeServicePrincipals?.length ?? 0) > 0
  );

  return {
    hasEntraIdP1: true, // CA itself requires P1
    hasEntraIdP2: hasP2,
    hasIntunePlan1: hasIntune,
    hasWorkloadIdPremium,
  };
}

/** Check whether a specific license requirement is met */
export function isLicensed(
  licenses: TenantLicenses,
  req?: LicenseRequirement
): boolean {
  if (!req) return true;
  switch (req) {
    case "entraIdP1":
      return licenses.hasEntraIdP1;
    case "entraIdP2":
      return licenses.hasEntraIdP2;
    case "intunePlan1":
      return licenses.hasIntunePlan1;
    case "workloadIdPremium":
      return licenses.hasWorkloadIdPremium;
    default:
      return true;
  }
}

// ─── Normalization ───────────────────────────────────────────────────────────

/** Ensure all expected array fields exist - beta API may return null/undefined */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function normalizePolicy(p: any): ConditionalAccessPolicy {
  const raw = p as Partial<ConditionalAccessPolicy> & { id: string; displayName: string; state: string };
  const users = (raw.conditions as Record<string, unknown>)?.users as Record<string, unknown> | undefined;
  const apps = (raw.conditions as Record<string, unknown>)?.applications as Record<string, unknown> | undefined;
  const cond = raw.conditions ?? {} as Record<string, unknown>;

  return {
    id: raw.id,
    templateId: raw.templateId ?? null,
    displayName: raw.displayName,
    state: (raw.state as ConditionalAccessPolicy["state"]) ?? "disabled",
    createdDateTime: raw.createdDateTime ?? "",
    modifiedDateTime: raw.modifiedDateTime ?? "",
    conditions: {
      users: {
        includeUsers: (users?.includeUsers as string[]) ?? [],
        excludeUsers: (users?.excludeUsers as string[]) ?? [],
        includeGroups: (users?.includeGroups as string[]) ?? [],
        excludeGroups: (users?.excludeGroups as string[]) ?? [],
        includeRoles: (users?.includeRoles as string[]) ?? [],
        excludeRoles: (users?.excludeRoles as string[]) ?? [],
        includeGuestsOrExternalUsers: users?.includeGuestsOrExternalUsers,
        excludeGuestsOrExternalUsers: users?.excludeGuestsOrExternalUsers,
      },
      applications: {
        includeApplications: (apps?.includeApplications as string[]) ?? [],
        excludeApplications: (apps?.excludeApplications as string[]) ?? [],
        includeUserActions: (apps?.includeUserActions as string[]) ?? [],
        includeAuthenticationContextClassReferences:
          (apps?.includeAuthenticationContextClassReferences as string[]) ?? [],
        applicationFilter: apps?.applicationFilter as ConditionalAccessPolicy["conditions"]["applications"]["applicationFilter"],
      },
      clientAppTypes: ((cond as Record<string, unknown>).clientAppTypes as string[]) ?? [],
      platforms: (cond as Record<string, unknown>).platforms as ConditionalAccessPolicy["conditions"]["platforms"],
      locations: (cond as Record<string, unknown>).locations as ConditionalAccessPolicy["conditions"]["locations"],
      userRiskLevels: ((cond as Record<string, unknown>).userRiskLevels as string[]) ?? [],
      signInRiskLevels: ((cond as Record<string, unknown>).signInRiskLevels as string[]) ?? [],
      servicePrincipalRiskLevels: (cond as Record<string, unknown>).servicePrincipalRiskLevels as string[] | undefined,
      devices: (cond as Record<string, unknown>).devices as ConditionalAccessPolicy["conditions"]["devices"],
      clientApplications: (cond as Record<string, unknown>).clientApplications as ConditionalAccessPolicy["conditions"]["clientApplications"],
      agentIdRiskLevels: (cond as Record<string, unknown>).agentIdRiskLevels as string | undefined,
      insiderRiskLevels: (cond as Record<string, unknown>).insiderRiskLevels as string | undefined,
      authenticationFlows: (cond as Record<string, unknown>).authenticationFlows as ConditionalAccessPolicy["conditions"]["authenticationFlows"],
    },
    grantControls: raw.grantControls
      ? {
          operator: raw.grantControls.operator ?? "OR",
          builtInControls: raw.grantControls.builtInControls ?? [],
          customAuthenticationFactors: raw.grantControls.customAuthenticationFactors ?? [],
          termsOfUse: raw.grantControls.termsOfUse ?? [],
          authenticationStrength: raw.grantControls.authenticationStrength,
        }
      : undefined,
    sessionControls: raw.sessionControls,
  };
}

// ─── Main Loader ─────────────────────────────────────────────────────────────

export async function loadTenantContext(
  msalInstance: IPublicClientApplication,
  account: AccountInfo,
  onProgress?: (step: string) => void,
  options?: { includeSignInLogs?: boolean }
): Promise<TenantContext> {
  const includeSignInLogs = options?.includeSignInLogs ?? false;
  const client = createGraphClient(
    msalInstance,
    account,
    scopesFor(includeSignInLogs)
  );

  onProgress?.(RUN_STEPS.policies);
  const rawPolicies = await fetchConditionalAccessPolicies(client);
  // Normalize: beta API may return null for fields we expect as arrays
  const policies = rawPolicies.map(normalizePolicy);

  onProgress?.(RUN_STEPS.namedLocations);
  const namedLocations = await fetchNamedLocations(client);

  onProgress?.(RUN_STEPS.servicePrincipals);
  const spList = await fetchServicePrincipals(client);
  const servicePrincipals = new Map<string, ServicePrincipal>(
    spList.map((sp) => [sp.appId.toLowerCase(), sp])
  );

  onProgress?.(RUN_STEPS.authStrength);
  let authStrengthPolicies = new Map<string, AuthenticationStrengthPolicy>();
  try {
    const aspList = await fetchAuthenticationStrengthPolicies(client);
    authStrengthPolicies = new Map(aspList.map((asp) => [asp.id, asp]));
  } catch {
    // Permission may not be granted - degrade gracefully
  }

  onProgress?.(RUN_STEPS.caSettings);
  let conditionalAccessSettings: ConditionalAccessSettings | null = null;
  try {
    conditionalAccessSettings = await fetchConditionalAccessSettings(client);
  } catch {
    // Permission may not be granted (Policy.Read.All) or tenant doesn't
    // expose this preview endpoint - degrade gracefully to null.
  }

  // The heaviest step, and the only one needing AuditLog.Read.All. Downstream
  // already treats an absent result as "not scanned".
  //
  // Sequential, not concurrent - this WAS made concurrent via Promise.allSettled
  // as a perf attempt, but every single Graph request from this client calls
  // acquireTokenSilent through its authProvider (see createGraphClient) - there
  // is no separate up-front token fetch. Firing both scans' paged requests at
  // once meant dozens of concurrent silent token acquisitions racing each
  // other; MSAL can reject overlapping silent calls in that pattern, and a
  // rejection here is caught by fetchPolicySignInMatches's own try/catch and
  // treated as "request failed, stop scanning" - which looks identical to
  // "zero matches found" in the UI. Reverted to sequential to stop that
  // regression; parallelizing safely would require pre-warming the token
  // once before either scan starts, which isn't done today.
  let unregisteredSignInApps: UnregisteredSignInAppsResult | undefined;
  let policySignInMatches: PolicySignInLogResult | undefined;
  if (includeSignInLogs) {
    onProgress?.(RUN_STEPS.signInLogs);
    try {
      unregisteredSignInApps = await fetchUnregisteredSignInApps(
        client,
        servicePrincipals
      );
    } catch (e) {
      // Needs AuditLog.Read.All and Entra ID P1 - degrade, don't fail the run
      console.warn(
        "Could not scan sign-in logs for unregistered service principals - skipping that check.",
        e
      );
    }
    onProgress?.(RUN_STEPS.signInPolicyMatches);
    try {
      policySignInMatches = await fetchPolicySignInMatches(client, policies);
    } catch (e) {
      // Needs AuditLog.Read.All - degrade, don't fail the run
      console.warn(
        "Could not scan sign-in logs for per-policy matches - skipping that check.",
        e
      );
    }
  }

  onProgress?.(RUN_STEPS.directoryObjects);
  const directoryObjects = await resolveDirectoryObjects(client, policies);

  onProgress?.(RUN_STEPS.licenses);
  let licenses: TenantLicenses;
  try {
    licenses = await fetchSubscribedSkus(client);
  } catch {
    // Fall back to policy-based inference if the API call fails
    licenses = inferLicensesFromPolicies(policies);
  }

  // Fetch tenant identity (display name + tenant ID)
  onProgress?.(RUN_STEPS.tenantIdentity);
  let tenantDisplayName = account.tenantId ?? "Unknown Tenant";
  const tenantId = account.tenantId ?? "";
  try {
    const orgResponse = await client.api("/organization").select("displayName").top(1).get();
    const orgs = orgResponse?.value;
    if (Array.isArray(orgs) && orgs.length > 0 && orgs[0].displayName) {
      tenantDisplayName = orgs[0].displayName;
    }
  } catch {
    // Fall back to account username domain or tenant ID
    const domain = account.username?.split("@")[1];
    if (domain) tenantDisplayName = domain;
  }

  return { tenantDisplayName, tenantId, policies, namedLocations, servicePrincipals, directoryObjects, licenses, authStrengthPolicies, unregisteredSignInApps, policySignInMatches, conditionalAccessSettings };
}
