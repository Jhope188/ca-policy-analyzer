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
 * One CA policy as the sign-in log recorded it - Entra's own verdict, not our
 * prediction. `conditionsNotSatisfied` containing "application" is the bypass,
 * evidenced.
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

/** An app in the sign-in logs with no service principal in the tenant. */
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
  /** Apps beyond the enrichment cap: listed, but without an evidence row. */
  evidenceCapped: number;
  windowStart: string;
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

/** The all-zero GUID stands for "unknown app" in the sign-in logs. */
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

/** Interactive first: cheapest and most common, and needs no filter clause. */
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
 * Captured from a live page - Microsoft documents no deep link, and a fragment
 * can't be verified automatically because the part after `#` never reaches the
 * server, so a wrong blade looks fine from the outside. `SignInEventsV3.ReactView`
 * and `ActiveDirectoryMenuBlade/~/SignIns` both fail to resolve on this host.
 * scripts/check-links.ts pins this.
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
      // Not fatal - the app still gets listed, without evidence
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

  // Skipped when the caller turned the scan off: it is the heaviest step of the
  // run and the only one needing AuditLog.Read.All. Everything downstream
  // already treats an absent result as "not scanned".
  let unregisteredSignInApps: UnregisteredSignInAppsResult | undefined;
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

  return { tenantDisplayName, tenantId, policies, namedLocations, servicePrincipals, directoryObjects, licenses, authStrengthPolicies, unregisteredSignInApps, conditionalAccessSettings };
}
