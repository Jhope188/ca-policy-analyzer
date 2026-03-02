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
import { loginRequest } from "./msal-config";

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
    };
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

export type LicenseRequirement = "entraIdP1" | "entraIdP2" | "intunePlan1";

export interface TenantLicenses {
  hasEntraIdP1: boolean;
  hasEntraIdP2: boolean;
  hasIntunePlan1: boolean;
}

/** Well-known service plan IDs */
const SERVICE_PLAN_IDS: Record<string, string> = {
  entraIdP1: "41781fb2-bc02-4b7c-bd55-b576c07bb09d",
  entraIdP2: "eec0eb4f-6444-4f95-aba0-50c24d67f998",
  intunePlan1: "c1ec4a95-1f05-45b3-a911-aa3fa01094f5",
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
  /** Authentication strength policies (built-in + custom) — used to detect EAM usage */
  authStrengthPolicies: Map<string, AuthenticationStrengthPolicy>;
}

// ─── Graph Client Factory ────────────────────────────────────────────────────

function createGraphClient(
  msalInstance: IPublicClientApplication,
  account: AccountInfo
): Client {
  return Client.init({
    authProvider: async (done) => {
      try {
        const response = await msalInstance.acquireTokenSilent({
          ...loginRequest,
          account,
        });
        done(null, response.accessToken);
      } catch (error) {
        if (error instanceof InteractionRequiredAuthError) {
          try {
            const response = await msalInstance.acquireTokenPopup({
              ...loginRequest,
              account,
            });
            done(null, response.accessToken);
          } catch (popupError) {
            done(popupError as Error, null);
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
    };
  } catch (e) {
    console.warn(
      "Could not fetch subscribedSkus — falling back to policy-based inference.",
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

  return {
    hasEntraIdP1: true, // CA itself requires P1
    hasEntraIdP2: hasP2,
    hasIntunePlan1: hasIntune,
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
    default:
      return true;
  }
}

// ─── Normalization ───────────────────────────────────────────────────────────

/** Ensure all expected array fields exist — beta API may return null/undefined */
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
  onProgress?: (step: string) => void
): Promise<TenantContext> {
  const client = createGraphClient(msalInstance, account);

  onProgress?.("Loading Conditional Access policies…");
  const rawPolicies = await fetchConditionalAccessPolicies(client);
  // Normalize: beta API may return null for fields we expect as arrays
  const policies = rawPolicies.map(normalizePolicy);

  onProgress?.("Loading named locations…");
  const namedLocations = await fetchNamedLocations(client);

  onProgress?.("Loading service principals…");
  const spList = await fetchServicePrincipals(client);
  const servicePrincipals = new Map<string, ServicePrincipal>(
    spList.map((sp) => [sp.appId.toLowerCase(), sp])
  );

  onProgress?.("Loading authentication strength policies…");
  let authStrengthPolicies = new Map<string, AuthenticationStrengthPolicy>();
  try {
    const aspList = await fetchAuthenticationStrengthPolicies(client);
    authStrengthPolicies = new Map(aspList.map((asp) => [asp.id, asp]));
  } catch {
    // Permission may not be granted — degrade gracefully
  }

  onProgress?.("Resolving directory objects…");
  const directoryObjects = await resolveDirectoryObjects(client, policies);

  onProgress?.("Detecting tenant licenses…");
  let licenses: TenantLicenses;
  try {
    licenses = await fetchSubscribedSkus(client);
  } catch {
    // Fall back to policy-based inference if the API call fails
    licenses = inferLicensesFromPolicies(policies);
  }

  // Fetch tenant identity (display name + tenant ID)
  onProgress?.("Loading tenant identity…");
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

  return { tenantDisplayName, tenantId, policies, namedLocations, servicePrincipals, directoryObjects, licenses, authStrengthPolicies };
}
