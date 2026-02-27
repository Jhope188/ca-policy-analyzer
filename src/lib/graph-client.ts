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

// ─── Tenant Context ──────────────────────────────────────────────────────────

export interface TenantContext {
  policies: ConditionalAccessPolicy[];
  namedLocations: NamedLocation[];
  servicePrincipals: Map<string, ServicePrincipal>;
  directoryObjects: Map<string, DirectoryObject>;
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
  url: string
): Promise<T[]> {
  const results: T[] = [];
  let nextLink: string | undefined = url;

  while (nextLink) {
    const response = await client.api(nextLink).get();
    results.push(...(response.value ?? []));
    nextLink = response["@odata.nextLink"];
  }

  return results;
}

export async function fetchConditionalAccessPolicies(
  client: Client
): Promise<ConditionalAccessPolicy[]> {
  return fetchAllPages<ConditionalAccessPolicy>(
    client,
    "/identity/conditionalAccess/policies"
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

// ─── Main Loader ─────────────────────────────────────────────────────────────

export async function loadTenantContext(
  msalInstance: IPublicClientApplication,
  account: AccountInfo,
  onProgress?: (step: string) => void
): Promise<TenantContext> {
  const client = createGraphClient(msalInstance, account);

  onProgress?.("Loading Conditional Access policies…");
  const policies = await fetchConditionalAccessPolicies(client);

  onProgress?.("Loading named locations…");
  const namedLocations = await fetchNamedLocations(client);

  onProgress?.("Loading service principals…");
  const spList = await fetchServicePrincipals(client);
  const servicePrincipals = new Map<string, ServicePrincipal>(
    spList.map((sp) => [sp.appId.toLowerCase(), sp])
  );

  onProgress?.("Resolving directory objects…");
  const directoryObjects = await resolveDirectoryObjects(client, policies);

  return { policies, namedLocations, servicePrincipals, directoryObjects };
}
