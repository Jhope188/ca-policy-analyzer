/**
 * GUID → Friendly Name Resolver
 *
 * Resolves Azure AD / Entra ID GUIDs (roles, groups, users, apps)
 * to human-readable display names.
 *
 * Resolution order:
 *  1. Static ADMIN_ROLE_IDS map (built-in Entra roles)
 *  2. Dynamic directoryObjects map (from Graph API - roles, groups, users)
 *  3. Dynamic servicePrincipals map (from Graph API - apps)
 *  4. Fall back to raw GUID
 */

import { ADMIN_ROLE_IDS } from "@/data/policy-templates";

// ─── Types ───────────────────────────────────────────────────────────────────

/** Minimal shape for a resolved directory object (matches graph-client.ts) */
export interface DirectoryObjectLike {
  id: string;
  displayName: string;
}

/** Optional lookup maps that can be injected for dynamic GUID resolution */
export interface GuidResolverMaps {
  /** Resolved directory objects (users, groups, roles) keyed by id (lowercase) */
  directoryObjects?: Map<string, DirectoryObjectLike>;
  /** Resolved service principals keyed by appId (lowercase) */
  servicePrincipals?: Map<string, DirectoryObjectLike>;
}

// ─── Role Name Lookup ────────────────────────────────────────────────────────

/** Reverse map: role GUID (lowercase) → human-friendly name */
export const ROLE_NAME_MAP: Record<string, string> = Object.fromEntries(
  Object.entries(ADMIN_ROLE_IDS).map(([key, id]) => [
    id.toLowerCase(),
    key
      .replace(/([A-Z])/g, " $1")
      .replace(/^./, (c) => c.toUpperCase())
      .trim(),
  ]),
);

/**
 * Resolve a role template GUID to its friendly name.
 * Falls back to directoryObjects → raw GUID.
 */
export function resolveRoleName(
  guid: string,
  maps?: GuidResolverMaps,
): string {
  const lower = guid.toLowerCase();
  return (
    ROLE_NAME_MAP[lower] ??
    maps?.directoryObjects?.get(lower)?.displayName ??
    guid
  );
}

/**
 * Resolve an array of role GUIDs to a comma-separated string of names.
 * Returns "-" if the array is empty or undefined.
 */
export function resolveRoleList(
  guids: string[] | undefined,
  maps?: GuidResolverMaps,
): string {
  if (!guids || guids.length === 0) return "-";
  return guids.map((g) => resolveRoleName(g, maps)).join(", ");
}

// ─── Universal GUID Resolver ─────────────────────────────────────────────────

/**
 * Resolve any GUID (user, group, role, app) to a friendly display name.
 * Checks static role map → directoryObjects → servicePrincipals → raw GUID.
 */
export function resolveGuid(
  guid: string,
  maps?: GuidResolverMaps,
): string {
  const lower = guid.toLowerCase();
  return (
    ROLE_NAME_MAP[lower] ??
    maps?.directoryObjects?.get(lower)?.displayName ??
    maps?.servicePrincipals?.get(lower)?.displayName ??
    guid
  );
}

/**
 * Resolve an array of GUIDs (any type) to a comma-separated string.
 * Returns "-" if the array is empty or undefined.
 */
export function resolveGuidList(
  guids: string[] | undefined,
  maps?: GuidResolverMaps,
): string {
  if (!guids || guids.length === 0) return "-";
  return guids.map((g) => resolveGuid(g, maps)).join(", ");
}

/**
 * Resolve app IDs to display names.
 * Checks servicePrincipals → directoryObjects → raw GUID.
 */
export function resolveAppList(
  appIds: string[] | undefined,
  maps?: GuidResolverMaps,
): string {
  if (!appIds || appIds.length === 0) return "-";
  return appIds
    .map((id) => {
      const lower = id.toLowerCase();
      return (
        maps?.servicePrincipals?.get(lower)?.displayName ??
        maps?.directoryObjects?.get(lower)?.displayName ??
        id
      );
    })
    .join(", ");
}
