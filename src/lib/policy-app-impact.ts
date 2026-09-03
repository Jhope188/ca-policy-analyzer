// Which policies would hit an app once its service principal exists. Verdict is
// three-valued because firing also depends on user, device, platform, location
// and risk, none of which follow from an appId.
// learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-cloud-apps

import { ConditionalAccessPolicy, TenantContext } from "./graph-client";

// ─── Types ───────────────────────────────────────────────────────────────────

export type ImpactVerdict = "willApply" | "mayApply" | "willNotApply";

export interface ObservedAppSignIn {
  appId: string;
  clientAppUsed?: string;
  userPrincipalName?: string;
  isWorkloadIdentity: boolean;
}

export interface PolicyAppImpact {
  policyId: string;
  policyName: string;
  state: ConditionalAccessPolicy["state"];
  verdict: ImpactVerdict;
  /** Most decisive reason first. */
  reasons: string[];
  /** Must also match at sign-in time; not verdict-changing. */
  gatedBy: string[];
  blocks: boolean;
  phantomExclusion: boolean;
}

// ─── Client app types ────────────────────────────────────────────────────────

const CLIENT_APP_USED_TO_TYPE: Record<string, string> = {
  "browser": "browser",
  "mobile apps and desktop clients": "mobileAppsAndDesktopClients",
  "exchange activesync": "exchangeActiveSync",
  "exchange activesync (supported)": "easSupported",
  "exchange activesync (not supported)": "other",
  "exchange web services": "other",
  "exchange online powershell": "other",
  "imap4": "other",
  "pop3": "other",
  "smtp": "other",
  "authenticated smtp": "other",
  "mapi over http": "other",
  "offline address book": "other",
  "other clients": "other",
  "reporting web services": "other",
  "autodiscover": "other",
};

export function mapClientAppUsedToType(
  clientAppUsed?: string
): string | undefined {
  if (!clientAppUsed) return undefined;
  return CLIENT_APP_USED_TO_TYPE[clientAppUsed.trim().toLowerCase()];
}

/** Graph splits EAS into two members; the portal shows them as one checkbox. */
function typesCovering(observedType: string): string[] {
  if (observedType === "exchangeActiveSync" || observedType === "easSupported") {
    return ["exchangeactivesync", "eassupported"];
  }
  return [observedType.toLowerCase()];
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function lower(values: string[] | undefined): Set<string> {
  return new Set((values ?? []).map((v) => v.toLowerCase()));
}

function resolveName(context: TenantContext, id: string): string {
  return context.directoryObjects.get(id)?.displayName ?? id;
}

function describeUserTargets(
  ids: string[],
  context: TenantContext,
  label: string
): string | null {
  if (ids.length === 0) return null;
  const names = ids.slice(0, 4).map((id) => resolveName(context, id));
  const rest = ids.length > names.length ? ` +${ids.length - names.length} more` : "";
  return `${label}: ${names.join(", ")}${rest}`;
}

function collectGates(
  policy: ConditionalAccessPolicy,
  context: TenantContext
): string[] {
  const gates: string[] = [];
  const c = policy.conditions;

  const includePlatforms = c.platforms?.includePlatforms ?? [];
  if (includePlatforms.length > 0 && !includePlatforms.includes("all")) {
    gates.push(`Device platform must be one of: ${includePlatforms.join(", ")}`);
  }
  const includeLocations = c.locations?.includeLocations ?? [];
  if (includeLocations.length > 0 && !includeLocations.includes("All")) {
    const names = includeLocations.map(
      (id) =>
        context.namedLocations.find((l) => l.id === id)?.displayName ?? id
    );
    gates.push(`Sign-in must come from: ${names.join(", ")}`);
  }
  if ((c.signInRiskLevels?.length ?? 0) > 0) {
    gates.push(
      `Sign-in risk must be: ${c.signInRiskLevels.join(", ")}` +
        (context.licenses.hasEntraIdP2 ? "" : " (requires Entra ID P2)")
    );
  }
  if ((c.userRiskLevels?.length ?? 0) > 0) {
    gates.push(
      `User risk must be: ${c.userRiskLevels.join(", ")}` +
        (context.licenses.hasEntraIdP2 ? "" : " (requires Entra ID P2)")
    );
  }
  if ((c.servicePrincipalRiskLevels?.length ?? 0) > 0) {
    gates.push(
      `Service principal risk must be: ${c.servicePrincipalRiskLevels?.join(", ")}`
    );
  }
  if (c.devices?.deviceFilter?.rule) {
    gates.push(
      `Device filter (${c.devices.deviceFilter.mode}): ${c.devices.deviceFilter.rule}`
    );
  }
  if (c.authenticationFlows?.transferMethods) {
    gates.push(
      `Authentication flow must be: ${c.authenticationFlows.transferMethods}`
    );
  }
  if (c.insiderRiskLevels) {
    gates.push(`Insider risk must be: ${c.insiderRiskLevels}`);
  }
  if (c.agentIdRiskLevels) {
    gates.push(`Agent identity risk must be: ${c.agentIdRiskLevels}`);
  }

  return gates;
}

// ─── Main evaluator ──────────────────────────────────────────────────────────

/** First decisive rule wins. */
export function evaluatePolicyImpact(
  policy: ConditionalAccessPolicy,
  app: ObservedAppSignIn,
  context: TenantContext
): PolicyAppImpact {
  const appId = app.appId.toLowerCase();
  const apps = policy.conditions.applications;
  const users = policy.conditions.users;

  const base = {
    policyId: policy.id,
    policyName: policy.displayName,
    state: policy.state,
    blocks: policy.grantControls?.builtInControls?.includes("block") ?? false,
    gatedBy: [] as string[],
    phantomExclusion: false,
  };

  const notApplied = (
    reason: string,
    extra: Partial<PolicyAppImpact> = {}
  ): PolicyAppImpact => ({
    ...base,
    verdict: "willNotApply",
    reasons: [reason],
    ...extra,
  });

  if ((apps.includeUserActions?.length ?? 0) > 0) {
    return notApplied(
      `Policy targets the user action "${apps.includeUserActions.join(", ")}", not a cloud app.`
    );
  }
  if ((apps.includeAuthenticationContextClassReferences?.length ?? 0) > 0) {
    return notApplied(
      "Policy targets an authentication context, not a cloud app."
    );
  }

  const excluded = lower(apps.excludeApplications);
  if (excluded.has(appId)) {
    return notApplied(
      "Policy excludes this app by ID - but the app has no service principal, " +
        "so the exclusion protects nothing today and the app is outside the policy either way.",
      { phantomExclusion: true }
    );
  }

  // Filters match custom security attributes and are evaluated at token
  // issuance, so a brand-new service principal never matches an include filter.
  const filter = apps.applicationFilter;
  if (filter?.mode === "include" && filter.rule) {
    return notApplied(
      `Policy scopes to apps matching the attribute filter (${filter.rule}). ` +
        "A newly created service principal has no custom security attributes, so " +
        "this policy will not apply until you assign the attribute."
    );
  }

  const included = lower(apps.includeApplications);
  const reasons: string[] = [];
  let verdict: ImpactVerdict = "willApply";

  if (included.has(appId)) {
    reasons.push(
      "Policy already names this app by ID, but the app has no service principal - " +
        "there is nothing for the policy to match today."
    );
  } else if (included.size === 0 || (included.size === 1 && included.has("none"))) {
    return notApplied("Policy targets no applications.");
  } else if (included.has("all")) {
    reasons.push(
      "Policy targets All resources, which reaches apps that cannot be selected individually."
    );
  } else if (included.has("office365")) {
    verdict = "mayApply";
    reasons.push(
      "Policy targets the Office 365 app suite. Membership of that suite is " +
        "Microsoft-managed and changes over time - check the current suite contents " +
        "to confirm whether this app is part of it."
    );
  } else {
    return notApplied(
      `Policy targets ${apps.includeApplications.length} specific app(s); this app is not one of them.`
    );
  }

  if (filter?.mode === "exclude" && filter.rule) {
    reasons.push(
      `Policy excludes apps matching the attribute filter (${filter.rule}). ` +
        "A new service principal has no custom security attributes, so it is not " +
        "filtered out and stays in scope."
    );
  }

  const clientAppTypes = lower(policy.conditions.clientAppTypes);
  if (clientAppTypes.size > 0 && !clientAppTypes.has("all")) {
    const observedType = mapClientAppUsedToType(app.clientAppUsed);
    if (
      observedType &&
      !typesCovering(observedType).some((t) => clientAppTypes.has(t))
    ) {
      return notApplied(
        `Policy only covers client app types [${policy.conditions.clientAppTypes.join(", ")}], ` +
          `but this app was observed signing in as "${app.clientAppUsed}".`
      );
    }
    if (!observedType) {
      verdict = "mayApply";
      reasons.push(
        `Policy only covers client app types [${policy.conditions.clientAppTypes.join(", ")}] - ` +
          "the observed client app type for this app is unknown."
      );
    }
  }

  if (app.isWorkloadIdentity) {
    const spScope = policy.conditions.clientApplications;
    const scopesServicePrincipals =
      (spScope?.includeServicePrincipals?.length ?? 0) > 0 ||
      !!spScope?.servicePrincipalFilter?.rule ||
      (spScope?.includeAgentIdServicePrincipals?.length ?? 0) > 0;

    if (!scopesServicePrincipals) {
      return notApplied(
        "This app signs in as a workload identity, and this policy scopes users. " +
          "Calls made by service principals are not blocked by user-scoped policies - " +
          "you need Conditional Access for workload identities."
      );
    }
    reasons.push(
      "Policy scopes service principals (workload identities)" +
        (context.licenses.hasWorkloadIdPremium
          ? "."
          : " - this requires Microsoft Entra Workload ID Premium, which was not detected in this tenant.")
    );
  } else {
    const includeUsers = lower(users.includeUsers);
    if (includeUsers.has("none")) {
      return notApplied("Policy targets no users.");
    }
    const scopedToEveryone =
      includeUsers.has("all") &&
      users.includeGroups.length === 0 &&
      users.includeRoles.length === 0;

    if (scopedToEveryone) {
      const excludeNotes = [
        describeUserTargets(users.excludeUsers, context, "Excluded users"),
        describeUserTargets(users.excludeGroups, context, "Excluded groups"),
        describeUserTargets(users.excludeRoles, context, "Excluded roles"),
      ].filter((n): n is string => n !== null);
      if (excludeNotes.length > 0) {
        base.gatedBy.push(...excludeNotes);
      }
    } else {
      verdict = "mayApply";
      const includeNotes = [
        describeUserTargets(users.includeUsers.filter((u) => u.toLowerCase() !== "all"), context, "users"),
        describeUserTargets(users.includeGroups, context, "groups"),
        describeUserTargets(users.includeRoles, context, "roles"),
      ].filter((n): n is string => n !== null);
      const observed = app.userPrincipalName
        ? ` Last observed sign-in was by ${app.userPrincipalName}.`
        : "";
      reasons.push(
        `Policy is scoped to specific ${includeNotes.join("; ") || "users"} - it applies only if the signing-in user is in scope.${observed}`
      );
    }

    if (users.includeGuestsOrExternalUsers) {
      base.gatedBy.push(
        "Policy scopes guest / external user types - internal users may fall outside it."
      );
    }
  }

  base.gatedBy.push(...collectGates(policy, context));

  return { ...base, verdict, reasons };
}

export function evaluateAppImpact(
  app: ObservedAppSignIn,
  context: TenantContext
): PolicyAppImpact[] {
  return context.policies.map((p) => evaluatePolicyImpact(p, app, context));
}

export function wouldBlock(impact: PolicyAppImpact): boolean {
  return impact.state === "enabled" && impact.blocks && impact.verdict === "willApply";
}
