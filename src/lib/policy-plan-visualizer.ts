/**
 * Conditional Access Policy Plans (preview) - display-only summarizer.
 *
 * Plans and their rules reuse the same `conditions` / `grantControls` /
 * `sessionControls` shapes as a standalone policy (see
 * `ConditionalAccessConditionSet` in graph-client.ts), just with every field
 * optional since a plan's shared conditions and a rule's own conditions are
 * each allowed to specify only part of the picture.
 *
 * This intentionally mirrors `buildVisualization` in analyzer.ts rather than
 * reusing it directly - that function assumes every field on a full
 * `ConditionalAccessPolicy` is present, which shared conditions and rules
 * aren't guaranteed to be. Kept separate, and read-only (no findings/scoring)
 * since policy plans don't yet feed the analyzer - see the Policy Plans tab.
 */

import {
  ConditionalAccessConditionSet,
  ConditionalAccessPolicyRuleControls,
  NamedLocation,
  ServicePrincipal,
} from "./graph-client";
import { WELL_KNOWN_APP_MAP } from "@/data/ca-bypass-database";

export interface ConditionSetSummary {
  targetUsers: string | null;
  targetApps: string | null;
  conditions: string[];
}

export interface ControlsSummary {
  grantControls: string[];
  sessionControls: string[];
}

/** Minimal slice of TenantContext needed to resolve names - avoids pulling in the full type. */
export interface PlanVisualizerContext {
  namedLocations: NamedLocation[];
  servicePrincipals: Map<string, ServicePrincipal>;
}

export function summarizeConditionSet(
  conditions: ConditionalAccessConditionSet | undefined,
  context: PlanVisualizerContext
): ConditionSetSummary {
  if (!conditions) return { targetUsers: null, targetApps: null, conditions: [] };

  const { users, applications, locations, platforms } = conditions;

  let targetUsers: string | null = null;
  if (users) {
    if (users.includeUsers?.includes("All")) {
      const excCount =
        (users.excludeUsers?.length ?? 0) +
        (users.excludeGroups?.length ?? 0) +
        (users.excludeRoles?.length ?? 0);
      targetUsers = excCount > 0 ? `All users (${excCount} exclusions)` : "All users";
    } else if (users.includeUsers?.includes("GuestsOrExternalUsers")) {
      targetUsers = "Guests / External users";
    } else {
      const count =
        (users.includeUsers?.length ?? 0) +
        (users.includeGroups?.length ?? 0) +
        (users.includeRoles?.length ?? 0);
      if (count > 0) targetUsers = `${count} specific user/group/role targets`;
    }
  }

  let targetApps: string | null = null;
  if (applications) {
    if (applications.includeApplications?.includes("All")) {
      const excCount = applications.excludeApplications?.length ?? 0;
      targetApps = excCount > 0 ? `All cloud apps (${excCount} exclusions)` : "All cloud apps";
    } else if ((applications.includeUserActions?.length ?? 0) > 0) {
      targetApps = `User actions: ${applications.includeUserActions!.join(", ")}`;
    } else if ((applications.includeApplications?.length ?? 0) > 0) {
      targetApps = applications
        .includeApplications!.map((id) => {
          const lower = id.toLowerCase();
          const known = WELL_KNOWN_APP_MAP.get(lower);
          if (known?.displayName) return known.displayName;
          const sp = context.servicePrincipals.get(lower);
          if (sp?.displayName) return sp.displayName;
          return id;
        })
        .join(", ");
    }
  }

  const conditionList: string[] = [];
  if (locations?.includeLocations?.length) {
    const locNames = locations.includeLocations.map((id) => {
      if (id === "AllTrusted") return "All trusted locations";
      if (id === "All") return "All locations";
      const loc = context.namedLocations.find((l) => l.id === id);
      return loc ? loc.displayName : id;
    });
    conditionList.push(`Locations: ${locNames.join(", ")}`);
    if (locations.excludeLocations?.length) {
      const exclNames = locations.excludeLocations.map((id) => {
        if (id === "AllTrusted") return "All trusted locations";
        if (id === "All") return "All locations";
        const loc = context.namedLocations.find((l) => l.id === id);
        return loc ? loc.displayName : id;
      });
      conditionList.push(`Exclude locations: ${exclNames.join(", ")}`);
    }
  }
  if (platforms?.includePlatforms?.length) {
    let platText = `Platforms: ${platforms.includePlatforms.join(", ")}`;
    if (platforms.excludePlatforms?.length) {
      platText += ` (exclude: ${platforms.excludePlatforms.join(", ")})`;
    }
    conditionList.push(platText);
  }
  if (conditions.userRiskLevels?.length) {
    conditionList.push(`User risk: ${conditions.userRiskLevels.join(", ")}`);
  }
  if (conditions.signInRiskLevels?.length) {
    conditionList.push(`Sign-in risk: ${conditions.signInRiskLevels.join(", ")}`);
  }
  if (conditions.clientAppTypes?.length) {
    conditionList.push(`Client apps: ${conditions.clientAppTypes.join(", ")}`);
  }
  if (conditions.devices?.deviceFilter) {
    conditionList.push(`Device filter: ${conditions.devices.deviceFilter.rule}`);
  }
  if (conditions.insiderRiskLevels) {
    conditionList.push(`Insider risk: ${conditions.insiderRiskLevels}`);
  }
  if (conditions.agentIdRiskLevels) {
    conditionList.push(`Agent risk: ${conditions.agentIdRiskLevels}`);
  }

  return { targetUsers, targetApps, conditions: conditionList };
}

export function summarizeControls(
  controls: ConditionalAccessPolicyRuleControls | undefined
): ControlsSummary {
  const grantControls: string[] = [];
  if (controls?.grantControls) {
    const g = controls.grantControls;
    if (g.builtInControls.includes("block")) {
      grantControls.push("🚫 Block access");
    } else {
      const names = g.builtInControls.map((c) => {
        switch (c) {
          case "mfa": return "✅ Require MFA";
          case "compliantDevice": return "📱 Require compliant device";
          case "domainJoinedDevice": return "💻 Require hybrid Azure AD joined";
          case "approvedApplication": return "✅ Require approved app";
          case "compliantApplication": return "✅ Require app protection policy";
          case "passwordChange": return "🔑 Require password change";
          default: return c;
        }
      });
      if (g.authenticationStrength) {
        names.push(`🛡️ Auth strength: ${g.authenticationStrength.displayName}`);
      }
      if (names.length > 0) grantControls.push(names.join(` ${g.operator} `));
    }
  }

  const sessionControls: string[] = [];
  if (controls?.sessionControls) {
    const s = controls.sessionControls;
    if (s.signInFrequency?.isEnabled) {
      sessionControls.push(`Sign-in frequency: ${s.signInFrequency.value} ${s.signInFrequency.type}`);
    }
    if (s.persistentBrowser?.isEnabled) {
      sessionControls.push(`Persistent browser: ${s.persistentBrowser.mode}`);
    }
    if (s.cloudAppSecurity?.isEnabled) {
      sessionControls.push("Cloud App Security");
    }
    if (s.continuousAccessEvaluation) {
      sessionControls.push(`CAE: ${s.continuousAccessEvaluation.mode}`);
    }
    if (s.disableResilienceDefaults) {
      sessionControls.push("⚠️ Resilience defaults disabled");
    }
  }

  return { grantControls, sessionControls };
}

export const PLAN_RULE_STATE_LABEL: Record<string, string> = {
  enabled: "✅ Enabled",
  disabled: "⛔ Disabled",
  enabledForReportingButNotEnforced: "📊 Report-only",
};
