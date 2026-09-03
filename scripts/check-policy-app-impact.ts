/** Run: npx tsx scripts/check-policy-app-impact.ts */

import assert from "node:assert/strict";
import {
  evaluatePolicyImpact,
  mapClientAppUsedToType,
  type ObservedAppSignIn,
} from "../src/lib/policy-app-impact";
import type {
  ConditionalAccessPolicy,
  TenantContext,
} from "../src/lib/graph-client";

const TARGET_APP = "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb";
const OTHER_APP = "cccccccc-4444-5555-6666-dddddddddddd";

// ─── Fixtures ────────────────────────────────────────────────────────────────

type PolicyOverrides = Omit<Partial<ConditionalAccessPolicy>, "conditions"> & {
  applications?: Partial<ConditionalAccessPolicy["conditions"]["applications"]>;
  users?: Partial<ConditionalAccessPolicy["conditions"]["users"]>;
  conditions?: Partial<ConditionalAccessPolicy["conditions"]>;
};

function policy(overrides: PolicyOverrides = {}): ConditionalAccessPolicy {
  const { applications, users, conditions, ...rest } = overrides;
  return {
    id: "p1",
    displayName: "Test policy",
    state: "enabled",
    createdDateTime: "",
    modifiedDateTime: "",
    conditions: {
      users: {
        includeUsers: ["All"],
        excludeUsers: [],
        includeGroups: [],
        excludeGroups: [],
        includeRoles: [],
        excludeRoles: [],
        ...users,
      },
      applications: {
        includeApplications: ["All"],
        excludeApplications: [],
        includeUserActions: [],
        includeAuthenticationContextClassReferences: [],
        ...applications,
      },
      clientAppTypes: ["all"],
      userRiskLevels: [],
      signInRiskLevels: [],
      ...conditions,
    },
    grantControls: {
      operator: "OR",
      builtInControls: ["mfa"],
      customAuthenticationFactors: [],
      termsOfUse: [],
    },
    ...rest,
  };
}

const context: TenantContext = {
  tenantDisplayName: "Contoso",
  tenantId: "tenant-1",
  policies: [],
  namedLocations: [],
  servicePrincipals: new Map(),
  directoryObjects: new Map([
    [
      "group-1",
      { id: "group-1", displayName: "Finance", "@odata.type": "#microsoft.graph.group" },
    ],
  ]),
  licenses: {
    hasEntraIdP1: true,
    hasEntraIdP2: false,
    hasIntunePlan1: false,
    hasWorkloadIdPremium: false,
  },
  authStrengthPolicies: new Map(),
};

const userApp: ObservedAppSignIn = {
  appId: TARGET_APP,
  clientAppUsed: "Browser",
  userPrincipalName: "user@contoso.com",
  isWorkloadIdentity: false,
};

// ─── Checks ──────────────────────────────────────────────────────────────────

const checks: Array<[string, () => void]> = [
  [
    "All resources + all users => willApply",
    () => {
      const r = evaluatePolicyImpact(policy(), userApp, context);
      assert.equal(r.verdict, "willApply");
      assert.equal(r.blocks, false);
      assert.match(r.reasons[0], /All resources/);
    },
  ],

  [
    "explicit exclusion => willNotApply + phantom exclusion",
    () => {
      const r = evaluatePolicyImpact(
        policy({ applications: { excludeApplications: [TARGET_APP] } }),
        userApp,
        context
      );
      assert.equal(r.verdict, "willNotApply");
      assert.equal(r.phantomExclusion, true);
    },
  ],

  [
    "exclusion matches regardless of GUID casing",
    () => {
      const r = evaluatePolicyImpact(
        policy({
          applications: { excludeApplications: [TARGET_APP.toUpperCase()] },
        }),
        userApp,
        context
      );
      assert.equal(r.phantomExclusion, true);
    },
  ],

  [
    "explicit inclusion of a non-existent app => willApply",
    () => {
      const r = evaluatePolicyImpact(
        policy({ applications: { includeApplications: [TARGET_APP] } }),
        userApp,
        context
      );
      assert.equal(r.verdict, "willApply");
      assert.match(r.reasons[0], /already names this app by ID/);
    },
  ],

  [
    "include-mode application filter => willNotApply (fresh SP has no attributes)",
    () => {
      const r = evaluatePolicyImpact(
        policy({
          applications: {
            applicationFilter: {
              mode: "include",
              rule: "CustomSecurityAttribute.Set_Tag -eq 'x'",
            },
          },
        }),
        userApp,
        context
      );
      assert.equal(r.verdict, "willNotApply");
      assert.match(r.reasons[0], /custom security attributes/);
    },
  ],

  [
    "exclude-mode application filter => still in scope",
    () => {
      const r = evaluatePolicyImpact(
        policy({
          applications: {
            applicationFilter: {
              mode: "exclude",
              rule: "CustomSecurityAttribute.Set_Tag -eq 'x'",
            },
          },
        }),
        userApp,
        context
      );
      assert.equal(r.verdict, "willApply");
      assert.ok(r.reasons.some((x) => /stays in scope/.test(x)));
    },
  ],

  [
    "user-action policy => willNotApply",
    () => {
      const r = evaluatePolicyImpact(
        policy({
          applications: {
            includeApplications: [],
            includeUserActions: ["urn:user:registersecurityinfo"],
          },
        }),
        userApp,
        context
      );
      assert.equal(r.verdict, "willNotApply");
      assert.match(r.reasons[0], /user action/);
    },
  ],

  [
    "auth-context policy => willNotApply",
    () => {
      const r = evaluatePolicyImpact(
        policy({
          applications: {
            includeApplications: [],
            includeAuthenticationContextClassReferences: ["c1"],
          },
        }),
        userApp,
        context
      );
      assert.equal(r.verdict, "willNotApply");
      assert.match(r.reasons[0], /authentication context/);
    },
  ],

  [
    "policy targeting other specific apps => willNotApply",
    () => {
      const r = evaluatePolicyImpact(
        policy({ applications: { includeApplications: [OTHER_APP] } }),
        userApp,
        context
      );
      assert.equal(r.verdict, "willNotApply");
      assert.match(r.reasons[0], /specific app/);
    },
  ],

  [
    "includeApplications None => willNotApply",
    () => {
      const r = evaluatePolicyImpact(
        policy({ applications: { includeApplications: ["None"] } }),
        userApp,
        context
      );
      assert.equal(r.verdict, "willNotApply");
    },
  ],

  [
    "Office365 suite => mayApply (membership is Microsoft-managed)",
    () => {
      const r = evaluatePolicyImpact(
        policy({ applications: { includeApplications: ["Office365"] } }),
        userApp,
        context
      );
      assert.equal(r.verdict, "mayApply");
    },
  ],

  [
    "clientAppTypes mismatch against observed type => willNotApply",
    () => {
      const r = evaluatePolicyImpact(
        policy({ conditions: { clientAppTypes: ["exchangeActiveSync", "other"] } }),
        userApp,
        context
      );
      assert.equal(r.verdict, "willNotApply");
      assert.match(r.reasons[0], /Browser/);
    },
  ],

  [
    "clientAppTypes match against observed type => willApply",
    () => {
      const r = evaluatePolicyImpact(
        policy({ conditions: { clientAppTypes: ["browser"] } }),
        userApp,
        context
      );
      assert.equal(r.verdict, "willApply");
    },
  ],

  [
    "EAS supported variant satisfies an exchangeActiveSync policy",
    () => {
      const r = evaluatePolicyImpact(
        policy({ conditions: { clientAppTypes: ["exchangeActiveSync"] } }),
        { ...userApp, clientAppUsed: "Exchange ActiveSync (supported)" },
        context
      );
      assert.equal(r.verdict, "willApply");
    },
  ],

  [
    "unknown observed client app type downgrades to mayApply",
    () => {
      const r = evaluatePolicyImpact(
        policy({ conditions: { clientAppTypes: ["browser"] } }),
        { ...userApp, clientAppUsed: undefined },
        context
      );
      assert.equal(r.verdict, "mayApply");
    },
  ],

  [
    "group-scoped users => mayApply, naming the resolved group",
    () => {
      const r = evaluatePolicyImpact(
        policy({ users: { includeUsers: [], includeGroups: ["group-1"] } }),
        userApp,
        context
      );
      assert.equal(r.verdict, "mayApply");
      assert.ok(r.reasons.some((x) => x.includes("Finance")));
      assert.ok(r.reasons.some((x) => x.includes("user@contoso.com")));
    },
  ],

  [
    "includeUsers None => willNotApply",
    () => {
      const r = evaluatePolicyImpact(
        policy({ users: { includeUsers: ["None"] } }),
        userApp,
        context
      );
      assert.equal(r.verdict, "willNotApply");
    },
  ],

  [
    "user exclusions surface as gates, not verdict changes",
    () => {
      const r = evaluatePolicyImpact(
        policy({ users: { excludeGroups: ["group-1"] } }),
        userApp,
        context
      );
      assert.equal(r.verdict, "willApply");
      assert.ok(r.gatedBy.some((g) => g.includes("Finance")));
    },
  ],

  [
    "workload identity vs user-scoped policy => willNotApply",
    () => {
      const r = evaluatePolicyImpact(
        policy(),
        {
          appId: TARGET_APP,
          isWorkloadIdentity: true,
        },
        context
      );
      assert.equal(r.verdict, "willNotApply");
      assert.match(r.reasons[0], /workload identit/);
    },
  ],

  [
    "workload identity vs SP-scoped policy => applies, flags missing licence",
    () => {
      const r = evaluatePolicyImpact(
        policy({
          conditions: {
            clientApplications: {
              includeServicePrincipals: ["ServicePrincipalsInMyTenant"],
              excludeServicePrincipals: [],
            },
          },
        }),
        { appId: TARGET_APP, isWorkloadIdentity: true },
        context
      );
      assert.equal(r.verdict, "willApply");
      assert.ok(r.reasons.some((x) => /Workload ID Premium/.test(x)));
    },
  ],

  [
    "block policy sets blocks",
    () => {
      const r = evaluatePolicyImpact(
        policy({
          grantControls: {
            operator: "OR",
            builtInControls: ["block"],
            customAuthenticationFactors: [],
            termsOfUse: [],
          },
        }),
        userApp,
        context
      );
      assert.equal(r.blocks, true);
    },
  ],

  [
    "policy state is carried through untouched",
    () => {
      const r = evaluatePolicyImpact(
        policy({ state: "enabledForReportingButNotEnforced" }),
        userApp,
        context
      );
      assert.equal(r.state, "enabledForReportingButNotEnforced");
      assert.equal(r.verdict, "willApply");
    },
  ],

  [
    "risk conditions surface as gates with the P2 caveat",
    () => {
      const r = evaluatePolicyImpact(
        policy({ conditions: { signInRiskLevels: ["high"] } }),
        userApp,
        context
      );
      assert.equal(r.verdict, "willApply");
      assert.ok(r.gatedBy.some((g) => /Entra ID P2/.test(g)));
    },
  ],

  [
    "clientAppUsed mapping covers legacy protocols",
    () => {
      assert.equal(mapClientAppUsedToType("IMAP4"), "other");
      assert.equal(mapClientAppUsedToType("Browser"), "browser");
      assert.equal(
        mapClientAppUsedToType("Mobile Apps and Desktop clients"),
        "mobileAppsAndDesktopClients"
      );
      assert.equal(mapClientAppUsedToType("Something New"), undefined);
      assert.equal(mapClientAppUsedToType(undefined), undefined);
    },
  ],
];

let failed = 0;
for (const [name, fn] of checks) {
  try {
    fn();
    console.log(`  ok   ${name}`);
  } catch (e) {
    failed += 1;
    console.error(`  FAIL ${name}`);
    console.error(`       ${e instanceof Error ? e.message : String(e)}`);
  }
}

console.log(`\n${checks.length - failed}/${checks.length} checks passed`);
if (failed > 0) process.exit(1);
