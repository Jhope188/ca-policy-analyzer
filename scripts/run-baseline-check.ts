import { checkBaselineEnforcement } from "../src/lib/analyzer";

// Minimal mock shapes to exercise the check
const mockPolicy: any = {
  id: "policy-1",
  displayName: "IAC - GLOBAL - GRANT - MFA - WindowsAzureAD-BaselineScopes",
  state: "enabled",
  conditions: {
    applications: {
      includeApplications: ["00000002-0000-0000-c000-000000000000"],
      excludeApplications: ["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"],
    },
  },
  grantControls: {},
};

const mockContext: any = {
  policies: [mockPolicy],
  // Case: advancedSettings present but baselineScopes.resourceAppId unset/null
  conditionalAccessSettings: {
    advancedSettings: null,
  },
};

async function run() {
  const findings = checkBaselineEnforcement(mockPolicy, mockContext);
  console.log(JSON.stringify(findings, null, 2));
}

run().catch((e) => {
  console.error(e);
  process.exit(1);
});
