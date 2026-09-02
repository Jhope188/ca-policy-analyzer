// Standalone verification of baseline-enforcement logic (no project imports)

type Policy = any;

type Context = any;

function standaloneCheckBaselineEnforcement(policy: Policy, context: Context) {
  const findings: any[] = [];
  if (!policy || policy.state === "disabled") return findings;

  const WINDOWS_AZURE_AD_RESOURCE = "00000002-0000-0000-c000-000000000000";

  const apps = policy.conditions?.applications;
  if (!apps || !Array.isArray(apps.includeApplications)) return findings;

  const targetsBaselineApp = apps.includeApplications
    .map((a: any) => String(a).toLowerCase())
    .includes(WINDOWS_AZURE_AD_RESOURCE.toLowerCase());

  if (!targetsBaselineApp) return findings;

  const excluded = apps.excludeApplications ?? [];
  if (!excluded || excluded.length === 0) return findings;

  const casettings = (context as any).conditionalAccessSettings;
  const advanced = casettings?.advancedSettings ?? null;
  const baselineScope = advanced?.baselineScopes?.resourceAppId ?? null;

  const isEnforcedForAzureAd =
    String(baselineScope).toLowerCase() === WINDOWS_AZURE_AD_RESOURCE.toLowerCase();

  if (isEnforcedForAzureAd) return findings;

  findings.push({
    id: "TEST-1",
    policyId: policy.id,
    policyName: policy.displayName,
    severity: "high",
    category: "Baseline Enforcement",
    title: "Enable baseline enforcement for Windows Azure AD or remove service-principal exclusions",
    description: `This policy targets the Windows Azure AD baseline-scoped app (${WINDOWS_AZURE_AD_RESOURCE}) but has ${excluded.length} excluded app(s). Tenant baseline enforcement is not currently targeting the Windows Azure AD app (tenant setting: ${baselineScope ?? "unset/null"}).`,
    recommendation: "Enable baseline enforcement or remove exclusions",
    relatedIds: excluded,
  });

  return findings;
}

const mockPolicy = {
  id: "policy-1",
  displayName: "IAC - GLOBAL - GRANT - MFA - WindowsAzureAD-BaselineScopes",
  state: "enabled",
  conditions: {
    applications: {
      includeApplications: ["00000002-0000-0000-c000-000000000000"],
      excludeApplications: ["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"],
    },
  },
};

const mockContext = {
  conditionalAccessSettings: { advancedSettings: null },
};

const findings = standaloneCheckBaselineEnforcement(mockPolicy, mockContext);
console.log(JSON.stringify(findings, null, 2));

if (findings.length === 0) {
  console.error("Standalone check failed: expected a finding but got none");
  process.exit(2);
}
console.log("Standalone baseline check passed");
