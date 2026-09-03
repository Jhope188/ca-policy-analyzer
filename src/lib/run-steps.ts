// Emitted by loadTenantContext and page.tsx, rendered and located by indexOf
// in RunProgress. One source of truth, so a label can't drift and leave the
// run looking frozen.
export const RUN_STEPS = {
  parseOffline: "Parsing offline export",
  policies: "Loading Conditional Access policies",
  namedLocations: "Loading named locations",
  servicePrincipals: "Loading service principals",
  authStrength: "Loading authentication strength policies",
  caSettings: "Loading Conditional Access baseline settings",
  signInLogs: "Scanning sign-in logs for unregistered apps",
  directoryObjects: "Resolving directory objects",
  licenses: "Detecting tenant licenses",
  tenantIdentity: "Loading tenant identity",
  analyzePolicies: "Analyzing policies",
  templates: "Matching against policy templates",
  posture: "Scoring coverage and security posture",
} as const;

const ANALYSIS_STEPS = [
  RUN_STEPS.analyzePolicies,
  RUN_STEPS.templates,
  RUN_STEPS.posture,
];

/** Omits the sign-in step when off, so the list never shows a step that won't run. */
export function liveStepList(includeSignInLogs: boolean): string[] {
  return [
    RUN_STEPS.policies,
    RUN_STEPS.namedLocations,
    RUN_STEPS.servicePrincipals,
    RUN_STEPS.authStrength,
    RUN_STEPS.caSettings,
    ...(includeSignInLogs ? [RUN_STEPS.signInLogs] : []),
    RUN_STEPS.directoryObjects,
    RUN_STEPS.licenses,
    RUN_STEPS.tenantIdentity,
    ...ANALYSIS_STEPS,
  ];
}

export const offlineStepList: string[] = [
  RUN_STEPS.parseOffline,
  ...ANALYSIS_STEPS,
];
