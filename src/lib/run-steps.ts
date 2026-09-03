/**
 * Step labels for one analysis run.
 *
 * loadTenantContext and page.tsx emit these strings, RunProgress renders them
 * and locates the current one with indexOf. One source of truth so the emitted
 * label can't drift from the rendered list and leave the UI looking frozen.
 */
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

/** Local computation over data already fetched - these tick over in a flash. */
const ANALYSIS_STEPS = [
  RUN_STEPS.analyzePolicies,
  RUN_STEPS.templates,
  RUN_STEPS.posture,
];

/**
 * Live Graph run. The sign-in log step is left out entirely when the scan is
 * off, so the list never shows a step that is never going to run.
 */
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

/** Offline import does no Graph calls at all - it parses, then analyzes. */
export const offlineStepList: string[] = [
  RUN_STEPS.parseOffline,
  ...ANALYSIS_STEPS,
];
