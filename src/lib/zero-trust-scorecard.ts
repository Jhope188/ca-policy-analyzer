/**
 * Zero Trust Scorecard (Phase 3)
 *
 * Aggregates existing analyzer signals into Microsoft's three Zero Trust
 * principles:
 *
 *   1. Verify Explicitly  - strong auth (MFA, phishing-resistant), device
 *                           compliance, location/risk signals used as trust
 *                           inputs on every access decision.
 *   2. Use Least Privilege - policies are scoped (admins vs internals vs
 *                           guests), excluded users/groups are minimal and
 *                           justified, break-glass is identified, and
 *                           privileged roles aren't bypassed.
 *   3. Assume Breach     - sign-in/user risk policies, session controls
 *                           (SIF, persistent browser), legacy auth blocked,
 *                           and high-risk apps blocked.
 *
 * The scorecard is intentionally a *roll-up* of evidence the analyzer has
 * already collected - it does not re-walk every policy. Each pillar exposes
 * 4–5 weighted signals, each scored 0–100, and the pillar score is the
 * weighted average. The overall posture is the simple average of pillars.
 */

import { AnalysisResult, Finding, Severity } from "./analyzer";
import { PersonaCoverageResult } from "./persona-coverage";
import { TenantContext, ConditionalAccessPolicy } from "./graph-client";
import { policyUsesPhishingResistant } from "./phishing-resistant";

// ─── Types ───────────────────────────────────────────────────────────────────

export type Pillar = "verify-explicitly" | "least-privilege" | "assume-breach";

export interface ScorecardSignal {
  id: string;
  label: string;
  description: string;
  /** 0–100 contribution. */
  score: number;
  /** Weight inside the pillar (relative). */
  weight: number;
  /** Short evidence string, e.g. "8 of 12 enabled policies require MFA". */
  evidence: string;
  status: "good" | "warn" | "bad" | "n/a";
}

export interface PillarScore {
  pillar: Pillar;
  label: string;
  shortLabel: string;
  description: string;
  /** 0–100 weighted average across signals. */
  score: number;
  signals: ScorecardSignal[];
}

export interface ZeroTrustScorecard {
  /** Simple average of the three pillar scores, 0–100. */
  overall: number;
  pillars: PillarScore[];
  generatedAt: string;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

const PILLAR_LABELS: Record<Pillar, { label: string; shortLabel: string; description: string }> = {
  "verify-explicitly": {
    label: "Verify Explicitly",
    shortLabel: "Verify",
    description:
      "Always authenticate and authorize using all available data points: identity, location, device health, service, workload, and behavior anomaly.",
  },
  "least-privilege": {
    label: "Use Least Privilege",
    shortLabel: "Least Priv",
    description:
      "Limit user access with just-in-time and just-enough access (JIT/JEA), risk-based adaptive policies, and tightly scoped exclusions.",
  },
  "assume-breach": {
    label: "Assume Breach",
    shortLabel: "Assume Breach",
    description:
      "Minimize blast radius and segment access. Verify end-to-end encryption, use analytics for visibility, and drive threat detection and improved defenses.",
  },
};

function statusFromScore(score: number): ScorecardSignal["status"] {
  if (score >= 80) return "good";
  if (score >= 50) return "warn";
  if (score < 0) return "n/a";
  return "bad";
}

function isEnabled(p: ConditionalAccessPolicy): boolean {
  return p.state === "enabled";
}

function pillarScore(signals: ScorecardSignal[]): number {
  const eligible = signals.filter((s) => s.status !== "n/a");
  if (eligible.length === 0) return 0;
  const totalW = eligible.reduce((n, s) => n + s.weight, 0);
  if (totalW === 0) return 0;
  const weighted = eligible.reduce((n, s) => n + s.score * s.weight, 0);
  return Math.round(weighted / totalW);
}

function countFindings(findings: Finding[], severities: Severity[]): number {
  return findings.filter((f) => severities.includes(f.severity)).length;
}

// ─── Verify Explicitly ───────────────────────────────────────────────────────

function buildVerifyExplicitly(
  context: TenantContext,
  persona: PersonaCoverageResult
): PillarScore {
  const enabled = context.policies.filter(isEnabled);
  const total = enabled.length || 1;

  // Signal 1: % of enabled policies that require MFA or auth strength
  const mfaCount = enabled.filter(
    (p) =>
      (p.grantControls?.builtInControls ?? []).includes("mfa") ||
      Boolean(p.grantControls?.authenticationStrength?.id)
  ).length;
  const mfaScore = Math.round((mfaCount / total) * 100);

  // Signal 2: Phishing-resistant MFA presence. Resolves the policy's
  // `authenticationStrength.id` against the tenant's authentication-strength
  // catalog (`context.authStrengthPolicies`) and inspects `allowedCombinations`
  // - that's how a custom strength named e.g. "Modern MFA + TAP" that *contains*
  // FIDO2 / WHfB / x509 cert MFA is correctly recognised as phishing-resistant.
  const prPolicies = enabled.filter((p) => policyUsesPhishingResistant(p, context));
  const prCount = prPolicies.length;
  const prScore = prCount > 0 ? Math.min(100, prCount * 50) : 0;

  // Signal 3: Compliant device coverage on enabled policies.
  const cdCount = enabled.filter((p) => {
    const c = p.grantControls?.builtInControls ?? [];
    return c.includes("compliantDevice") || c.includes("domainJoinedDevice");
  }).length;
  const cdScore = Math.round((cdCount / total) * 100);

  // Signal 4: Risk-signal usage (sign-in or user risk on any enabled policy).
  const riskCount = enabled.filter(
    (p) =>
      (p.conditions.signInRiskLevels?.length ?? 0) > 0 ||
      (p.conditions.userRiskLevels?.length ?? 0) > 0
  ).length;
  const riskScore = riskCount > 0 ? Math.min(100, riskCount * 25) : 0;

  // Signal 5: Persona coverage Admins MFA (re-uses Phase 2 result).
  const adminsRow = persona.rows.find((r) => r.persona === "admins");
  const adminsMfa = adminsRow?.controls.find((c) => c.control === "require-mfa");
  const adminsMfaScore =
    !adminsRow || adminsRow.assignedPolicies.length === 0
      ? -1
      : adminsMfa?.status === "present"
        ? 100
        : adminsMfa?.status === "partial"
          ? 50
          : 0;

  const signals: ScorecardSignal[] = [
    {
      id: "ve-mfa",
      label: "MFA on enabled policies",
      description: "Share of enabled CA policies requiring MFA (built-in or auth strength).",
      score: mfaScore,
      weight: 3,
      evidence: `${mfaCount} of ${enabled.length} enabled policies require MFA.`,
      status: statusFromScore(mfaScore),
    },
    {
      id: "ve-phishing-resistant",
      label: "Phishing-resistant MFA in use",
      description:
        "At least one enabled policy uses an authentication strength whose allowed combinations include FIDO2, Windows Hello for Business, or certificate-based MFA.",
      score: prScore,
      weight: 2,
      evidence:
        prCount > 0
          ? `${prCount} polic${prCount === 1 ? "y" : "ies"} use a phishing-resistant auth strength` +
            (prPolicies[0]?.grantControls?.authenticationStrength?.displayName
              ? ` (e.g. "${prPolicies[0].grantControls.authenticationStrength.displayName}").`
              : ".")
          : "No phishing-resistant authentication strength detected on any enabled policy.",
      status: statusFromScore(prScore),
    },
    {
      id: "ve-compliant-device",
      label: "Compliant device coverage",
      description: "Share of enabled policies requiring compliant or hybrid-joined device.",
      score: cdScore,
      weight: 2,
      evidence: `${cdCount} of ${enabled.length} enabled policies require compliant device.`,
      status: statusFromScore(cdScore),
    },
    {
      id: "ve-risk-signals",
      label: "Risk signals as conditions",
      description: "Sign-in or user risk levels referenced by enabled policies.",
      score: riskScore,
      weight: 2,
      evidence: riskCount > 0
        ? `${riskCount} polic${riskCount === 1 ? "y" : "ies"} consume sign-in or user risk signals.`
        : "No enabled policy uses sign-in or user risk as a condition.",
      status: statusFromScore(riskScore),
    },
    {
      id: "ve-admin-mfa",
      label: "Admins persona MFA",
      description: "Persona-coverage check: Admins persona policies enforce MFA.",
      score: adminsMfaScore,
      weight: 3,
      evidence:
        adminsMfaScore < 0
          ? "No policies assigned to the Admins persona - N/A."
          : `Admins persona MFA control: ${adminsMfa?.status}.`,
      status: adminsMfaScore < 0 ? "n/a" : statusFromScore(adminsMfaScore),
    },
  ];

  return {
    pillar: "verify-explicitly",
    ...PILLAR_LABELS["verify-explicitly"],
    score: pillarScore(signals),
    signals,
  };
}

// ─── Use Least Privilege ─────────────────────────────────────────────────────

function buildLeastPrivilege(
  context: TenantContext,
  result: AnalysisResult,
  persona: PersonaCoverageResult
): PillarScore {
  const enabled = context.policies.filter(isEnabled);
  const total = enabled.length || 1;

  // Signal 1: Persona-segmented policies present (admins, externals, etc.).
  const segmentedPersonas = persona.rows.filter(
    (r) => r.persona !== "global" && r.persona !== "internals" && r.assignedPolicies.length > 0
  ).length;
  const segScore = Math.min(100, segmentedPersonas * 25);

  // Signal 2: Privileged-role exclusion findings (critical/high). Inverse
  // score - fewer findings = higher score.
  const privExclFindings = result.findings.filter((f) =>
    f.category.toLowerCase().includes("privileged role") ||
    /admin.?role|priv/i.test(f.title)
  );
  const privCrit = countFindings(privExclFindings, ["critical", "high"]);
  const privScore = privCrit === 0 ? 100 : Math.max(0, 100 - privCrit * 20);

  // Signal 3: Scope discipline - penalize "All users + All apps + no MFA"
  // policies, which are typically misconfigured tenant-wide blockers.
  const blanketCount = enabled.filter((p) => {
    const u = p.conditions.users.includeUsers ?? [];
    const a = p.conditions.applications.includeApplications ?? [];
    const grants = p.grantControls?.builtInControls ?? [];
    return (
      u.includes("All") &&
      a.includes("All") &&
      grants.length === 0 &&
      !p.grantControls?.authenticationStrength
    );
  }).length;
  const scopeScore = blanketCount === 0 ? 100 : Math.max(0, 100 - blanketCount * 30);

  // Signal 4: Break-glass identified by analyzer. We look for any finding
  // mentioning break-glass; presence = good, absence = unknown (warn).
  const bgEvidence = result.findings.find((f) =>
    f.category.toLowerCase().includes("break-glass") ||
    /break.?glass|emergency access/i.test(f.title)
  );
  const bgScore = bgEvidence ? 100 : 50;

  // Signal 5: FOCI / token-sharing exclusion findings. Inverse score.
  const fociCount = countFindings(
    result.findings.filter((f) =>
      f.category.toLowerCase().includes("foci") ||
      /token.?sharing|shared refresh/i.test(f.title)
    ),
    ["critical", "high"]
  );
  const fociScore = fociCount === 0 ? 100 : Math.max(0, 100 - fociCount * 25);

  const signals: ScorecardSignal[] = [
    {
      id: "lp-segmentation",
      label: "Persona segmentation",
      description: "Distinct policies for Admins, Externals, ServiceAccounts, etc. (not just one tenant-wide blob).",
      score: segScore,
      weight: 3,
      evidence: `${segmentedPersonas} segmented persona${segmentedPersonas === 1 ? "" : "s"} have assigned policies.`,
      status: statusFromScore(segScore),
    },
    {
      id: "lp-privileged-exclusions",
      label: "Privileged role exclusions",
      description: "No admin roles bypassing MFA / compliance via excludeRoles.",
      score: privScore,
      weight: 3,
      evidence:
        privCrit === 0
          ? "No critical/high privileged-role exclusion findings."
          : `${privCrit} privileged-role exclusion finding${privCrit === 1 ? "" : "s"} (critical/high).`,
      status: statusFromScore(privScore),
    },
    {
      id: "lp-scope",
      label: "Scope discipline",
      description: "Penalizes 'All users + All apps + no controls' policies.",
      score: scopeScore,
      weight: 2,
      evidence:
        blanketCount === 0
          ? "No blanket all-users/all-apps no-control policies detected."
          : `${blanketCount} blanket polic${blanketCount === 1 ? "y" : "ies"} with no enforced controls.`,
      status: statusFromScore(scopeScore),
    },
    {
      id: "lp-break-glass",
      label: "Break-glass identified",
      description: "Analyzer detected at least one break-glass / emergency access account.",
      score: bgScore,
      weight: 2,
      evidence: bgEvidence
        ? "Break-glass account detected and annotated across policies."
        : "No break-glass account identified - verify emergency access design.",
      status: statusFromScore(bgScore),
    },
    {
      id: "lp-foci",
      label: "FOCI token-sharing",
      description: "App exclusions don't break trust boundaries via the Family of Client IDs.",
      score: fociScore,
      weight: 2,
      evidence:
        fociCount === 0
          ? "No FOCI / token-sharing critical/high findings."
          : `${fociCount} FOCI finding${fociCount === 1 ? "" : "s"}.`,
      status: statusFromScore(fociScore),
    },
  ];
  // Avoid `total` being unused in the signal calc above
  void total;

  return {
    pillar: "least-privilege",
    ...PILLAR_LABELS["least-privilege"],
    score: pillarScore(signals),
    signals,
  };
}

// ─── Assume Breach ───────────────────────────────────────────────────────────

function buildAssumeBreach(
  context: TenantContext,
  result: AnalysisResult,
  persona: PersonaCoverageResult
): PillarScore {
  const enabled = context.policies.filter(isEnabled);

  // Signal 1: Legacy auth block - Global persona must have block-legacy-auth.
  const globalRow = persona.rows.find((r) => r.persona === "global");
  const legacy = globalRow?.controls.find((c) => c.control === "block-legacy-auth");
  const legacyScore =
    legacy?.status === "present" ? 100 : legacy?.status === "partial" ? 50 : 0;

  // Signal 2: Sign-in risk policies enabled (any).
  const sirPolicies = enabled.filter(
    (p) => (p.conditions.signInRiskLevels?.length ?? 0) > 0
  );
  const sirScore = sirPolicies.length > 0 ? Math.min(100, sirPolicies.length * 50) : 0;

  // Signal 3: User risk policies enabled (any).
  const urPolicies = enabled.filter(
    (p) => (p.conditions.userRiskLevels?.length ?? 0) > 0
  );
  const urScore = urPolicies.length > 0 ? Math.min(100, urPolicies.length * 50) : 0;

  // Signal 4: Session controls (SIF or persistent browser) on any enabled.
  const sessionPolicies = enabled.filter(
    (p) =>
      p.sessionControls?.signInFrequency?.isEnabled ||
      p.sessionControls?.persistentBrowser?.isEnabled
  );
  const sessionScore = sessionPolicies.length > 0 ? Math.min(100, sessionPolicies.length * 25) : 0;

  // Signal 5: High-severity findings backlog. Inverse score, capped at 0.
  const critHigh = countFindings(result.findings, ["critical", "high"]);
  const findingsScore = Math.max(0, 100 - critHigh * 5);

  const signals: ScorecardSignal[] = [
    {
      id: "ab-legacy",
      label: "Legacy authentication blocked",
      description: "A tenant-wide policy blocks ActiveSync / 'other' clients.",
      score: legacyScore,
      weight: 3,
      evidence:
        legacy?.status === "present"
          ? "Global persona has an enforced legacy-auth block policy."
          : legacy?.status === "partial"
            ? "Legacy-auth block is report-only - not enforced."
            : "No enabled legacy-auth block policy detected at the Global persona.",
      status: legacyScore < 0 ? "n/a" : statusFromScore(legacyScore),
    },
    {
      id: "ab-signin-risk",
      label: "Sign-in risk policies",
      description: "Real-time risk signals trigger MFA or block on suspicious sign-ins.",
      score: sirScore,
      weight: 2,
      evidence: sirPolicies.length > 0
        ? `${sirPolicies.length} policy uses sign-in risk levels.`
        : "No enabled policy consumes sign-in risk levels.",
      status: statusFromScore(sirScore),
    },
    {
      id: "ab-user-risk",
      label: "User risk policies",
      description: "Compromised-user risk triggers password reset or block.",
      score: urScore,
      weight: 2,
      evidence: urPolicies.length > 0
        ? `${urPolicies.length} policy uses user risk levels.`
        : "No enabled policy consumes user risk levels.",
      status: statusFromScore(urScore),
    },
    {
      id: "ab-session",
      label: "Session controls",
      description: "Sign-in frequency / persistent-browser controls limit token lifetime.",
      score: sessionScore,
      weight: 2,
      evidence: sessionPolicies.length > 0
        ? `${sessionPolicies.length} polic${sessionPolicies.length === 1 ? "y" : "ies"} enforce session controls.`
        : "No enabled policy enforces sign-in frequency or persistent-browser.",
      status: statusFromScore(sessionScore),
    },
    {
      id: "ab-findings-backlog",
      label: "Critical/high findings backlog",
      description: "Open critical and high findings reduce this score by 5 each.",
      score: findingsScore,
      weight: 3,
      evidence:
        critHigh === 0
          ? "No open critical/high findings."
          : `${critHigh} open critical/high finding${critHigh === 1 ? "" : "s"}.`,
      status: statusFromScore(findingsScore),
    },
  ];

  return {
    pillar: "assume-breach",
    ...PILLAR_LABELS["assume-breach"],
    score: pillarScore(signals),
    signals,
  };
}

// ─── Public ──────────────────────────────────────────────────────────────────

export function buildZeroTrustScorecard(
  context: TenantContext,
  result: AnalysisResult,
  persona: PersonaCoverageResult
): ZeroTrustScorecard {
  const pillars: PillarScore[] = [
    buildVerifyExplicitly(context, persona),
    buildLeastPrivilege(context, result, persona),
    buildAssumeBreach(context, result, persona),
  ];
  const overall = Math.round(pillars.reduce((n, p) => n + p.score, 0) / pillars.length);
  return {
    overall,
    pillars,
    generatedAt: new Date().toISOString(),
  };
}
