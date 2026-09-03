/**
 * Baseline Gap Analysis (Phase 4)
 *
 * Compares a tenant's live CA policies against a *loaded* Zero Trust baseline
 * (Kenneth, Joey, custom GitHub repo, or the built-in template set) and
 * produces a focused gap report:
 *
 *   1. **Missing**    - baseline policies the tenant doesn't have
 *   2. **Drift**      - baseline policies present, but the tenant's
 *                       implementation differs (lower confidence match)
 *   3. **Tenant-only** - tenant policies that don't map to any template
 *                       (shadow / custom / drift the other direction)
 *
 * Everything is grouped by Zero Trust persona so an operator sees, e.g.,
 * "Admins is missing 3 baseline policies and has 2 unaccounted-for tenant
 * policies."
 *
 * The analyzer is a *roll-up* of `TemplateAnalysisResult` - no extra Graph
 * calls, no template re-scanning. It just reclassifies and re-groups.
 */

import { ConditionalAccessPolicy, TenantContext } from "./graph-client";
import { TemplateAnalysisResult, TemplateMatch } from "./template-matcher";
import { Persona, PERSONA_ORDER, PERSONA_META, detectPersona } from "./personas";

// ─── Types ───────────────────────────────────────────────────────────────────

export type GapKind = "missing" | "drift" | "tenant-only";

export interface BaselineGapEntry {
  kind: GapKind;
  /** Stable identifier for React keys */
  id: string;
  /** What the user sees */
  label: string;
  /** Persona this gap is attributed to */
  persona: Persona;
  /** Severity: critical templates → critical, recommended → high, optional → medium, tenant-only → low */
  severity: "critical" | "high" | "medium" | "low";
  /** One-line summary of the gap */
  summary: string;
  /** Specific differences / actions */
  details: string[];
  /** Underlying template (for missing/drift) */
  templateId?: string;
  /** Underlying tenant policy ids (for drift / tenant-only) */
  policyIds?: string[];
}

export interface PersonaGapBucket {
  persona: Persona;
  label: string;
  shortLabel: string;
  emoji: string;
  /** All entries that touch this persona */
  entries: BaselineGapEntry[];
  missingCount: number;
  driftCount: number;
  tenantOnlyCount: number;
}

export interface BaselineGapResult {
  /** Total unique baseline templates considered */
  baselineTemplateCount: number;
  /** Total tenant policies considered */
  tenantPolicyCount: number;
  /** All gap entries flat */
  entries: BaselineGapEntry[];
  /** Bucketed by persona, in PERSONA_ORDER (skipping empty) */
  buckets: PersonaGapBucket[];
  /** Summary counts */
  missing: number;
  drift: number;
  tenantOnly: number;
  /** Coverage score 0–100: how much of the baseline the tenant implements */
  coverageScore: number;
  generatedAt: string;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function severityForMatch(match: TemplateMatch, context?: any): BaselineGapEntry["severity"] {
  const p = match.template.priority;

  // Special-case: when tenant baseline enforcement targets Windows Azure AD
  // (`00000002-0000-0000-c000-000000000000`), the dedicated baseline
  // template `baseline-mfa-windowsazuread-baseline-scopes` no longer needs
  // to be treated as a 'recommended' high-severity gap - downgrade to
  // optional/medium so UI shows it as optional instead of recommended.
  try {
    const baselineTemplateId = "baseline-mfa-windowsazuread-baseline-scopes";
    const WINDOWS_AZURE_AD_RESOURCE = "00000002-0000-0000-c000-000000000000";
    const baselineScope = context?.conditionalAccessSettings?.advancedSettings?.baselineScopes?.resourceAppId;
    if (
      match.template.id === baselineTemplateId &&
      baselineScope &&
      String(baselineScope).toLowerCase() === WINDOWS_AZURE_AD_RESOURCE.toLowerCase()
    ) {
      // Treat as optional/medium
      return "medium";
    }
  } catch (e) {
    // ignore and fall back to default mapping
  }

  if (p === "critical") return "critical";
  if (p === "recommended") return "high";
  return "medium";
}

function shortDiff(differences: string[]): string[] {
  // Keep the first ~5 distinct differences for UI brevity
  const out: string[] = [];
  const seen = new Set<string>();
  for (const d of differences) {
    if (seen.has(d)) continue;
    seen.add(d);
    out.push(d);
    if (out.length >= 5) break;
  }
  return out;
}

// ─── Analyzer ────────────────────────────────────────────────────────────────

export function analyzeBaselineGaps(
  context: TenantContext,
  templateResult: TemplateAnalysisResult,
  /** When set, only templates in this category are included. When null/undefined,
   * lewis-barry templates are excluded and all other templates are included. */
  baselineCategory?: string | null
): BaselineGapResult {
  const entries: BaselineGapEntry[] = [];

  // 1) Baseline → tenant: missing & drift
  // Track which tenant policies are accounted for by at least one template
  const accountedFor = new Set<string>();

  for (const match of templateResult.matches) {
    if (match.status === "not-applicable") continue;
    // Filter to the selected baseline category. When no baseline is selected
    // (Jon Hope default) exclude lewis-barry; when lewis-barry is selected
    // show only lewis-barry templates.
    if (baselineCategory) {
      if (match.template.category !== baselineCategory) continue;
    } else {
      if (match.template.category === "lewis-barry") continue;
    }

    const tplPersona = detectPersona(match.template.displayName);

    if (match.status === "missing") {
      entries.push({
        kind: "missing",
        id: `missing:${match.template.id}`,
        label: match.template.displayName,
        persona: tplPersona,
        severity: severityForMatch(match, context),
        summary: match.template.summary,
        details: match.gaps.length
          ? shortDiff(match.gaps)
          : [`No tenant policy matches this baseline template.`],
        templateId: match.template.id,
      });
      continue;
    }

    if (match.status === "partial") {
      // Mark tenant policies as accounted for, but flag drift
      for (const mp of match.matchingPolicies) {
        accountedFor.add(mp.policy.id);
      }
      const topMatch = match.matchingPolicies[0];
      entries.push({
        kind: "drift",
        id: `drift:${match.template.id}`,
        label: match.template.displayName,
        persona: tplPersona,
        severity: severityForMatch(match, context),
        summary: `Tenant has a similar policy (${match.confidence}% match) but it differs from the baseline.`,
        details: shortDiff([
          ...(topMatch ? [`Closest tenant policy: "${topMatch.policy.displayName}"`] : []),
          ...match.differences,
          ...match.gaps,
        ]),
        templateId: match.template.id,
        policyIds: match.matchingPolicies.map((mp) => mp.policy.id),
      });
      continue;
    }

    if (match.status === "present") {
      for (const mp of match.matchingPolicies) {
        accountedFor.add(mp.policy.id);
      }
    }
  }

  // 2) Tenant → baseline: tenant-only
  for (const policy of context.policies) {
    if (accountedFor.has(policy.id)) continue;
    // Skip disabled policies - drift on something already off isn't actionable
    if (policy.state === "disabled") continue;

    const persona = detectPersona(policy.displayName);
    entries.push({
      kind: "tenant-only",
      id: `tenant:${policy.id}`,
      label: policy.displayName,
      persona,
      severity: "low",
      summary: `Tenant policy with no equivalent in the loaded baseline.`,
      details: [
        `State: ${policy.state}`,
        `This is either a custom policy, drift from the baseline, or a policy the baseline doesn't cover.`,
        `Review whether it should be added to your baseline or retired.`,
      ],
      policyIds: [policy.id],
    });
  }

  // 3) Bucket by persona
  const byPersona = new Map<Persona, BaselineGapEntry[]>();
  for (const e of entries) {
    const arr = byPersona.get(e.persona) ?? [];
    arr.push(e);
    byPersona.set(e.persona, arr);
  }

  const buckets: PersonaGapBucket[] = [];
  for (const persona of PERSONA_ORDER) {
    // We append unknown explicitly at the end so ordering is stable.
    if (persona === "unknown") continue;
    const list = byPersona.get(persona) ?? [];
    if (list.length === 0) continue;
    const meta = PERSONA_META[persona];
    buckets.push({
      persona,
      label: meta.label,
      shortLabel: meta.shortLabel,
      emoji: meta.emoji,
      entries: list,
      missingCount: list.filter((e) => e.kind === "missing").length,
      driftCount: list.filter((e) => e.kind === "drift").length,
      tenantOnlyCount: list.filter((e) => e.kind === "tenant-only").length,
    });
  }
  // Catch any "unknown" persona last
  const unknownList = byPersona.get("unknown") ?? [];
  if (unknownList.length > 0) {
    const meta = PERSONA_META.unknown;
    buckets.push({
      persona: "unknown",
      label: meta.label,
      shortLabel: meta.shortLabel,
      emoji: meta.emoji,
      entries: unknownList,
      missingCount: unknownList.filter((e) => e.kind === "missing").length,
      driftCount: unknownList.filter((e) => e.kind === "drift").length,
      tenantOnlyCount: unknownList.filter((e) => e.kind === "tenant-only").length,
    });
  }

  const missing = entries.filter((e) => e.kind === "missing").length;
  const drift = entries.filter((e) => e.kind === "drift").length;
  const tenantOnly = entries.filter((e) => e.kind === "tenant-only").length;

  // Coverage = (present + 0.5 × partial) / applicable_templates
  // Filter to the selected baseline category (same logic as the loop above).
  const applicable = templateResult.matches.filter((m) => {
    if (m.status === "not-applicable") return false;
    if (baselineCategory) return m.template.category === baselineCategory;
    return m.template.category !== "lewis-barry";
  });
  const present = applicable.filter((m) => m.status === "present").length;
  const partial = applicable.filter((m) => m.status === "partial").length;
  const coverageScore =
    applicable.length === 0
      ? 0
      : Math.round(((present + 0.5 * partial) / applicable.length) * 100);

  return {
    baselineTemplateCount: templateResult.totalTemplates,
    tenantPolicyCount: context.policies.length,
    entries,
    buckets,
    missing,
    drift,
    tenantOnly,
    coverageScore,
    generatedAt: new Date().toISOString(),
  };
}

/** Filter helper for the view layer. */
export function filterEntries(
  entries: BaselineGapEntry[],
  kinds: Set<GapKind>
): BaselineGapEntry[] {
  return entries.filter((e) => kinds.has(e.kind));
}

// Keep tree-shaking happy
export type { ConditionalAccessPolicy };
