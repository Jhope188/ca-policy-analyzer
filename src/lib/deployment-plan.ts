/**
 * Deployment Plan Generator (Phase 5)
 *
 * Turns the gaps surfaced by `analyzeBaselineGaps` into a Graph-ready
 * deployment bundle the operator can import via:
 *
 *   - Microsoft Graph PowerShell SDK (`New-MgIdentityConditionalAccessPolicy`)
 *   - DCToolbox / IntuneCD restore flows
 *   - Plain `Invoke-MgGraphRequest` with a JSON body
 *
 * Every exported policy is forced to **state: "disabled"** so nothing is
 * ever activated by accident - the operator must explicitly flip it to
 * `enabledForReportingButNotEnforced` (report-only) or `enabled` after
 * review.
 *
 * Two formats are produced:
 *
 *   1. **Bundle JSON** - a single `deployment-plan.json` with metadata,
 *      a per-persona summary, and an array of `policies[]` ready for
 *      iteration.
 *   2. **Per-policy JSON files** - one file per missing/drift policy,
 *      named `<persona>-<id>.json`, suitable for git-tracking.
 *
 * The current implementation produces the bundle; the per-policy split
 * is exposed as a helper for future ZIP packaging.
 */

import { BaselineGapResult, BaselineGapEntry } from "./baseline-gap";
import { TemplateAnalysisResult } from "./template-matcher";
import { PolicyTemplate, DeploymentPolicy } from "@/data/policy-templates";
import { Persona, PERSONA_META, PERSONA_ORDER } from "./personas";
import JSZip from "jszip";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface DeploymentPlanPolicy {
  /** Persona this policy targets */
  persona: Persona;
  /** Why this policy is in the plan */
  reason: "missing" | "drift";
  /** Severity inherited from the gap */
  severity: BaselineGapEntry["severity"];
  /** Stable id from the source template */
  templateId: string;
  /** Original template displayName */
  templateDisplayName: string;
  /** One-line summary */
  summary: string;
  /** Why it matters */
  rationale: string;
  /** Action notes - for drift, what differs */
  actionNotes: string[];
  /** The Graph-ready JSON body */
  body: DeploymentPolicy;
}

export interface DeploymentPlanSummary {
  persona: Persona;
  label: string;
  missing: number;
  drift: number;
  total: number;
}

export interface DeploymentPlan {
  /** Schema version (bump when shape changes) */
  schemaVersion: 1;
  /** Tool that generated the plan */
  generator: {
    name: string;
    version: string;
  };
  generatedAt: string;
  /** Metadata about the source baseline */
  baseline: {
    label: string;
    templateCount: number;
    coverageScore: number;
  };
  /** Per-persona summary, ordered like the UI */
  perPersona: DeploymentPlanSummary[];
  /** Top-level counts */
  totals: {
    missing: number;
    drift: number;
    total: number;
  };
  /** All policies the operator needs to deploy, in priority order */
  policies: DeploymentPlanPolicy[];
  /** README-style instructions baked into the plan */
  instructions: string[];
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

const SEVERITY_RANK: Record<BaselineGapEntry["severity"], number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

const PLAN_INSTRUCTIONS: string[] = [
  "Review each policy below before applying. Every policy is exported with state=\"disabled\" for safety.",
  "Recommended deploy order: critical -> high -> medium. Within a tier, apply Admins first, then Internals, then Externals.",
  "After import, flip state to \"enabledForReportingButNotEnforced\" (report-only) for at least 7 days before \"enabled\".",
  "PowerShell example: Get-Content deployment-plan.json | ConvertFrom-Json | ForEach-Object { $_.policies | ForEach-Object { New-MgIdentityConditionalAccessPolicy -BodyParameter $_.body } }",
  "DCToolbox: pipe each .body object through Invoke-DCConditionalAccessPolicyDeployment -PolicyJson.",
  "Drift entries (reason=\"drift\") replace existing tenant policies - back them up first via Export-MgIdentityConditionalAccessPolicy or DCToolbox export.",
];

function templateLookup(
  templateResult: TemplateAnalysisResult
): Map<string, PolicyTemplate> {
  const m = new Map<string, PolicyTemplate>();
  for (const match of templateResult.matches) {
    m.set(match.template.id, match.template);
  }
  return m;
}

// ─── Main builder ────────────────────────────────────────────────────────────

export function buildDeploymentPlan(
  gaps: BaselineGapResult,
  templateResult: TemplateAnalysisResult,
  baselineLabel: string,
  generatorVersion: string = "1.14.0"
): DeploymentPlan {
  const templates = templateLookup(templateResult);

  const policies: DeploymentPlanPolicy[] = [];
  for (const entry of gaps.entries) {
    if (entry.kind === "tenant-only") continue; // tenant-only isn't a deploy
    if (!entry.templateId) continue;
    const tpl = templates.get(entry.templateId);
    if (!tpl) continue;

    policies.push({
      persona: entry.persona,
      reason: entry.kind,
      severity: entry.severity,
      templateId: tpl.id,
      templateDisplayName: tpl.displayName,
      summary: tpl.summary,
      rationale: tpl.rationale,
      actionNotes:
        entry.kind === "drift"
          ? entry.details
          : [`Baseline policy "${tpl.displayName}" has no tenant equivalent.`],
      // Force state to disabled regardless of what the template said
      body: { ...tpl.deploymentJson, state: "disabled" },
    });
  }

  // Sort: critical first, then by persona, then by name
  policies.sort((a, b) => {
    const sev = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
    if (sev !== 0) return sev;
    if (a.persona !== b.persona) return a.persona.localeCompare(b.persona);
    return a.templateDisplayName.localeCompare(b.templateDisplayName);
  });

  // Per-persona summary
  const perPersonaMap = new Map<Persona, DeploymentPlanSummary>();
  for (const p of policies) {
    const cur =
      perPersonaMap.get(p.persona) ?? {
        persona: p.persona,
        label: PERSONA_META[p.persona].label,
        missing: 0,
        drift: 0,
        total: 0,
      };
    if (p.reason === "missing") cur.missing += 1;
    if (p.reason === "drift") cur.drift += 1;
    cur.total += 1;
    perPersonaMap.set(p.persona, cur);
  }

  return {
    schemaVersion: 1,
    generator: { name: "ca-policy-analyzer", version: generatorVersion },
    generatedAt: new Date().toISOString(),
    baseline: {
      label: baselineLabel,
      templateCount: gaps.baselineTemplateCount,
      coverageScore: gaps.coverageScore,
    },
    perPersona: Array.from(perPersonaMap.values()),
    totals: {
      missing: policies.filter((p) => p.reason === "missing").length,
      drift: policies.filter((p) => p.reason === "drift").length,
      total: policies.length,
    },
    policies,
    instructions: PLAN_INSTRUCTIONS,
  };
}

// ─── Helpers for the view layer ──────────────────────────────────────────────

/** Trigger a JSON file download in the browser. */
export function downloadDeploymentPlan(plan: DeploymentPlan, filename?: string) {
  const safeLabel = plan.baseline.label
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
  const stamp = plan.generatedAt.slice(0, 10);
  const fname = filename ?? `ca-deployment-plan-${safeLabel || "baseline"}-${stamp}.json`;
  const blob = new Blob([JSON.stringify(plan, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = fname;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** Returns one map { filename: jsonString } for ZIP export. */
export function deploymentPlanToFileMap(
  plan: DeploymentPlan
): Record<string, string> {
  const files: Record<string, string> = {
    "deployment-plan.json": JSON.stringify(plan, null, 2),
    "README.md": buildReadme(plan),
  };

  for (const p of plan.policies) {
    files[policyFilePath(p)] = JSON.stringify(p.body, null, 2);
  }

  return files;
}

/**
 * Build the human-readable README that ships in the bundle.
 *
 * Ordered by **Zero Trust criticality** - within each criticality tier,
 * the personas are listed in the same order Microsoft's Zero Trust
 * framework puts them (Global → Admins → Internals → Externals → Guest
 * Admins → Developers → CorpServiceAccounts → WorkloadIdentities).
 */
function buildReadme(plan: DeploymentPlan): string {
  const lines: string[] = [];

  lines.push("# Conditional Access Deployment Plan");
  lines.push("");
  lines.push(
    `Generated by **${plan.generator.name} v${plan.generator.version}** on ${plan.generatedAt}.`,
  );
  lines.push(
    `Baseline: **${plan.baseline.label}** - ${plan.baseline.templateCount} templates, current coverage **${plan.baseline.coverageScore}/100**.`,
  );
  lines.push("");

  lines.push("## ⚠️ Read this first");
  lines.push("");
  lines.push(
    "Every policy in this bundle is exported with `state = \"disabled\"` for safety. **Nothing will ever be enforced by accident.** After importing, you must explicitly:",
  );
  lines.push("");
  lines.push("1. Flip the policy to `enabledForReportingButNotEnforced` (report-only)");
  lines.push("2. Watch sign-in logs for **at least 7 days** to confirm no legitimate sign-ins are blocked");
  lines.push("3. Only then flip to `enabled`");
  lines.push("");
  lines.push("**Drift entries** (where the tenant already has a similar policy) will *create a new policy* - they will not edit the existing one. Decide whether to keep, archive, or delete the existing tenant policy after import.");
  lines.push("");

  // ── Totals ───────────────────────────────────────────────────────────────
  lines.push("## Totals");
  lines.push("");
  lines.push(`| Reason | Count |`);
  lines.push(`|---|---|`);
  lines.push(`| Missing (no tenant equivalent) | ${plan.totals.missing} |`);
  lines.push(`| Drift (tenant has it, but differs) | ${plan.totals.drift} |`);
  lines.push(`| **Total policies in this bundle** | **${plan.totals.total}** |`);
  lines.push("");

  // ── Recommended deployment order ─────────────────────────────────────────
  lines.push("## Recommended deployment order (by Zero Trust criticality)");
  lines.push("");
  lines.push(
    "Apply tiers top-to-bottom. **Critical** addresses the highest-impact Zero Trust principles (block legacy auth, MFA for admins, risk-based blocks). **Low** is hardening and edge cases. Within each tier, personas are listed in the order Microsoft's Zero Trust framework prioritises them.",
  );
  lines.push("");

  const tiers: Array<{ sev: BaselineGapEntry["severity"]; label: string; emoji: string; meaning: string }> = [
    { sev: "critical", label: "Critical", emoji: "🔴", meaning: "Required by every Zero Trust baseline. Blocks the most common attacks (legacy auth, admin compromise, token theft). Deploy first." },
    { sev: "high", label: "High", emoji: "🟠", meaning: "Strongly recommended. Closes major gaps (risk-based access, device compliance, session controls)." },
    { sev: "medium", label: "Medium", emoji: "🟡", meaning: "Hardening. Improves defence-in-depth (location restrictions, app-specific policies, persona scoping)." },
    { sev: "low", label: "Low", emoji: "🟢", meaning: "Edge cases and polish. Apply as time permits." },
  ];

  for (const tier of tiers) {
    const tierPolicies = plan.policies.filter((p) => p.severity === tier.sev);
    if (tierPolicies.length === 0) continue;

    lines.push(`### ${tier.emoji} ${tier.label} (${tierPolicies.length})`);
    lines.push("");
    lines.push(`> ${tier.meaning}`);
    lines.push("");

    // Within the tier, group by persona - preserve PERSONA_META ordering
    const personaOrder: Persona[] = PERSONA_ORDER;

    let counter = 1;
    for (const persona of personaOrder) {
      const personaPolicies = tierPolicies.filter((p) => p.persona === persona);
      if (personaPolicies.length === 0) continue;

      const meta = PERSONA_META[persona];
      lines.push(`#### ${meta.emoji} ${meta.label}`);
      lines.push("");

      for (const p of personaPolicies) {
        const file = policyFilePath(p);
        lines.push(`**${counter}. ${p.templateDisplayName}** - \`${p.reason}\``);
        lines.push("");
        lines.push(`- 📄 File: [\`${file}\`](./${file})`);
        lines.push(`- 📌 Summary: ${p.summary}`);
        if (p.rationale) {
          lines.push(`- 🎯 Why: ${p.rationale}`);
        }
        if (p.actionNotes.length > 0) {
          lines.push(`- 📝 Notes:`);
          for (const note of p.actionNotes) {
            lines.push(`  - ${note}`);
          }
        }
        lines.push("");
        counter += 1;
      }
    }
  }

  // ── Auto-import recipes ──────────────────────────────────────────────────
  lines.push("## Auto-import recipes");
  lines.push("");
  lines.push("All policy files are valid Microsoft Graph `ConditionalAccessPolicy` request bodies. Pick whichever import flow your organisation already uses.");
  lines.push("");

  lines.push("### Microsoft Graph PowerShell SDK");
  lines.push("");
  lines.push("```powershell");
  lines.push("# Connect with the right scopes");
  lines.push("Connect-MgGraph -Scopes 'Policy.ReadWrite.ConditionalAccess','Policy.Read.All'");
  lines.push("");
  lines.push("# Import every JSON in the bundle, in deployment-plan.json order");
  lines.push("$plan = Get-Content ./deployment-plan.json | ConvertFrom-Json");
  lines.push("foreach ($p in $plan.policies) {");
  lines.push("    Write-Host \"[$($p.severity)] $($p.templateDisplayName) → $($p.persona)\"");
  lines.push("    New-MgIdentityConditionalAccessPolicy -BodyParameter $p.body");
  lines.push("}");
  lines.push("```");
  lines.push("");

  lines.push("### DCToolbox");
  lines.push("");
  lines.push("```powershell");
  lines.push("Import-Module DCToolbox");
  lines.push("Connect-DCMsGraphAsUser -Scopes 'Policy.ReadWrite.ConditionalAccess'");
  lines.push("");
  lines.push("Get-ChildItem -Path ./policies -Recurse -Filter *.json | ForEach-Object {");
  lines.push("    $body = Get-Content $_.FullName -Raw");
  lines.push("    Invoke-DCConditionalAccessPolicyDeployment -PolicyJson $body");
  lines.push("}");
  lines.push("```");
  lines.push("");

  lines.push("### Plain Invoke-MgGraphRequest");
  lines.push("");
  lines.push("```powershell");
  lines.push("Get-ChildItem -Path ./policies -Recurse -Filter *.json | ForEach-Object {");
  lines.push("    $body = Get-Content $_.FullName -Raw");
  lines.push("    Invoke-MgGraphRequest -Method POST `");
  lines.push("        -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' `");
  lines.push("        -Body $body -ContentType 'application/json'");
  lines.push("}");
  lines.push("```");
  lines.push("");

  lines.push("### Bash + curl + jq");
  lines.push("");
  lines.push("```bash");
  lines.push("TOKEN=\"<your-graph-access-token>\"");
  lines.push("find ./policies -name '*.json' | while read f; do");
  lines.push("  echo \"Importing $f\"");
  lines.push("  curl -sS -X POST \\");
  lines.push("    -H \"Authorization: Bearer $TOKEN\" \\");
  lines.push("    -H \"Content-Type: application/json\" \\");
  lines.push("    --data @\"$f\" \\");
  lines.push("    https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies");
  lines.push("done");
  lines.push("```");
  lines.push("");

  lines.push("## Bundle layout");
  lines.push("");
  lines.push("```");
  lines.push("ca-deployment-plan/");
  lines.push("├── README.md                    ← this file");
  lines.push("├── deployment-plan.json         ← machine-readable manifest");
  lines.push("└── policies/");
  lines.push("    ├── <persona>/<template>.json  ← one file per policy");
  lines.push("    └── ...");
  lines.push("```");
  lines.push("");
  lines.push(
    "Files are grouped by persona on disk so you can selectively deploy a single persona by importing only that subdirectory.",
  );
  lines.push("");

  return lines.join("\n");
}

/** Stable on-disk path for one policy. */
function policyFilePath(p: DeploymentPlanPolicy): string {
  const safeId = p.templateId.replace(/[^a-z0-9-]/gi, "-").toLowerCase();
  return `policies/${p.persona}/${safeId}.json`;
}

/**
 * Build a ZIP bundle containing the README, the manifest, and every
 * per-policy JSON, then trigger a browser download.
 */
export async function downloadDeploymentBundle(
  plan: DeploymentPlan,
  filename?: string,
): Promise<void> {
  const safeLabel = plan.baseline.label
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
  const stamp = plan.generatedAt.slice(0, 10);
  const fname =
    filename ?? `ca-deployment-plan-${safeLabel || "baseline"}-${stamp}.zip`;

  const zip = new JSZip();
  const files = deploymentPlanToFileMap(plan);
  for (const [path, content] of Object.entries(files)) {
    zip.file(path, content);
  }

  const blob = await zip.generateAsync({
    type: "blob",
    compression: "DEFLATE",
    compressionOptions: { level: 6 },
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = fname;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
