/**
 * Excel + PowerPoint export utilities for CA Policy Analyzer
 *
 * Exports all policies with their visualization data, findings,
 * and a summary sheet into .xlsx or .pptx format.
 */

import * as XLSX from "xlsx";
import PptxGenJS from "pptxgenjs";
import {
  AnalysisResult,
  PolicyResult,
  CompositeScoreResult,
} from "./analyzer";
import { CISAlignmentResult } from "@/data/cis-benchmarks";
import { resolveRoleList, resolveGuidList, resolveAppList, type GuidResolverMaps } from "@/lib/role-names";
import type { PersonaCoverageResult, PersonaCoverageRow } from "./persona-coverage";
import type { ZeroTrustScorecard } from "./zero-trust-scorecard";
import type { BaselineGapResult, PersonaGapBucket } from "./baseline-gap";
import { PERSONA_META } from "./personas";

// ─── Export Options ──────────────────────────────────────────────────────────

export interface ExportOptions {
  /** When true, filter out Microsoft-managed policies from policy slides/rows */
  hideMicrosoftPolicies?: boolean;
  /** Base64-encoded logo image (data URI or raw base64) for the PPTX cover slide */
  logoBase64?: string | null;
  /** Tenant display name (company / org name) */
  tenantDisplayName?: string;
  /** Entra ID tenant ID */
  tenantId?: string;
  /** Dynamic lookup maps for resolving GUIDs to display names */
  resolverMaps?: GuidResolverMaps;
}

/** Detect Microsoft-managed / built-in policies */
function isMicrosoftManaged(pr: PolicyResult): boolean {
  const p = pr.policy;
  if (p.templateId && p.templateId !== "00000000-0000-0000-0000-000000000000") return true;
  const name = p.displayName.toLowerCase();
  return name.startsWith("microsoft-managed") || name.startsWith("[microsoft");
}

/** Load the default logo from public/logo.png as a base64 data URI */
export async function loadDefaultLogo(): Promise<string | null> {
  try {
    // Try multiple paths to handle both local dev and GitHub Pages deployment.
    // logo.png in public/ is the Conditionalaccess.tech brand logo.
    const base = `${window.location.origin}/ca-policy-analyzer`;
    const candidates = [
      `${window.location.origin}${window.location.pathname.replace(/\/[^/]*$/, "")}/logo.png`,
      `${base}/logo.png`,
      `${window.location.origin}/logo.png`,
      `${base}/docs/screenshots/Conditionalaccess.tech.png`,
    ];

    for (const url of candidates) {
      try {
        const resp = await fetch(url);
        if (!resp.ok) continue;
        const contentType = resp.headers.get("content-type") ?? "";
        if (!contentType.startsWith("image/")) continue;
        const blob = await resp.blob();
        return new Promise((resolve) => {
          const reader = new FileReader();
          reader.onloadend = () => resolve(reader.result as string);
          reader.onerror = () => resolve(null);
          reader.readAsDataURL(blob);
        });
      } catch {
        continue;
      }
    }
    return null;
  } catch {
    return null;
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function stateLabel(state: string): string {
  switch (state) {
    case "enabled":
      return "Enabled";
    case "enabledForReportingButNotEnforced":
      return "Report-only";
    case "disabled":
      return "Disabled";
    default:
      return state;
  }
}

function joinOrNone(arr: string[] | undefined): string {
  return arr && arr.length > 0 ? arr.join(", ") : "-";
}

function datestamp(): string {
  return new Date().toISOString().slice(0, 10);
}

// ─── Excel Export ────────────────────────────────────────────────────────────

export function exportToExcel(
  analysis: AnalysisResult,
  cisResult?: CISAlignmentResult | null,
  compositeScore?: CompositeScoreResult | null,
  options?: ExportOptions,
) {
  const wb = XLSX.utils.book_new();

  // Filter policies if Microsoft-managed are hidden
  const policyResults = options?.hideMicrosoftPolicies
    ? analysis.policyResults.filter((r) => !isMicrosoftManaged(r))
    : analysis.policyResults;

  // ── Sheet 1: Summary ────────────────────────────────────────────────
  const s = analysis.tenantSummary;
  const summaryData = [
    ["CA Policy Analyzer - Export", ""],
    ["Tenant", options?.tenantDisplayName ?? "-"],
    ["Tenant ID", options?.tenantId ?? "-"],
    ["Generated", new Date().toLocaleString()],
    [""],
    ["Policy Summary", ""],
    ["Total Policies", s.totalPolicies],
    ["Enabled", s.enabledPolicies],
    ["Report-only", s.reportOnlyPolicies],
    ["Disabled", s.disabledPolicies],
    [""],
    ["Findings Summary", ""],
    ["Critical", s.criticalFindings],
    ["High", s.highFindings],
    ["Medium", s.mediumFindings],
    ["Low", s.lowFindings],
    ["Info", s.infoFindings],
    ["Total Findings", s.totalFindings],
  ];

  if (compositeScore) {
    summaryData.push(
      [""],
      ["Security Posture Score", ""],
      ["Overall Score", compositeScore.overall],
      ["Grade", compositeScore.grade],
      ["CIS Alignment", `${compositeScore.cisScore} / ${compositeScore.cisMax}`],
      ["Template Coverage", `${compositeScore.templateScore} / ${compositeScore.templateMax}`],
      ["Config Quality", `${compositeScore.configScore} / ${compositeScore.configMax}`],
    );
  }

  const wsSummary = XLSX.utils.aoa_to_sheet(summaryData);
  wsSummary["!cols"] = [{ wch: 25 }, { wch: 30 }];
  XLSX.utils.book_append_sheet(wb, wsSummary, "Summary");

  // ── Sheet 2: All Policies ───────────────────────────────────────────
  const maps = options?.resolverMaps;
  const policyRows = policyResults.map((r) => ({
    "Policy Name": r.policy.displayName,
    State: stateLabel(r.policy.state),
    "Target Users": r.visualization.targetUsers,
    "Target Apps": r.visualization.targetApps,
    Conditions: joinOrNone(r.visualization.conditions),
    "Grant Controls": joinOrNone(r.visualization.grantControls),
    "Session Controls": joinOrNone(r.visualization.sessionControls),
    "Include Users": resolveGuidList(r.policy.conditions.users.includeUsers, maps),
    "Exclude Users": resolveGuidList(r.policy.conditions.users.excludeUsers, maps),
    "Include Groups": resolveGuidList(r.policy.conditions.users.includeGroups, maps),
    "Exclude Groups": resolveGuidList(r.policy.conditions.users.excludeGroups, maps),
    "Include Roles": resolveRoleList(r.policy.conditions.users.includeRoles, maps),
    "Exclude Roles": resolveRoleList(r.policy.conditions.users.excludeRoles, maps),
    "Include Apps": resolveAppList(r.policy.conditions.applications.includeApplications, maps),
    "Exclude Apps": resolveAppList(r.policy.conditions.applications.excludeApplications, maps),
    "Client App Types": joinOrNone(r.policy.conditions.clientAppTypes),
    Platforms: joinOrNone(r.policy.conditions.platforms?.includePlatforms),
    "User Risk Levels": joinOrNone(r.policy.conditions.userRiskLevels),
    "Sign-in Risk Levels": joinOrNone(r.policy.conditions.signInRiskLevels),
    Findings: r.findings.length,
    "Policy ID": r.policy.id,
    Created: r.policy.createdDateTime?.slice(0, 10) ?? "",
    Modified: r.policy.modifiedDateTime?.slice(0, 10) ?? "",
  }));

  const wsPolicies = XLSX.utils.json_to_sheet(policyRows);
  wsPolicies["!cols"] = [
    { wch: 50 }, { wch: 12 }, { wch: 25 }, { wch: 25 },
    { wch: 30 }, { wch: 30 }, { wch: 30 },
  ];
  XLSX.utils.book_append_sheet(wb, wsPolicies, "Policies");

  // ── Sheet 3: All Findings ───────────────────────────────────────────
  const findingRows = analysis.findings.map((f) => ({
    ID: f.id,
    Severity: f.severity.toUpperCase(),
    Category: f.category,
    "Policy Name": f.policyName,
    Title: f.title,
    Description: f.description,
    Recommendation: f.recommendation,
  }));

  const wsFindings = XLSX.utils.json_to_sheet(findingRows);
  wsFindings["!cols"] = [
    { wch: 8 }, { wch: 10 }, { wch: 25 }, { wch: 50 },
    { wch: 60 }, { wch: 80 }, { wch: 60 },
  ];
  XLSX.utils.book_append_sheet(wb, wsFindings, "Findings");

  // ── Sheet 4: CIS Alignment ─────────────────────────────────────────
  if (cisResult) {
    const cisRows = cisResult.controls.map((cr) => ({
      "Control ID": cr.control.id,
      Title: cr.control.title,
      Level: cr.control.level,
      Status: cr.result.status.toUpperCase(),
      Detail: cr.result.detail,
      "Matching Policies": joinOrNone(cr.result.matchingPolicies),
      Remediation: cr.result.remediation ?? "",
    }));

    const wsCIS = XLSX.utils.json_to_sheet(cisRows);
    wsCIS["!cols"] = [
      { wch: 10 }, { wch: 60 }, { wch: 6 }, { wch: 10 },
      { wch: 60 }, { wch: 40 }, { wch: 60 },
    ];
    XLSX.utils.book_append_sheet(wb, wsCIS, "CIS Alignment");
  }

  // ── Download ────────────────────────────────────────────────────────
  const buf = XLSX.write(wb, { type: "array", bookType: "xlsx" });
  downloadBlob(
    new Blob([buf], { type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" }),
    `ca-analysis-${datestamp()}.xlsx`,
  );
}

// ─── PowerPoint Export ───────────────────────────────────────────────────────

const COLORS = {
  bg: "0F172A",
  card: "1E293B",
  text: "F1F5F9",
  muted: "94A3B8",
  accent: "3B82F6",
  green: "22C55E",
  yellow: "EAB308",
  red: "EF4444",
  orange: "F97316",
  purple: "A855F7",
  white: "FFFFFF",
};

function severityColor(sev: string): string {
  switch (sev) {
    case "critical":
      return COLORS.red;
    case "high":
      return COLORS.orange;
    case "medium":
      return COLORS.yellow;
    case "low":
      return COLORS.muted;
    default:
      return COLORS.muted;
  }
}

function stateColor(state: string): string {
  switch (state) {
    case "enabled":
      return COLORS.green;
    case "enabledForReportingButNotEnforced":
      return COLORS.yellow;
    default:
      return COLORS.muted;
  }
}

export async function exportToPowerPoint(
  analysis: AnalysisResult,
  cisResult?: CISAlignmentResult | null,
  compositeScore?: CompositeScoreResult | null,
  options?: ExportOptions & {
    personaResult?: PersonaCoverageResult | null;
    scorecard?: ZeroTrustScorecard | null;
    baselineGap?: BaselineGapResult | null;
  },
) {
  const pptx = new PptxGenJS();

  // Filter policies if Microsoft-managed are hidden
  const policyResults = options?.hideMicrosoftPolicies
    ? analysis.policyResults.filter((r) => !isMicrosoftManaged(r))
    : analysis.policyResults;
  pptx.layout = "LAYOUT_WIDE";
  pptx.author = "CA Policy Analyzer";
  pptx.title = "Conditional Access Policy Analysis";

  // ── Slide 1: Title ──────────────────────────────────────────────────
  const titleSlide = pptx.addSlide();
  titleSlide.background = { color: COLORS.bg };

  // Logo - top-right corner. Logo is 1024×1024 (square) so keep 1:1 aspect ratio.
  // Slide width = 10" (pptxgenjs default). Logo at 1.8" square, 0.3" from right/top edge.
  const logoData = options?.logoBase64;
  const LOGO_SIZE = 1.8; // inches - square
  if (logoData) {
    titleSlide.addImage({
      data: logoData,
      x: 7.9,  // 10 - 1.8 - 0.3 = right-aligned with margin
      y: 0.3,
      w: LOGO_SIZE,
      h: LOGO_SIZE,
    });
  }

  titleSlide.addText("Conditional Access\nPolicy Analysis", {
    x: 0.8,
    y: 1.5,
    w: logoData ? 6.8 : 11,
    h: 2.5,
    fontSize: 36,
    fontFace: "Arial",
    color: COLORS.white,
    bold: true,
    lineSpacingMultiple: 1.2,
  });

  // Tenant identity
  const tenantLine = options?.tenantDisplayName
    ? `${options.tenantDisplayName}${options.tenantId ? `  •  ${options.tenantId}` : ""}`
    : options?.tenantId ?? "";
  if (tenantLine) {
    titleSlide.addText(tenantLine, {
      x: 0.8,
      y: 3.8,
      w: 11,
      h: 0.4,
      fontSize: 14,
      fontFace: "Arial",
      color: COLORS.accent,
      bold: true,
    });
  }

  titleSlide.addText(`Generated ${new Date().toLocaleDateString()}`, {
    x: 0.8,
    y: 4.2,
    w: 11,
    h: 0.5,
    fontSize: 14,
    fontFace: "Arial",
    color: COLORS.muted,
  });

  // Show policy count and filter indicator
  const totalCount = analysis.policyResults.length;
  const exportedCount = policyResults.length;
  const filterNote =
    options?.hideMicrosoftPolicies && exportedCount < totalCount
      ? `${exportedCount} policies exported (${totalCount - exportedCount} Microsoft-managed hidden)`
      : `${exportedCount} policies`;
  titleSlide.addText(filterNote, {
    x: 0.8,
    y: 4.7,
    w: 11,
    h: 0.4,
    fontSize: 11,
    fontFace: "Arial",
    color: COLORS.muted,
  });
  if (!logoData) {
    // Placeholder hint when no logo is provided
    titleSlide.addShape("rect" as PptxGenJS.ShapeType, {
      x: 8.1,
      y: 0.3,
      w: 1.8,
      h: 1.8,
      fill: { color: COLORS.card },
      rectRadius: 0.1,
      line: { color: COLORS.muted, dashType: "dash", width: 1 },
    });
    titleSlide.addText("Your Logo Here", {
      x: 8.1,
      y: 0.95,
      w: 1.8,
      h: 0.5,
      fontSize: 11,
      fontFace: "Arial",
      color: COLORS.muted,
      align: "center",
    });
  }

  // ── Slide 2: Executive Summary ──────────────────────────────────────
  const summarySlide = pptx.addSlide();
  summarySlide.background = { color: COLORS.bg };
  summarySlide.addText("Executive Summary", {
    x: 0.5,
    y: 0.3,
    w: 12,
    h: 0.6,
    fontSize: 24,
    fontFace: "Arial",
    color: COLORS.white,
    bold: true,
  });

  const s = analysis.tenantSummary;

  // Score + grade
  if (compositeScore) {
    const scoreColor =
      compositeScore.overall >= 80
        ? COLORS.green
        : compositeScore.overall >= 60
          ? COLORS.yellow
          : compositeScore.overall >= 40
            ? COLORS.orange
            : COLORS.red;

    summarySlide.addText(String(compositeScore.overall), {
      x: 0.8,
      y: 1.2,
      w: 2.5,
      h: 1.8,
      fontSize: 64,
      fontFace: "Arial",
      color: scoreColor,
      bold: true,
      align: "center",
    });
    summarySlide.addText(`Grade: ${compositeScore.grade}\nSecurity Posture Score`, {
      x: 0.8,
      y: 3.0,
      w: 2.5,
      h: 0.8,
      fontSize: 11,
      fontFace: "Arial",
      color: COLORS.muted,
      align: "center",
      lineSpacingMultiple: 1.4,
    });

    // Pillar breakdown
    const pillars = [
      { label: "CIS Alignment", score: compositeScore.cisScore, max: compositeScore.cisMax, color: COLORS.accent },
      { label: "Template Coverage", score: compositeScore.templateScore, max: compositeScore.templateMax, color: COLORS.purple },
      { label: "Config Quality", score: compositeScore.configScore, max: compositeScore.configMax, color: COLORS.green },
    ];
    pillars.forEach((p, i) => {
      const y = 1.3 + i * 0.7;
      summarySlide.addText(`${p.label}:  ${p.score} / ${p.max}`, {
        x: 3.8,
        y,
        w: 4,
        h: 0.45,
        fontSize: 13,
        fontFace: "Arial",
        color: p.color,
      });
    });
  }

  // Policy counts
  const statsX = 8.5;
  const statsData = [
    { label: "Total Policies", value: s.totalPolicies, color: COLORS.white },
    { label: "Enabled", value: s.enabledPolicies, color: COLORS.green },
    { label: "Report-only", value: s.reportOnlyPolicies, color: COLORS.yellow },
    { label: "Disabled", value: s.disabledPolicies, color: COLORS.muted },
  ];
  statsData.forEach((st, i) => {
    const y = 1.3 + i * 0.65;
    summarySlide.addText(String(st.value), {
      x: statsX,
      y,
      w: 1.2,
      h: 0.5,
      fontSize: 28,
      fontFace: "Arial",
      color: st.color,
      bold: true,
      align: "right",
    });
    summarySlide.addText(st.label, {
      x: statsX + 1.3,
      y: y + 0.05,
      w: 3,
      h: 0.45,
      fontSize: 13,
      fontFace: "Arial",
      color: COLORS.muted,
    });
  });

  // Findings row
  const findingStats = [
    { label: "Critical", value: s.criticalFindings, color: COLORS.red },
    { label: "High", value: s.highFindings, color: COLORS.orange },
    { label: "Medium", value: s.mediumFindings, color: COLORS.yellow },
    { label: "Low", value: s.lowFindings, color: COLORS.muted },
    { label: "Info", value: s.infoFindings, color: COLORS.muted },
  ];

  summarySlide.addText("Findings Breakdown", {
    x: 0.5,
    y: 4.2,
    w: 12,
    h: 0.4,
    fontSize: 14,
    fontFace: "Arial",
    color: COLORS.white,
    bold: true,
  });

  findingStats.forEach((fs, i) => {
    const x = 0.8 + i * 2.3;
    summarySlide.addText(String(fs.value), {
      x,
      y: 4.8,
      w: 1.5,
      h: 0.6,
      fontSize: 32,
      fontFace: "Arial",
      color: fs.color,
      bold: true,
      align: "center",
    });
    summarySlide.addText(fs.label, {
      x,
      y: 5.4,
      w: 1.5,
      h: 0.3,
      fontSize: 11,
      fontFace: "Arial",
      color: COLORS.muted,
      align: "center",
    });
  });

  // ── Slide 3+: Policy Detail Slides (one per policy) ────────────────
  for (const pr of policyResults) {
    addPolicySlide(pptx, pr, options?.resolverMaps);
  }

  // ── Zero Trust Scorecard ───────────────────────────────────────────
  if (options?.scorecard) {
    addScorecardSlide(pptx, options.scorecard);
  }

  // ── Persona × Control Coverage ─────────────────────────────────────
  if (options?.personaResult) {
    addPersonaCoverageSlide(pptx, options.personaResult);
    // Per-persona detail slides - one slide per persona with assigned policies
    addPerPersonaSlides(pptx, options.personaResult, options?.baselineGap ?? undefined);
  }

  // ── Baseline Gap Summary ───────────────────────────────────────────
  if (options?.baselineGap) {
    addBaselineGapSlide(pptx, options.baselineGap);
  }

  // ── Slide N: CIS Alignment ──────────────────────────────────────────
  if (cisResult) {
    addCISSlide(pptx, cisResult);
  }

  // ── Download ────────────────────────────────────────────────────────
  await pptx.writeFile({ fileName: `ca-analysis-${datestamp()}.pptx` });
}

function addPolicySlide(pptx: PptxGenJS, pr: PolicyResult, maps?: GuidResolverMaps) {
  const slide = pptx.addSlide();
  slide.background = { color: COLORS.bg };

  const viz = pr.visualization;
  const policy = pr.policy;

  // Title bar
  slide.addShape("rect" as PptxGenJS.ShapeType, {
    x: 0,
    y: 0,
    w: "100%",
    h: 0.9,
    fill: { color: COLORS.card },
  });
  slide.addText(policy.displayName, {
    x: 0.5,
    y: 0.15,
    w: 10,
    h: 0.35,
    fontSize: 16,
    fontFace: "Arial",
    color: COLORS.white,
    bold: true,
  });
  slide.addText(stateLabel(policy.state), {
    x: 0.5,
    y: 0.5,
    w: 3,
    h: 0.3,
    fontSize: 11,
    fontFace: "Arial",
    color: stateColor(policy.state),
  });
  slide.addText(`ID: ${policy.id}`, {
    x: 5,
    y: 0.5,
    w: 7.5,
    h: 0.3,
    fontSize: 9,
    fontFace: "Arial",
    color: COLORS.muted,
    align: "right",
  });

  // Flow boxes: Users → Apps → Conditions → Grant → Session
  const flowBoxes = [
    { title: "Users", value: viz.targetUsers },
    { title: "Apps", value: viz.targetApps },
    { title: "Conditions", value: joinOrNone(viz.conditions) },
    { title: "Grant Controls", value: joinOrNone(viz.grantControls) },
    { title: "Session", value: joinOrNone(viz.sessionControls) },
  ];

  const boxW = 2.2;
  const gap = 0.15;
  const startX = 0.5;

  flowBoxes.forEach((box, i) => {
    const x = startX + i * (boxW + gap);
    slide.addShape("rect" as PptxGenJS.ShapeType, {
      x,
      y: 1.3,
      w: boxW,
      h: 1.6,
      fill: { color: COLORS.card },
      rectRadius: 0.1,
    });
    slide.addText(box.title, {
      x: x + 0.15,
      y: 1.4,
      w: boxW - 0.3,
      h: 0.3,
      fontSize: 10,
      fontFace: "Arial",
      color: COLORS.accent,
      bold: true,
    });
    slide.addText(box.value, {
      x: x + 0.15,
      y: 1.75,
      w: boxW - 0.3,
      h: 1.0,
      fontSize: 9,
      fontFace: "Arial",
      color: COLORS.text,
      valign: "top",
      wrap: true,
    });

    // Arrow between boxes
    if (i < flowBoxes.length - 1) {
      slide.addText("→", {
        x: x + boxW,
        y: 1.8,
        w: gap,
        h: 0.5,
        fontSize: 16,
        fontFace: "Arial",
        color: COLORS.muted,
        align: "center",
      });
    }
  });

  // Detailed conditions table
  const details = [
    ["Include Users", resolveGuidList(policy.conditions.users.includeUsers, maps)],
    ["Exclude Users", resolveGuidList(policy.conditions.users.excludeUsers, maps)],
    ["Include Groups", resolveGuidList(policy.conditions.users.includeGroups, maps)],
    ["Exclude Groups", resolveGuidList(policy.conditions.users.excludeGroups, maps)],
    ["Include Roles", resolveRoleList(policy.conditions.users.includeRoles, maps)],
    ["Exclude Roles", resolveRoleList(policy.conditions.users.excludeRoles, maps)],
    ["Include Apps", resolveAppList(policy.conditions.applications.includeApplications, maps)],
    ["Exclude Apps", resolveAppList(policy.conditions.applications.excludeApplications, maps)],
    ["Client App Types", joinOrNone(policy.conditions.clientAppTypes)],
    ["Platforms", joinOrNone(policy.conditions.platforms?.includePlatforms)],
    ["User Risk", joinOrNone(policy.conditions.userRiskLevels)],
    ["Sign-in Risk", joinOrNone(policy.conditions.signInRiskLevels)],
  ].filter((row) => row[1] !== "-");

  if (details.length > 0) {
    slide.addText("Condition Details", {
      x: 0.5,
      y: 3.2,
      w: 12,
      h: 0.35,
      fontSize: 12,
      fontFace: "Arial",
      color: COLORS.white,
      bold: true,
    });

    const tableRows: PptxGenJS.TableRow[] = details.map(([label, value]) => [
      {
        text: label,
        options: {
          fontSize: 9,
          fontFace: "Arial",
          color: COLORS.muted,
          fill: { color: COLORS.card },
          border: { type: "solid" as const, pt: 0.5, color: COLORS.bg },
          valign: "middle" as const,
        },
      },
      {
        text: value,
        options: {
          fontSize: 9,
          fontFace: "Arial",
          color: COLORS.text,
          fill: { color: COLORS.card },
          border: { type: "solid" as const, pt: 0.5, color: COLORS.bg },
          valign: "middle" as const,
        },
      },
    ]);

    slide.addTable(tableRows, {
      x: 0.5,
      y: 3.6,
      w: 11.5,
      colW: [2.5, 9],
      rowH: 0.3,
    });
  }

  // Findings for this policy
  if (pr.findings.length > 0) {
    const findingsY = details.length > 0 ? 3.6 + details.length * 0.3 + 0.2 : 3.2;
    if (findingsY < 6.5) {
      slide.addText(`Findings (${pr.findings.length})`, {
        x: 0.5,
        y: findingsY,
        w: 12,
        h: 0.35,
        fontSize: 12,
        fontFace: "Arial",
        color: COLORS.white,
        bold: true,
      });

      pr.findings.slice(0, 5).forEach((f, i) => {
        const fy = findingsY + 0.4 + i * 0.35;
        if (fy < 7) {
          slide.addText(`[${f.severity.toUpperCase()}]  ${f.title}`, {
            x: 0.5,
            y: fy,
            w: 11.5,
            h: 0.3,
            fontSize: 9,
            fontFace: "Arial",
            color: severityColor(f.severity),
          });
        }
      });
    }
  }
}

function addCISSlide(pptx: PptxGenJS, cisResult: CISAlignmentResult) {
  const slide = pptx.addSlide();
  slide.background = { color: COLORS.bg };

  slide.addText(`CIS v${cisResult.benchmarkVersion} Alignment`, {
    x: 0.5,
    y: 0.3,
    w: 12,
    h: 0.6,
    fontSize: 24,
    fontFace: "Arial",
    color: COLORS.white,
    bold: true,
  });

  // Summary stats
  const cisStats = [
    { label: "Pass", value: cisResult.passCount, color: COLORS.green },
    { label: "Fail", value: cisResult.failCount, color: COLORS.red },
    { label: "Manual", value: cisResult.manualCount, color: COLORS.yellow },
    ...(cisResult.notApplicableCount > 0
      ? [{ label: "N/A", value: cisResult.notApplicableCount, color: COLORS.muted }]
      : []),
    { label: "Score", value: `${cisResult.alignmentScore}%`, color: COLORS.accent },
  ];

  cisStats.forEach((cs, i) => {
    const x = 0.8 + i * 2.8;
    slide.addText(String(cs.value), {
      x,
      y: 1.1,
      w: 1.5,
      h: 0.6,
      fontSize: 32,
      fontFace: "Arial",
      color: cs.color,
      bold: true,
      align: "center",
    });
    slide.addText(cs.label, {
      x,
      y: 1.7,
      w: 1.5,
      h: 0.3,
      fontSize: 11,
      fontFace: "Arial",
      color: COLORS.muted,
      align: "center",
    });
  });

  // Controls table
  const statusColor = (st: string) =>
    st === "pass" ? COLORS.green : st === "fail" ? COLORS.red : COLORS.yellow;

  const rows: PptxGenJS.TableRow[] = cisResult.controls.map((cr) => [
    {
      text: cr.control.id,
      options: {
        fontSize: 8,
        fontFace: "Arial",
        color: COLORS.muted,
        fill: { color: COLORS.card },
        border: { type: "solid" as const, pt: 0.5, color: COLORS.bg },
        valign: "middle" as const,
      },
    },
    {
      text: cr.control.title,
      options: {
        fontSize: 8,
        fontFace: "Arial",
        color: COLORS.text,
        fill: { color: COLORS.card },
        border: { type: "solid" as const, pt: 0.5, color: COLORS.bg },
        valign: "middle" as const,
      },
    },
    {
      text: cr.control.level,
      options: {
        fontSize: 8,
        fontFace: "Arial",
        color: COLORS.muted,
        fill: { color: COLORS.card },
        border: { type: "solid" as const, pt: 0.5, color: COLORS.bg },
        align: "center" as const,
        valign: "middle" as const,
      },
    },
    {
      text: cr.result.status.toUpperCase(),
      options: {
        fontSize: 8,
        fontFace: "Arial",
        color: statusColor(cr.result.status),
        fill: { color: COLORS.card },
        border: { type: "solid" as const, pt: 0.5, color: COLORS.bg },
        align: "center" as const,
        bold: true,
        valign: "middle" as const,
      },
    },
  ]);

  slide.addTable(rows, {
    x: 0.5,
    y: 2.3,
    w: 12,
    colW: [0.8, 7.5, 0.6, 0.8],
    rowH: 0.28,
  });
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// ─── Phase 6: Persona / Scorecard / Baseline-gap PowerPoint slides ──────────

function pillarColor(score: number): string {
  if (score >= 80) return COLORS.green;
  if (score >= 50) return COLORS.yellow;
  return COLORS.red;
}

function addScorecardSlide(pptx: PptxGenJS, sc: ZeroTrustScorecard) {
  const slide = pptx.addSlide();
  slide.background = { color: COLORS.bg };

  slide.addText("Zero Trust Scorecard", {
    x: 0.5, y: 0.3, w: 12, h: 0.6,
    fontSize: 24, fontFace: "Arial", color: COLORS.white, bold: true,
  });
  slide.addText(`Overall: ${sc.overall}/100  •  Verify Explicitly · Use Least Privilege · Assume Breach`, {
    x: 0.5, y: 0.95, w: 12, h: 0.35,
    fontSize: 12, fontFace: "Arial", color: COLORS.muted,
  });

  const startX = 0.5;
  const startY = 1.6;
  const cardW = 4.1;
  const cardH = 5.3;
  const gap = 0.25;

  sc.pillars.forEach((p, i) => {
    const x = startX + i * (cardW + gap);
    // Card background
    slide.addShape(pptx.ShapeType.roundRect, {
      x, y: startY, w: cardW, h: cardH,
      fill: { color: COLORS.card },
      line: { color: COLORS.muted, width: 0.5 },
      rectRadius: 0.1,
    });
    // Pillar header
    slide.addText(p.label, {
      x: x + 0.2, y: startY + 0.15, w: cardW - 0.4, h: 0.4,
      fontSize: 14, fontFace: "Arial", color: COLORS.white, bold: true,
    });
    // Score
    slide.addText(String(p.score), {
      x: x + 0.2, y: startY + 0.6, w: cardW - 0.4, h: 0.9,
      fontSize: 48, fontFace: "Arial", color: pillarColor(p.score), bold: true,
    });
    slide.addText("/ 100", {
      x: x + 0.2, y: startY + 1.55, w: cardW - 0.4, h: 0.3,
      fontSize: 10, fontFace: "Arial", color: COLORS.muted,
    });
    // Signals list (truncated)
    const signalRows = p.signals.slice(0, 5).map((s) => ({
      text: [
        { text: `${s.label}  `, options: { color: COLORS.text, bold: true, fontSize: 10 } },
        { text: s.status === "n/a" ? "n/a" : `${s.score}`, options: { color: pillarColor(s.score), fontSize: 10, bold: true } },
        { text: `\n${s.evidence}`, options: { color: COLORS.muted, fontSize: 8 } },
      ],
    }));
    signalRows.forEach((row, j) => {
      slide.addText(row.text, {
        x: x + 0.2, y: startY + 2.1 + j * 0.6, w: cardW - 0.4, h: 0.55,
        fontFace: "Arial",
      });
    });
  });
}

function addPersonaCoverageSlide(pptx: PptxGenJS, pr: PersonaCoverageResult) {
  const slide = pptx.addSlide();
  slide.background = { color: COLORS.bg };

  slide.addText("Persona × Control Coverage", {
    x: 0.5, y: 0.3, w: 12, h: 0.6,
    fontSize: 24, fontFace: "Arial", color: COLORS.white, bold: true,
  });
  slide.addText(`Overall coverage: ${pr.overallScore}/100  •  ${pr.totalCovered}/${pr.totalExpected} expected controls implemented`, {
    x: 0.5, y: 0.95, w: 12, h: 0.35,
    fontSize: 12, fontFace: "Arial", color: COLORS.muted,
  });

  // Filter to personas the tenant actually has policies for
  const rows = pr.rows.filter((r) => r.assignedPolicies.length > 0);
  if (rows.length === 0) {
    slide.addText("No personas detected in this tenant.", {
      x: 0.5, y: 2, w: 12, h: 0.5,
      fontSize: 14, fontFace: "Arial", color: COLORS.muted,
    });
    return;
  }

  // Header row
  const tableRows: PptxGenJS.TableRow[] = [
    [
      { text: "Persona", options: { bold: true, color: COLORS.white, fill: { color: COLORS.card } } },
      { text: "Policies", options: { bold: true, color: COLORS.white, fill: { color: COLORS.card } } },
      { text: "Score", options: { bold: true, color: COLORS.white, fill: { color: COLORS.card } } },
      { text: "Present", options: { bold: true, color: COLORS.white, fill: { color: COLORS.card } } },
      { text: "Partial", options: { bold: true, color: COLORS.white, fill: { color: COLORS.card } } },
      { text: "Missing", options: { bold: true, color: COLORS.white, fill: { color: COLORS.card } } },
    ],
  ];

  for (const row of rows) {
    const meta = PERSONA_META[row.persona];
    const present = row.controls.filter((c) => c.status === "present").length;
    const partial = row.controls.filter((c) => c.status === "partial").length;
    const missing = row.controls.filter((c) => c.status === "missing").length;
    tableRows.push([
      { text: meta.label, options: { color: COLORS.text } },
      { text: String(row.assignedPolicies.length), options: { color: COLORS.muted, align: "center" } },
      { text: `${row.score}`, options: { color: pillarColor(row.score), bold: true, align: "center" } },
      { text: String(present), options: { color: COLORS.green, align: "center" } },
      { text: String(partial), options: { color: COLORS.yellow, align: "center" } },
      { text: String(missing), options: { color: COLORS.red, align: "center" } },
    ]);
  }

  slide.addTable(tableRows, {
    x: 0.5, y: 1.5, w: 12,
    colW: [3.2, 1.6, 1.4, 1.9, 1.9, 2.0],
    fontSize: 11, fontFace: "Arial",
    border: { type: "solid", color: COLORS.muted, pt: 0.25 },
    fill: { color: COLORS.bg },
  });
}

function addBaselineGapSlide(pptx: PptxGenJS, gap: BaselineGapResult) {
  const slide = pptx.addSlide();
  slide.background = { color: COLORS.bg };

  slide.addText("Baseline Gap Analysis", {
    x: 0.5, y: 0.3, w: 12, h: 0.6,
    fontSize: 24, fontFace: "Arial", color: COLORS.white, bold: true,
  });
  slide.addText(`Coverage: ${gap.coverageScore}/100  •  ${gap.baselineTemplateCount} baseline templates  •  ${gap.tenantPolicyCount} tenant policies`, {
    x: 0.5, y: 0.95, w: 12, h: 0.35,
    fontSize: 12, fontFace: "Arial", color: COLORS.muted,
  });

  // Top stats row
  const stats = [
    { label: "Missing", value: gap.missing, color: COLORS.red },
    { label: "Drift", value: gap.drift, color: COLORS.yellow },
    { label: "Tenant-only", value: gap.tenantOnly, color: COLORS.accent },
    { label: "Coverage", value: `${gap.coverageScore}%`, color: pillarColor(gap.coverageScore) },
  ];
  stats.forEach((s, i) => {
    const x = 0.8 + i * 3.0;
    slide.addText(String(s.value), {
      x, y: 1.5, w: 2.2, h: 0.7,
      fontSize: 36, fontFace: "Arial", color: s.color, bold: true, align: "center",
    });
    slide.addText(s.label, {
      x, y: 2.2, w: 2.2, h: 0.3,
      fontSize: 11, fontFace: "Arial", color: COLORS.muted, align: "center",
    });
  });

  // Per-persona table
  if (gap.buckets.length > 0) {
    const tableRows: PptxGenJS.TableRow[] = [
      [
        { text: "Persona", options: { bold: true, color: COLORS.white, fill: { color: COLORS.card } } },
        { text: "Missing", options: { bold: true, color: COLORS.white, fill: { color: COLORS.card } } },
        { text: "Drift", options: { bold: true, color: COLORS.white, fill: { color: COLORS.card } } },
        { text: "Tenant-only", options: { bold: true, color: COLORS.white, fill: { color: COLORS.card } } },
        { text: "Total", options: { bold: true, color: COLORS.white, fill: { color: COLORS.card } } },
      ],
    ];
    for (const b of gap.buckets) {
      tableRows.push([
        { text: b.label, options: { color: COLORS.text } },
        { text: String(b.missingCount), options: { color: b.missingCount > 0 ? COLORS.red : COLORS.muted, align: "center" } },
        { text: String(b.driftCount), options: { color: b.driftCount > 0 ? COLORS.yellow : COLORS.muted, align: "center" } },
        { text: String(b.tenantOnlyCount), options: { color: b.tenantOnlyCount > 0 ? COLORS.accent : COLORS.muted, align: "center" } },
        { text: String(b.entries.length), options: { color: COLORS.text, align: "center", bold: true } },
      ]);
    }
    slide.addTable(tableRows, {
      x: 0.5, y: 3.0, w: 12,
      colW: [4.0, 2.0, 2.0, 2.0, 2.0],
      fontSize: 11, fontFace: "Arial",
      border: { type: "solid", color: COLORS.muted, pt: 0.25 },
      fill: { color: COLORS.bg },
    });
  }
}

// ─── Per-persona detail slides ───────────────────────────────────────────────
/**
 * Emits one slide per persona that the tenant actually has policies for.
 * Each slide shows the persona's coverage score, control coverage breakdown
 * (with the names of partial / missing controls), and baseline-gap entries
 * attributed to that persona (missing / drift / tenant-only).
 */
function addPerPersonaSlides(
  pptx: PptxGenJS,
  pr: PersonaCoverageResult,
  gap: BaselineGapResult | undefined,
) {
  // Build a quick lookup from persona → gap bucket
  const gapByPersona = new Map<string, PersonaGapBucket>();
  if (gap) {
    for (const b of gap.buckets) gapByPersona.set(b.persona, b);
  }

  const rows = pr.rows.filter(
    (r) => r.assignedPolicies.length > 0 || (gapByPersona.get(r.persona)?.entries.length ?? 0) > 0,
  );

  for (const row of rows) {
    addPersonaDetailSlide(pptx, row, gapByPersona.get(row.persona));
  }
}

function addPersonaDetailSlide(
  pptx: PptxGenJS,
  row: PersonaCoverageRow,
  bucket: PersonaGapBucket | undefined,
) {
  const slide = pptx.addSlide();
  slide.background = { color: COLORS.bg };

  const meta = PERSONA_META[row.persona];

  // ── Title ────────────────────────────────────────────────────────────────
  slide.addText(`${meta.emoji}  ${meta.label}`, {
    x: 0.5, y: 0.3, w: 9, h: 0.6,
    fontSize: 24, fontFace: "Arial", color: COLORS.white, bold: true,
  });
  slide.addText(meta.description ?? "", {
    x: 0.5, y: 0.9, w: 9, h: 0.4,
    fontSize: 11, fontFace: "Arial", color: COLORS.muted, italic: true,
  });

  // ── Score badge (top right) ──────────────────────────────────────────────
  slide.addShape("roundRect", {
    x: 10.4, y: 0.3, w: 2.3, h: 1.05,
    fill: { color: COLORS.card },
    line: { color: pillarColor(row.score), width: 2 },
    rectRadius: 0.1,
  });
  slide.addText(`${row.score}`, {
    x: 10.4, y: 0.32, w: 2.3, h: 0.65,
    fontSize: 32, fontFace: "Arial", color: pillarColor(row.score), bold: true, align: "center",
  });
  slide.addText("Coverage Score", {
    x: 10.4, y: 0.95, w: 2.3, h: 0.35,
    fontSize: 9, fontFace: "Arial", color: COLORS.muted, align: "center",
  });

  // ── Stat strip ───────────────────────────────────────────────────────────
  const present = row.controls.filter((c) => c.status === "present").length;
  const partial = row.controls.filter((c) => c.status === "partial").length;
  const missing = row.controls.filter((c) => c.status === "missing").length;

  const stats = [
    { label: "Assigned policies", value: String(row.assignedPolicies.length), color: COLORS.text },
    { label: "Enabled", value: String(row.enabledCount), color: COLORS.green },
    { label: "Controls present", value: String(present), color: COLORS.green },
    { label: "Partial", value: String(partial), color: COLORS.yellow },
    { label: "Missing", value: String(missing), color: COLORS.red },
  ];
  const stripY = 1.6;
  const stripCardW = 2.4;
  const stripCardH = 0.85;
  const stripGap = 0.1;
  stats.forEach((s, i) => {
    const x = 0.5 + i * (stripCardW + stripGap);
    slide.addShape("roundRect", {
      x, y: stripY, w: stripCardW, h: stripCardH,
      fill: { color: COLORS.card }, line: { color: COLORS.muted, width: 0.5 }, rectRadius: 0.06,
    });
    slide.addText(s.value, {
      x, y: stripY + 0.05, w: stripCardW, h: 0.45,
      fontSize: 22, fontFace: "Arial", color: s.color, bold: true, align: "center",
    });
    slide.addText(s.label, {
      x, y: stripY + 0.5, w: stripCardW, h: 0.3,
      fontSize: 9, fontFace: "Arial", color: COLORS.muted, align: "center",
    });
  });

  // ── Left column: Control coverage details ────────────────────────────────
  const colY = 2.7;
  const colH = 4.5;
  slide.addText("Control coverage", {
    x: 0.5, y: colY, w: 6, h: 0.4,
    fontSize: 14, fontFace: "Arial", color: COLORS.white, bold: true,
  });

  // Show partial + missing first (the actionable ones), then present
  const sortedControls = [...row.controls].sort((a, b) => {
    const order: Record<string, number> = { missing: 0, partial: 1, present: 2, "n/a": 3 };
    return (order[a.status] ?? 99) - (order[b.status] ?? 99);
  });

  const controlRows: PptxGenJS.TableRow[] = [
    [
      { text: "Status", options: { bold: true, color: COLORS.white, fill: { color: COLORS.card } } },
      { text: "Control", options: { bold: true, color: COLORS.white, fill: { color: COLORS.card } } },
    ],
  ];
  for (const c of sortedControls.slice(0, 10)) {
    const statusColor =
      c.status === "present" ? COLORS.green :
      c.status === "partial" ? COLORS.yellow :
      c.status === "missing" ? COLORS.red : COLORS.muted;
    const statusText =
      c.status === "present" ? "✓ Present" :
      c.status === "partial" ? "⚠ Partial" :
      c.status === "missing" ? "✗ Missing" : "- n/a";
    controlRows.push([
      { text: statusText, options: { color: statusColor, bold: true } },
      { text: c.label, options: { color: COLORS.text } },
    ]);
  }
  slide.addTable(controlRows, {
    x: 0.5, y: colY + 0.45, w: 6, colW: [1.5, 4.5],
    fontSize: 9, fontFace: "Arial",
    border: { type: "solid", color: COLORS.muted, pt: 0.25 },
    fill: { color: COLORS.bg },
  });
  if (sortedControls.length > 10) {
    slide.addText(`+ ${sortedControls.length - 10} more`, {
      x: 0.5, y: colY + colH - 0.3, w: 6, h: 0.3,
      fontSize: 9, fontFace: "Arial", color: COLORS.muted, italic: true,
    });
  }

  // ── Right column: Baseline gaps for this persona ─────────────────────────
  slide.addText("Baseline gaps", {
    x: 6.8, y: colY, w: 6, h: 0.4,
    fontSize: 14, fontFace: "Arial", color: COLORS.white, bold: true,
  });

  if (!bucket || bucket.entries.length === 0) {
    slide.addText("No baseline gaps detected for this persona.", {
      x: 6.8, y: colY + 0.5, w: 6, h: 0.4,
      fontSize: 11, fontFace: "Arial", color: COLORS.muted, italic: true,
    });
  } else {
    // Top stat row for gaps
    const gapStats = [
      { label: "Missing", value: String(bucket.missingCount), color: COLORS.red },
      { label: "Drift", value: String(bucket.driftCount), color: COLORS.yellow },
      { label: "Tenant-only", value: String(bucket.tenantOnlyCount), color: COLORS.purple },
    ];
    const gw = 1.95, gh = 0.7, gy = colY + 0.45;
    gapStats.forEach((g, i) => {
      const gx = 6.8 + i * (gw + 0.07);
      slide.addShape("roundRect", {
        x: gx, y: gy, w: gw, h: gh,
        fill: { color: COLORS.card }, line: { color: g.color, width: 0.75 }, rectRadius: 0.06,
      });
      slide.addText(g.value, {
        x: gx, y: gy + 0.02, w: gw, h: 0.4,
        fontSize: 18, fontFace: "Arial", color: g.color, bold: true, align: "center",
      });
      slide.addText(g.label, {
        x: gx, y: gy + 0.42, w: gw, h: 0.25,
        fontSize: 9, fontFace: "Arial", color: COLORS.muted, align: "center",
      });
    });

    // Top entries - sort by severity, take 6
    const sevRank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
    const topEntries = [...bucket.entries]
      .sort((a, b) => (sevRank[a.severity] ?? 9) - (sevRank[b.severity] ?? 9))
      .slice(0, 6);

    const entryRows: PptxGenJS.TableRow[] = [
      [
        { text: "Kind", options: { bold: true, color: COLORS.white, fill: { color: COLORS.card } } },
        { text: "Sev", options: { bold: true, color: COLORS.white, fill: { color: COLORS.card } } },
        { text: "Entry", options: { bold: true, color: COLORS.white, fill: { color: COLORS.card } } },
      ],
    ];
    for (const e of topEntries) {
      const kindColor =
        e.kind === "missing" ? COLORS.red :
        e.kind === "drift" ? COLORS.yellow : COLORS.purple;
      entryRows.push([
        { text: e.kind, options: { color: kindColor, bold: true } },
        { text: e.severity, options: { color: severityColor(e.severity) } },
        { text: e.label, options: { color: COLORS.text } },
      ]);
    }
    slide.addTable(entryRows, {
      x: 6.8, y: gy + gh + 0.15, w: 6, colW: [0.9, 0.7, 4.4],
      fontSize: 9, fontFace: "Arial",
      border: { type: "solid", color: COLORS.muted, pt: 0.25 },
      fill: { color: COLORS.bg },
    });
    if (bucket.entries.length > 6) {
      slide.addText(`+ ${bucket.entries.length - 6} more gap${bucket.entries.length - 6 === 1 ? "" : "s"}`, {
        x: 6.8, y: colY + colH - 0.3, w: 6, h: 0.3,
        fontSize: 9, fontFace: "Arial", color: COLORS.muted, italic: true,
      });
    }
  }
}

