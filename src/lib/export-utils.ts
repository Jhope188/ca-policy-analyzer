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

// ─── Export Options ──────────────────────────────────────────────────────────

export interface ExportOptions {
  /** When true, filter out Microsoft-managed policies from policy slides/rows */
  hideMicrosoftPolicies?: boolean;
  /** Base64-encoded logo image (data URI or raw base64) for the PPTX cover slide */
  logoBase64?: string | null;
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
    // Detect Next.js basePath for GitHub Pages deployment
    /* eslint-disable @typescript-eslint/no-explicit-any */
    const basePath =
      typeof window !== "undefined" && (window as any).__NEXT_DATA__?.basePath
        ? String((window as any).__NEXT_DATA__.basePath)
        : "";
    /* eslint-enable @typescript-eslint/no-explicit-any */
    const resp = await fetch(`${basePath}/logo.png`);
    if (!resp.ok) return null;
    const blob = await resp.blob();
    return new Promise((resolve) => {
      const reader = new FileReader();
      reader.onloadend = () => resolve(reader.result as string);
      reader.onerror = () => resolve(null);
      reader.readAsDataURL(blob);
    });
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
  return arr && arr.length > 0 ? arr.join(", ") : "—";
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
    ["CA Policy Analyzer — Export", ""],
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
  const policyRows = policyResults.map((r) => ({
    "Policy Name": r.policy.displayName,
    State: stateLabel(r.policy.state),
    "Target Users": r.visualization.targetUsers,
    "Target Apps": r.visualization.targetApps,
    Conditions: joinOrNone(r.visualization.conditions),
    "Grant Controls": joinOrNone(r.visualization.grantControls),
    "Session Controls": joinOrNone(r.visualization.sessionControls),
    "Include Users": joinOrNone(r.policy.conditions.users.includeUsers),
    "Exclude Users": joinOrNone(r.policy.conditions.users.excludeUsers),
    "Include Groups": joinOrNone(r.policy.conditions.users.includeGroups),
    "Exclude Groups": joinOrNone(r.policy.conditions.users.excludeGroups),
    "Include Roles": joinOrNone(r.policy.conditions.users.includeRoles),
    "Exclude Roles": joinOrNone(r.policy.conditions.users.excludeRoles),
    "Include Apps": joinOrNone(r.policy.conditions.applications.includeApplications),
    "Exclude Apps": joinOrNone(r.policy.conditions.applications.excludeApplications),
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
  options?: ExportOptions,
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

  // Logo — top-right corner (customisable placeholder)
  const logoData = options?.logoBase64;
  if (logoData) {
    titleSlide.addImage({
      data: logoData,
      x: 8.5,
      y: 0.4,
      w: 3.8,
      h: 2.53,
      rounding: true,
    });
  }

  titleSlide.addText("Conditional Access\nPolicy Analysis", {
    x: 0.8,
    y: 1.5,
    w: logoData ? 7.5 : 11,
    h: 2.5,
    fontSize: 36,
    fontFace: "Arial",
    color: COLORS.white,
    bold: true,
    lineSpacingMultiple: 1.2,
  });
  titleSlide.addText(`Generated ${new Date().toLocaleDateString()}`, {
    x: 0.8,
    y: 4.2,
    w: 11,
    h: 0.5,
    fontSize: 14,
    fontFace: "Arial",
    color: COLORS.muted,
  });
  if (!logoData) {
    // Placeholder hint when no logo is provided
    titleSlide.addShape("rect" as PptxGenJS.ShapeType, {
      x: 9.2,
      y: 0.5,
      w: 3,
      h: 2,
      fill: { color: COLORS.card },
      rectRadius: 0.1,
      line: { color: COLORS.muted, dashType: "dash", width: 1 },
    });
    titleSlide.addText("Your Logo Here", {
      x: 9.2,
      y: 1.1,
      w: 3,
      h: 0.5,
      fontSize: 12,
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
    addPolicySlide(pptx, pr);
  }

  // ── Slide N: CIS Alignment ──────────────────────────────────────────
  if (cisResult) {
    addCISSlide(pptx, cisResult);
  }

  // ── Download ────────────────────────────────────────────────────────
  await pptx.writeFile({ fileName: `ca-analysis-${datestamp()}.pptx` });
}

function addPolicySlide(pptx: PptxGenJS, pr: PolicyResult) {
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
    ["Include Users", joinOrNone(policy.conditions.users.includeUsers)],
    ["Exclude Users", joinOrNone(policy.conditions.users.excludeUsers)],
    ["Include Groups", joinOrNone(policy.conditions.users.includeGroups)],
    ["Exclude Groups", joinOrNone(policy.conditions.users.excludeGroups)],
    ["Include Roles", joinOrNone(policy.conditions.users.includeRoles)],
    ["Client App Types", joinOrNone(policy.conditions.clientAppTypes)],
    ["Platforms", joinOrNone(policy.conditions.platforms?.includePlatforms)],
    ["User Risk", joinOrNone(policy.conditions.userRiskLevels)],
    ["Sign-in Risk", joinOrNone(policy.conditions.signInRiskLevels)],
  ].filter((row) => row[1] !== "—");

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
