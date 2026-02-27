"use client";

import { useState } from "react";
import {
  CISAlignmentResult,
  CISControlResult,
  CISStatus,
  CISLevel,
  NearMissPolicy,
} from "@/data/cis-benchmarks";
import { ScoreRing, Card } from "./ui-primitives";
import {
  CheckCircle2,
  XCircle,
  HelpCircle,
  ChevronDown,
  ChevronRight,
  Filter,
  Shield,
  ClipboardList,
  AlertTriangle,
} from "lucide-react";
import { cn } from "@/lib/utils";

// ─── Props ───────────────────────────────────────────────────────────────────

interface CISViewProps {
  result: CISAlignmentResult;
}

// ─── Status Badge ────────────────────────────────────────────────────────────

function CISStatusBadge({ status }: { status: CISStatus }) {
  const map: Record<
    CISStatus,
    { label: string; color: string; Icon: typeof CheckCircle2 }
  > = {
    pass: { label: "Pass", color: "text-emerald-400 bg-emerald-400/10", Icon: CheckCircle2 },
    fail: { label: "Fail", color: "text-red-400 bg-red-400/10", Icon: XCircle },
    manual: { label: "Manual", color: "text-amber-400 bg-amber-400/10", Icon: HelpCircle },
    "not-applicable": { label: "N/A", color: "text-gray-400 bg-gray-400/10", Icon: HelpCircle },
  };
  const { label, color, Icon } = map[status];
  return (
    <span className={cn("inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium", color)}>
      <Icon className="h-3.5 w-3.5" />
      {label}
    </span>
  );
}

function LevelBadge({ level }: { level: CISLevel }) {
  return (
    <span
      className={cn(
        "rounded px-1.5 py-0.5 text-xs font-mono font-bold",
        level === "L1"
          ? "text-amber-300 bg-amber-400/10"
          : "text-blue-300 bg-blue-400/10"
      )}
    >
      {level}
    </span>
  );
}

// ─── Control Card ────────────────────────────────────────────────────────────

function ControlCard({ controlResult }: { controlResult: CISControlResult }) {
  const [expanded, setExpanded] = useState(false);
  const { control, result } = controlResult;

  return (
    <div
      className={cn(
        "rounded-lg border bg-gray-900 transition-colors",
        result.status === "pass"
          ? "border-emerald-800/50"
          : result.status === "fail"
            ? "border-red-800/50"
            : result.status === "not-applicable"
              ? "border-gray-800/50 opacity-60"
              : "border-gray-800"
      )}
    >
      {/* Header */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex w-full items-center justify-between gap-3 p-4 text-left"
      >
        <div className="flex items-center gap-3 min-w-0">
          {expanded ? (
            <ChevronDown className="h-4 w-4 shrink-0 text-gray-500" />
          ) : (
            <ChevronRight className="h-4 w-4 shrink-0 text-gray-500" />
          )}
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs font-mono text-gray-500">
                {control.id}
              </span>
              <LevelBadge level={control.level} />
              <h4 className="text-sm font-semibold text-white">
                {control.title}
              </h4>
            </div>
            <p className="text-xs text-gray-500 mt-0.5">{control.section}</p>
          </div>
        </div>
        <CISStatusBadge status={result.status} />
      </button>

      {/* Expanded Content */}
      {expanded && (
        <div className="border-t border-gray-800 p-4 space-y-4">
          {/* Description */}
          <div>
            <h5 className="text-xs font-medium text-gray-400 uppercase mb-1">
              CIS Requirement
            </h5>
            <p className="text-sm text-gray-300">{control.description}</p>
          </div>

          {/* Result Detail */}
          <div>
            <h5 className="text-xs font-medium text-gray-400 uppercase mb-1">
              Assessment Result
            </h5>
            <p
              className={cn(
                "text-sm",
                result.status === "pass"
                  ? "text-emerald-300"
                  : result.status === "fail"
                    ? "text-red-300"
                    : "text-amber-300"
              )}
            >
              {result.detail}
            </p>
          </div>

          {/* Matching Policies */}
          {result.matchingPolicies.length > 0 && (
            <div>
              <h5 className="text-xs font-medium text-gray-400 uppercase mb-1">
                Satisfying Policies
              </h5>
              <div className="space-y-1">
                {result.matchingPolicies.map((name, i) => (
                  <div
                    key={i}
                    className="flex items-center gap-2 rounded bg-gray-800 px-3 py-2 text-sm text-gray-300"
                  >
                    <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                    {name}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Near-Miss Policies */}
          {result.nearMissPolicies && result.nearMissPolicies.length > 0 && (
            <div>
              <h5 className="text-xs font-medium text-amber-400 uppercase mb-1 flex items-center gap-1.5">
                <AlertTriangle className="h-3.5 w-3.5" />
                Near-Miss Policies
              </h5>
              <p className="text-xs text-gray-500 mb-2">
                These policies are close to satisfying this control but need modifications:
              </p>
              <div className="space-y-2">
                {result.nearMissPolicies.map((nm, i) => (
                  <div
                    key={i}
                    className="rounded bg-amber-400/5 border border-amber-800/30 p-3 space-y-1.5"
                  >
                    <div className="flex items-center gap-2 text-sm font-medium text-amber-300">
                      {nm.policyName}
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-800 text-gray-400 font-normal">
                        {nm.state === "disabled"
                          ? "Disabled"
                          : nm.state === "enabledForReportingButNotEnforced"
                            ? "Report-only"
                            : "Enabled"}
                      </span>
                    </div>
                    {nm.met.map((m, j) => (
                      <div
                        key={`met-${j}`}
                        className="flex items-start gap-2 text-xs text-emerald-400"
                      >
                        <CheckCircle2 className="h-3 w-3 mt-0.5 shrink-0" />
                        {m}
                      </div>
                    ))}
                    {nm.gaps.map((g, j) => (
                      <div
                        key={`gap-${j}`}
                        className="flex items-start gap-2 text-xs text-red-400"
                      >
                        <XCircle className="h-3 w-3 mt-0.5 shrink-0" />
                        {g}
                      </div>
                    ))}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Near-Miss Policies */}
          {result.nearMissPolicies && result.nearMissPolicies.length > 0 && (
            <div>
              <h5 className="text-xs font-medium text-amber-400 uppercase mb-1 flex items-center gap-1.5">
                <AlertTriangle className="h-3.5 w-3.5" />
                Near-Miss Policies
              </h5>
              <p className="text-xs text-gray-500 mb-2">
                These policies are close to satisfying this control but need modifications:
              </p>
              <div className="space-y-2">
                {result.nearMissPolicies.map((nm, i) => (
                  <div
                    key={i}
                    className="rounded bg-amber-400/5 border border-amber-800/30 p-3 space-y-1.5"
                  >
                    <div className="flex items-center gap-2 text-sm font-medium text-amber-300">
                      {nm.policyName}
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-800 text-gray-400 font-normal">
                        {nm.state === "disabled"
                          ? "Disabled"
                          : nm.state === "enabledForReportingButNotEnforced"
                            ? "Report-only"
                            : "Enabled"}
                      </span>
                    </div>
                    {nm.met.map((m, j) => (
                      <div
                        key={`met-${j}`}
                        className="flex items-start gap-2 text-xs text-emerald-400"
                      >
                        <CheckCircle2 className="h-3 w-3 mt-0.5 shrink-0" />
                        {m}
                      </div>
                    ))}
                    {nm.gaps.map((g, j) => (
                      <div
                        key={`gap-${j}`}
                        className="flex items-start gap-2 text-xs text-red-400"
                      >
                        <XCircle className="h-3 w-3 mt-0.5 shrink-0" />
                        {g}
                      </div>
                    ))}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Remediation */}
          {result.status === "fail" && result.remediation && (
            <div>
              <h5 className="text-xs font-medium text-gray-400 uppercase mb-1">
                Remediation
              </h5>
              <div className="rounded bg-red-400/5 border border-red-800/30 p-3">
                <p className="text-sm text-red-300">{result.remediation}</p>
              </div>
            </div>
          )}

          {/* Policy Creation Guidance */}
          {result.status === "fail" && control.policyGuidance && (
            <div>
              <h5 className="text-xs font-medium text-teal-400 uppercase mb-2 flex items-center gap-1.5">
                <ClipboardList className="h-3.5 w-3.5" />
                Recommended Policy
              </h5>
              <div className="rounded-lg bg-teal-400/5 border border-teal-800/30 p-4 space-y-3">
                {/* Suggested name */}
                <div>
                  <span className="text-xs text-gray-400">Suggested Name:</span>
                  <div className="mt-1 rounded bg-gray-800 px-3 py-2 font-mono text-sm text-teal-300">
                    {control.policyGuidance.suggestedName}
                  </div>
                </div>

                {/* Portal steps */}
                <div>
                  <span className="text-xs text-gray-400">
                    Entra Admin Center → Protection → Conditional Access → + New policy:
                  </span>
                  <ol className="mt-2 space-y-2">
                    {control.policyGuidance.portalSteps.map((step, i) => (
                      <li key={i} className="flex gap-3">
                        <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-teal-400/10 text-xs font-bold text-teal-400">
                          {i + 1}
                        </span>
                        <div className="min-w-0">
                          <span className="text-sm font-semibold text-white">
                            {step.tab}
                          </span>
                          <ul className="mt-0.5 space-y-0.5">
                            {step.instructions.map((inst, j) => (
                              <li
                                key={j}
                                className="text-sm text-gray-300 before:content-['→_'] before:text-teal-600"
                              >
                                {inst}
                              </li>
                            ))}
                          </ul>
                        </div>
                      </li>
                    ))}
                  </ol>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Main View ───────────────────────────────────────────────────────────────

export function CISView({ result }: CISViewProps) {
  const [statusFilter, setStatusFilter] = useState<CISStatus | "all">("all");
  const [levelFilter, setLevelFilter] = useState<CISLevel | "all">("all");

  const filtered = result.controls.filter((c) => {
    if (statusFilter !== "all" && c.result.status !== statusFilter) return false;
    if (levelFilter !== "all" && c.control.level !== levelFilter) return false;
    return true;
  });

  // Group by section
  const sections = [...new Set(result.controls.map((c) => c.control.section))];

  const l1Controls = result.controls.filter((c) => c.control.level === "L1" && c.result.status !== "not-applicable");
  const l2Controls = result.controls.filter((c) => c.control.level === "L2" && c.result.status !== "not-applicable");
  const l1Pass = l1Controls.filter((c) => c.result.status === "pass").length;
  const l2Pass = l2Controls.filter((c) => c.result.status === "pass").length;

  return (
    <div className="space-y-6">
      {/* Summary Header */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
        <Card className="flex flex-col items-center justify-center p-6 sm:col-span-2">
          <ScoreRing score={result.alignmentScore} />
          <p className="mt-3 text-sm text-gray-400">CIS Alignment Score</p>
          <p className="text-xs text-gray-600">
            CIS Microsoft 365 Foundations Benchmark v{result.benchmarkVersion ?? "6.0.0"}
          </p>
          {result.notApplicableCount > 0 && (
            <p className="text-xs text-gray-600 mt-1">
              {result.notApplicableCount} control{result.notApplicableCount > 1 ? "s" : ""} excluded (license N/A)
            </p>
          )}
        </Card>

        <Card className="flex flex-col items-center justify-center p-4">
          <div className="text-3xl font-bold text-emerald-400">
            {result.passCount}
          </div>
          <div className="text-xs text-gray-400 mt-1">Passing</div>
        </Card>
        <Card className="flex flex-col items-center justify-center p-4">
          <div className="text-3xl font-bold text-red-400">
            {result.failCount}
          </div>
          <div className="text-xs text-gray-400 mt-1">Failing</div>
        </Card>
        <Card className="flex flex-col items-center justify-center p-4">
          <div className="text-3xl font-bold text-gray-400">
            {result.totalControls - result.notApplicableCount}
          </div>
          <div className="text-xs text-gray-400 mt-1">Applicable</div>
        </Card>
      </div>

      {/* Level Breakdown */}
      <div className="grid gap-4 sm:grid-cols-2">
        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Shield className="h-4 w-4 text-amber-400" />
              <span className="text-sm font-medium text-white">
                Level 1 (Essential)
              </span>
            </div>
            <span className="text-sm font-mono text-amber-400">
              {l1Pass}/{l1Controls.length}
            </span>
          </div>
          <div className="mt-2 h-2 rounded-full bg-gray-800 overflow-hidden">
            <div
              className="h-full rounded-full bg-amber-500 transition-all"
              style={{
                width: `${l1Controls.length > 0 ? (l1Pass / l1Controls.length) * 100 : 0}%`,
              }}
            />
          </div>
        </Card>
        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Shield className="h-4 w-4 text-blue-400" />
              <span className="text-sm font-medium text-white">
                Level 2 (Defense-in-Depth)
              </span>
            </div>
            <span className="text-sm font-mono text-blue-400">
              {l2Pass}/{l2Controls.length}
            </span>
          </div>
          <div className="mt-2 h-2 rounded-full bg-gray-800 overflow-hidden">
            <div
              className="h-full rounded-full bg-blue-500 transition-all"
              style={{
                width: `${l2Controls.length > 0 ? (l2Pass / l2Controls.length) * 100 : 0}%`,
              }}
            />
          </div>
        </Card>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-4">
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-gray-500" />
          <span className="text-xs text-gray-500">Status:</span>
          {(["all", "pass", "fail", "manual", "not-applicable"] as const).map((f) => (
            <button
              key={f}
              onClick={() => setStatusFilter(f)}
              className={cn(
                "rounded-md px-3 py-1.5 text-xs font-medium transition-colors",
                statusFilter === f
                  ? "bg-gray-700 text-white"
                  : "text-gray-400 hover:text-white"
              )}
            >
              {f === "all"
                ? "All"
                : f === "not-applicable"
                  ? "N/A"
                  : f.charAt(0).toUpperCase() + f.slice(1)}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-gray-500">Level:</span>
          {(["all", "L1", "L2"] as const).map((f) => (
            <button
              key={f}
              onClick={() => setLevelFilter(f)}
              className={cn(
                "rounded-md px-3 py-1.5 text-xs font-medium transition-colors",
                levelFilter === f
                  ? "bg-gray-700 text-white"
                  : "text-gray-400 hover:text-white"
              )}
            >
              {f === "all" ? "All" : f}
            </button>
          ))}
        </div>
      </div>

      {/* Control Cards by Section */}
      {sections.map((section) => {
        const sectionControls = filtered.filter(
          (c) => c.control.section === section
        );
        if (sectionControls.length === 0) return null;

        return (
          <div key={section} className="space-y-3">
            <h3 className="text-sm font-semibold text-gray-300">{section}</h3>
            <div className="space-y-2">
              {sectionControls.map((cr) => (
                <ControlCard key={cr.control.id} controlResult={cr} />
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}
