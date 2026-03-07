"use client";

import { AnalysisResult, CompositeScoreResult } from "@/lib/analyzer";
import { TenantLicenses } from "@/lib/graph-client";
import { ScoreRing, StatCard } from "./ui-primitives";
import {
  ShieldCheck,
  ShieldAlert,
  ShieldOff,
  FileBarChart,
  AlertCircle,
  AlertTriangle,
  KeyRound,
} from "lucide-react";
import { cn } from "@/lib/utils";

// ─── Score Breakdown Bar ────────────────────────────────────────────────────

function ScoreBar({
  label,
  score,
  max,
  color,
}: {
  label: string;
  score: number;
  max: number;
  color: string;
}) {
  const pct = max > 0 ? (score / max) * 100 : 0;
  return (
    <div className="flex items-center gap-3 text-xs">
      <span className="w-32 shrink-0 text-gray-400 text-right">{label}</span>
      <div className="flex-1 h-2 rounded-full bg-gray-800 overflow-hidden">
        <div
          className={cn("h-full rounded-full transition-all duration-700", color)}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="w-14 shrink-0 text-gray-500 tabular-nums">
        {score} / {max}
      </span>
    </div>
  );
}

// ─── License Badge ──────────────────────────────────────────────────────────

function LicenseBadge({ label, detected }: { label: string; detected: boolean }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium",
        detected
          ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
          : "bg-gray-800 text-gray-500 border border-gray-700"
      )}
    >
      <span className={cn("h-1.5 w-1.5 rounded-full", detected ? "bg-emerald-400" : "bg-gray-600")} />
      {label}
      {detected ? "" : " — not detected"}
    </span>
  );
}

export function Dashboard({
  result,
  compositeScore,
  licenses,
}: {
  result: AnalysisResult;
  compositeScore: CompositeScoreResult | null;
  licenses?: TenantLicenses | null;
}) {
  const s = result.tenantSummary;
  const score = compositeScore?.overall ?? result.overallScore;

  return (
    <div className="space-y-6">
      {/* Top Row — Score + Summary Stats */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-6">
        {/* Score Ring + Breakdown — spans 2 cols */}
        <div className="flex flex-col items-center justify-center rounded-xl border border-gray-800 bg-gray-900 p-6 sm:col-span-2">
          <ScoreRing score={score} />
          <p className="mt-3 text-sm text-gray-400">Security Posture Score</p>
          {compositeScore && (
            <span className="text-xs text-gray-600">
              Grade: {compositeScore.grade}
            </span>
          )}

          {/* Score Breakdown */}
          {compositeScore && (
            <div className="mt-4 w-full space-y-2">
              <ScoreBar
                label="CIS Alignment"
                score={compositeScore.cisScore}
                max={compositeScore.cisMax}
                color="bg-blue-500"
              />
              <ScoreBar
                label="Template Coverage"
                score={compositeScore.templateScore}
                max={compositeScore.templateMax}
                color="bg-purple-500"
              />
              <ScoreBar
                label="Config Quality"
                score={compositeScore.configScore}
                max={compositeScore.configMax}
                color="bg-emerald-500"
              />
            </div>
          )}
        </div>

        {/* Policy Stats */}
        <StatCard
          label="Enabled"
          value={s.enabledPolicies}
          icon={ShieldCheck}
          variant="success"
        />
        <StatCard
          label="Report-only"
          value={s.reportOnlyPolicies}
          icon={FileBarChart}
          variant="warning"
        />
        <StatCard
          label="Disabled"
          value={s.disabledPolicies}
          icon={ShieldOff}
          variant="default"
        />
        <StatCard
          label="Total"
          value={s.totalPolicies}
          icon={ShieldCheck}
          variant="default"
        />
      </div>

      {/* Detected Licenses */}
      {licenses && (
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <div className="flex items-center gap-2 mb-3">
            <KeyRound className="h-4 w-4 text-gray-400" />
            <h3 className="text-sm font-medium text-gray-300">Detected Licenses</h3>
            <span className="text-xs text-gray-600">(affects scoring scope)</span>
          </div>
          <div className="flex flex-wrap gap-2">
            <LicenseBadge label="Entra ID P1" detected={licenses.hasEntraIdP1} />
            <LicenseBadge label="Entra ID P2" detected={licenses.hasEntraIdP2} />
            <LicenseBadge label="Intune Plan 1" detected={licenses.hasIntunePlan1} />
            <LicenseBadge label="Workload ID Premium" detected={licenses.hasWorkloadIdPremium} />
          </div>
          {(!licenses.hasEntraIdP2 || !licenses.hasIntunePlan1 || !licenses.hasWorkloadIdPremium) && (
            <p className="mt-2 text-xs text-gray-600">
              Controls requiring undetected licenses are excluded from scoring and marked &ldquo;N/A&rdquo;.
            </p>
          )}
        </div>
      )}

      {/* Finding Severity Breakdown */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
        <StatCard
          label="Critical"
          value={s.criticalFindings}
          icon={ShieldAlert}
          variant={s.criticalFindings > 0 ? "danger" : "default"}
        />
        <StatCard
          label="High"
          value={s.highFindings}
          icon={AlertCircle}
          variant={s.highFindings > 0 ? "danger" : "default"}
        />
        <StatCard
          label="Medium"
          value={s.mediumFindings}
          icon={AlertTriangle}
          variant={s.mediumFindings > 0 ? "warning" : "default"}
        />
        <StatCard
          label="Low"
          value={s.lowFindings}
          icon={AlertTriangle}
          variant="default"
        />
        <StatCard
          label="Info"
          value={s.infoFindings}
          icon={AlertTriangle}
          variant="default"
        />
      </div>
    </div>
  );
}
