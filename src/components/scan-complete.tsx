"use client";

/**
 * The moment a run finishes. Holds for a couple of seconds, then page.tsx drops
 * it and the dashboard takes over - so nothing has to be dismissed on a
 * re-scan.
 *
 * It marks finishing the scan, not the tenant's score: with critical findings
 * open, the accent goes amber and the wording stays flat. Congratulating
 * someone on a broken tenant is worse than saying nothing.
 */

import { TenantSummary } from "@/lib/analyzer";
import { ScoreRing, StatCard } from "./ui-primitives";
import {
  Check,
  ShieldCheck,
  ShieldAlert,
  AlertCircle,
  AlertTriangle,
  ScanSearch,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface ScanCompleteProps {
  summary: TenantSummary;
  score: number;
  /** Letter grade from the composite score. Absent for offline imports. */
  grade?: string;
  /** How many steps this run walked through. */
  steps: number;
  /** Wall-clock duration of the run, in seconds. */
  seconds: number;
  /** False when the sign-in log scan did not run. */
  signInScanRan: boolean;
  /** Null hides the offer - an offline import has no live tenant to scan. */
  onRescanWithSignInLogs: (() => void) | null;
  onDismiss: () => void;
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return s === 0 ? `${m}m` : `${m}m ${s}s`;
}

export function ScanComplete({
  summary,
  score,
  grade,
  steps,
  seconds,
  signInScanRan,
  onRescanWithSignInLogs,
  onDismiss,
}: ScanCompleteProps) {
  const clean = summary.criticalFindings === 0;
  const policyWord = summary.totalPolicies === 1 ? "policy" : "policies";

  return (
    <div className="flex flex-col items-center text-center">
      <span
        className={cn(
          "rk-rise inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-semibold",
          clean
            ? "bg-green-500/10 text-green-400"
            : "bg-amber-500/10 text-amber-300"
        )}
      >
        <Check className="h-3 w-3" />
        {steps} steps complete
      </span>

      {/* ponytail: ScoreRing renders at its final value - the arc doesn't sweep
          in. Add an `animate` prop there if the reveal ever needs more. */}
      <div className="rk-rise mt-5" style={{ animationDelay: "80ms" }}>
        <ScoreRing score={score} size={132} />
      </div>

      <div className="rk-rise mt-4" style={{ animationDelay: "160ms" }}>
        <div className="flex flex-wrap items-center justify-center gap-2.5">
          <h2 className="text-2xl font-bold text-white">Analysis complete</h2>
          {grade && (
            <span className="rounded-full bg-gray-800 px-2.5 py-0.5 text-xs font-semibold text-gray-300">
              Grade {grade}
            </span>
          )}
        </div>
        <p className="mt-1.5 text-sm text-gray-400">
          {clean
            ? "No critical findings."
            : `${summary.criticalFindings} critical ${
                summary.criticalFindings === 1 ? "finding needs" : "findings need"
              } attention.`}{" "}
          {summary.totalPolicies} {policyWord} read in {formatDuration(seconds)}.
        </p>
      </div>

      <div
        className="rk-rise mt-6 grid w-full max-w-2xl grid-cols-2 gap-3 sm:grid-cols-4"
        style={{ animationDelay: "240ms" }}
      >
        <StatCard
          label="Policies read"
          value={summary.totalPolicies}
          icon={ShieldCheck}
          variant="default"
        />
        <StatCard
          label="Critical"
          value={summary.criticalFindings}
          icon={ShieldAlert}
          variant={summary.criticalFindings > 0 ? "danger" : "success"}
        />
        <StatCard
          label="High"
          value={summary.highFindings}
          icon={AlertCircle}
          variant={summary.highFindings > 0 ? "danger" : "default"}
        />
        <StatCard
          label="Findings total"
          value={summary.totalFindings}
          icon={AlertTriangle}
          variant="default"
        />
      </div>

      {!signInScanRan && (
        <div
          className="rk-rise mt-5 flex flex-wrap items-center justify-center gap-3"
          style={{ animationDelay: "320ms" }}
        >
          <span className="rounded-full bg-gray-800 px-3 py-1 text-xs text-gray-400">
            Sign-in log scan skipped
          </span>
          {onRescanWithSignInLogs && (
            <button
              onClick={onRescanWithSignInLogs}
              className="inline-flex items-center gap-2 rounded-lg border border-gray-700 px-3 py-1.5 text-xs text-gray-300 transition-colors hover:bg-gray-800"
            >
              <ScanSearch className="h-3.5 w-3.5" />
              Re-scan with sign-in logs
            </button>
          )}
        </div>
      )}

      <button
        onClick={onDismiss}
        className="rk-rise mt-7 text-xs text-gray-500 transition-colors hover:text-gray-300"
        style={{ animationDelay: "400ms" }}
      >
        Opening dashboard - skip
      </button>
    </div>
  );
}
