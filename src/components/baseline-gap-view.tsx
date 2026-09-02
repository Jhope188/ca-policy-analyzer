"use client";

import { useMemo, useState } from "react";
import {
  BaselineGapResult,
  BaselineGapEntry,
  PersonaGapBucket,
  GapKind,
} from "@/lib/baseline-gap";
import { TemplateAnalysisResult } from "@/lib/template-matcher";
import { buildDeploymentPlan, downloadDeploymentBundle } from "@/lib/deployment-plan";
import {
  GitCompareArrows,
  ChevronDown,
  ChevronRight,
  AlertOctagon,
  GitBranch,
  PackageOpen,
  Download,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface Props {
  result: BaselineGapResult;
  baselineLabel?: string | null;
  templateResult?: TemplateAnalysisResult | null;
}

const KIND_META: Record<
  GapKind,
  { label: string; icon: typeof AlertOctagon; tone: string; bg: string; border: string }
> = {
  missing: {
    label: "Missing",
    icon: AlertOctagon,
    tone: "text-rose-400",
    bg: "bg-rose-500/10",
    border: "border-rose-500/30",
  },
  drift: {
    label: "Drift",
    icon: GitBranch,
    tone: "text-amber-400",
    bg: "bg-amber-500/10",
    border: "border-amber-500/30",
  },
  "tenant-only": {
    label: "Tenant-only",
    icon: PackageOpen,
    tone: "text-sky-400",
    bg: "bg-sky-500/10",
    border: "border-sky-500/30",
  },
};

const SEVERITY_TONE: Record<BaselineGapEntry["severity"], string> = {
  critical: "bg-rose-600 text-white",
  high: "bg-orange-600 text-white",
  medium: "bg-amber-600 text-white",
  low: "bg-gray-700 text-gray-200",
};

function GapEntryRow({ entry }: { entry: BaselineGapEntry }) {
  const [open, setOpen] = useState(false);
  const meta = KIND_META[entry.kind];
  const Icon = meta.icon;
  return (
    <div
      className={cn(
        "rounded-md border p-3",
        meta.border,
        meta.bg,
      )}
    >
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-start justify-between gap-3 text-left"
      >
        <div className="flex min-w-0 items-start gap-2">
          {open ? (
            <ChevronDown className="mt-0.5 h-3.5 w-3.5 shrink-0 text-gray-500" />
          ) : (
            <ChevronRight className="mt-0.5 h-3.5 w-3.5 shrink-0 text-gray-500" />
          )}
          <Icon className={cn("mt-0.5 h-3.5 w-3.5 shrink-0", meta.tone)} />
          <div className="min-w-0">
            <div className="truncate text-sm font-medium text-gray-100">
              {entry.label}
            </div>
            <p className="mt-0.5 text-xs text-gray-400">{entry.summary}</p>
          </div>
        </div>
        <span
          className={cn(
            "shrink-0 rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider",
            SEVERITY_TONE[entry.severity]
          )}
        >
          {entry.severity}
        </span>
      </button>
      {open && entry.details.length > 0 && (
        <ul className="mt-2 space-y-1 border-t border-gray-800/60 pt-2 pl-7 text-xs text-gray-400">
          {entry.details.map((d, i) => (
            <li key={i} className="list-disc">
              {d}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function PersonaBucketCard({
  bucket,
  filter,
}: {
  bucket: PersonaGapBucket;
  filter: Set<GapKind>;
}) {
  const [open, setOpen] = useState(true);
  const visible = bucket.entries.filter((e) => filter.has(e.kind));
  if (visible.length === 0) return null;

  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between gap-3 p-4 text-left"
      >
        <div className="flex items-center gap-3">
          {open ? (
            <ChevronDown className="h-4 w-4 text-gray-500" />
          ) : (
            <ChevronRight className="h-4 w-4 text-gray-500" />
          )}
          <span className="text-lg">{bucket.emoji}</span>
          <div>
            <h3 className="text-sm font-semibold text-white">{bucket.label}</h3>
            <p className="text-xs text-gray-500">
              {visible.length} gap{visible.length === 1 ? "" : "s"} for this persona
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2 text-xs">
          {bucket.missingCount > 0 && (
            <span className="rounded bg-rose-500/10 px-2 py-0.5 text-rose-300">
              {bucket.missingCount} missing
            </span>
          )}
          {bucket.driftCount > 0 && (
            <span className="rounded bg-amber-500/10 px-2 py-0.5 text-amber-300">
              {bucket.driftCount} drift
            </span>
          )}
          {bucket.tenantOnlyCount > 0 && (
            <span className="rounded bg-sky-500/10 px-2 py-0.5 text-sky-300">
              {bucket.tenantOnlyCount} tenant-only
            </span>
          )}
        </div>
      </button>
      {open && (
        <div className="space-y-1.5 border-t border-gray-800 p-3">
          {visible.map((e) => (
            <GapEntryRow key={e.id} entry={e} />
          ))}
        </div>
      )}
    </div>
  );
}

export function BaselineGapView({ result, baselineLabel, templateResult }: Props) {
  const [active, setActive] = useState<Set<GapKind>>(
    new Set<GapKind>(["missing", "drift", "tenant-only"])
  );

  const deployableCount = result.missing + result.drift;

  const handleDownloadPlan = async () => {
    if (!templateResult) return;
    const plan = buildDeploymentPlan(
      result,
      templateResult,
      baselineLabel ?? "baseline"
    );
    await downloadDeploymentBundle(plan);
  };

  const toggle = (k: GapKind) => {
    const next = new Set(active);
    if (next.has(k)) {
      next.delete(k);
    } else {
      next.add(k);
    }
    if (next.size === 0) {
      // Don't allow zero filters - re-add the one being toggled
      next.add(k);
    }
    setActive(next);
  };

  const visibleTotal = useMemo(
    () => result.entries.filter((e) => active.has(e.kind)).length,
    [result.entries, active]
  );

  const coverageColor =
    result.coverageScore >= 80
      ? "text-emerald-400"
      : result.coverageScore >= 50
        ? "text-amber-400"
        : "text-rose-400";

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <GitCompareArrows className="h-4 w-4 text-blue-400" />
              <h2 className="text-base font-semibold text-white">
                Baseline Gap Analysis
              </h2>
            </div>
            <p className="mt-1 max-w-2xl text-xs text-gray-400">
              Tenant policies compared against{" "}
              <span className="font-medium text-gray-200">
                {baselineLabel ?? "the loaded baseline"}
              </span>
              . <span className="text-rose-400">Missing</span> = the baseline
              has it, the tenant doesn&apos;t.{" "}
              <span className="text-amber-400">Drift</span> = both have it but
              they differ. <span className="text-sky-400">Tenant-only</span> =
              an enabled tenant policy with no baseline equivalent.
            </p>
          </div>
          <div className="flex items-start gap-3">
            {templateResult && deployableCount > 0 && (
              <button
                onClick={handleDownloadPlan}
                title="Download Graph-ready deployment plan (JSON)"
                className="flex items-center gap-1.5 self-start rounded-lg border border-blue-500/40 bg-blue-500/10 px-3 py-1.5 text-xs font-medium text-blue-300 transition-colors hover:bg-blue-500/20"
              >
                <Download className="h-3.5 w-3.5" />
                Download deployment bundle ({deployableCount})
              </button>
            )}
            <div className="text-right">
              <div className={cn("text-3xl font-bold tabular-nums", coverageColor)}>
                {result.coverageScore}
              </div>
              <div className="text-[10px] uppercase tracking-wider text-gray-500">
                Baseline coverage
              </div>
            </div>
          </div>
        </div>

        {/* Stat row */}
        <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
          <button
            onClick={() => toggle("missing")}
            className={cn(
              "rounded-md border p-3 text-left transition-colors",
              active.has("missing")
                ? "border-rose-500/40 bg-rose-500/10"
                : "border-gray-800 bg-gray-950 opacity-50 hover:opacity-75"
            )}
          >
            <div className="text-xl font-bold text-rose-400 tabular-nums">
              {result.missing}
            </div>
            <div className="text-xs text-gray-400">Missing</div>
          </button>
          <button
            onClick={() => toggle("drift")}
            className={cn(
              "rounded-md border p-3 text-left transition-colors",
              active.has("drift")
                ? "border-amber-500/40 bg-amber-500/10"
                : "border-gray-800 bg-gray-950 opacity-50 hover:opacity-75"
            )}
          >
            <div className="text-xl font-bold text-amber-400 tabular-nums">
              {result.drift}
            </div>
            <div className="text-xs text-gray-400">Drift</div>
          </button>
          <button
            onClick={() => toggle("tenant-only")}
            className={cn(
              "rounded-md border p-3 text-left transition-colors",
              active.has("tenant-only")
                ? "border-sky-500/40 bg-sky-500/10"
                : "border-gray-800 bg-gray-950 opacity-50 hover:opacity-75"
            )}
          >
            <div className="text-xl font-bold text-sky-400 tabular-nums">
              {result.tenantOnly}
            </div>
            <div className="text-xs text-gray-400">Tenant-only</div>
          </button>
          <div className="rounded-md border border-gray-800 bg-gray-950 p-3">
            <div className="text-xl font-bold text-gray-100 tabular-nums">
              {result.baselineTemplateCount}
            </div>
            <div className="text-xs text-gray-400">
              Baseline templates · {result.tenantPolicyCount} tenant policies
            </div>
          </div>
        </div>
      </div>

      {/* Buckets */}
      {visibleTotal === 0 ? (
        <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-6 text-center">
          <p className="text-sm text-emerald-300">
            No gaps in the selected categories. The tenant aligns with the
            baseline for these filters.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {result.buckets.map((b) => (
            <PersonaBucketCard key={b.persona} bucket={b} filter={active} />
          ))}
        </div>
      )}
    </div>
  );
}
