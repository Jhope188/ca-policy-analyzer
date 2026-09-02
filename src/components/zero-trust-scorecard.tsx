"use client";

import { useState } from "react";
import {
  ZeroTrustScorecard,
  PillarScore,
  ScorecardSignal,
} from "@/lib/zero-trust-scorecard";
import {
  Eye,
  Lock,
  ShieldAlert,
  ChevronDown,
  ChevronRight,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  MinusCircle,
  Sparkles,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface Props {
  scorecard: ZeroTrustScorecard;
}

const PILLAR_ICONS = {
  "verify-explicitly": Eye,
  "least-privilege": Lock,
  "assume-breach": ShieldAlert,
} as const;

function statusIcon(status: ScorecardSignal["status"]) {
  if (status === "good") return CheckCircle2;
  if (status === "warn") return AlertTriangle;
  if (status === "bad") return XCircle;
  return MinusCircle;
}

function statusColor(status: ScorecardSignal["status"]) {
  if (status === "good") return "text-emerald-400";
  if (status === "warn") return "text-amber-400";
  if (status === "bad") return "text-rose-400";
  return "text-gray-500";
}

function scoreColor(score: number) {
  if (score >= 80) return "text-emerald-400";
  if (score >= 50) return "text-amber-400";
  return "text-rose-400";
}

function barColor(score: number) {
  if (score >= 80) return "bg-emerald-500";
  if (score >= 50) return "bg-amber-500";
  return "bg-rose-500";
}

function SignalRow({ signal }: { signal: ScorecardSignal }) {
  const Icon = statusIcon(signal.status);
  return (
    <div className="rounded-md border border-gray-800 bg-gray-950/50 p-3">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <Icon className={cn("h-3.5 w-3.5 shrink-0", statusColor(signal.status))} />
            <span className="text-sm font-medium text-gray-200">
              {signal.label}
            </span>
          </div>
          <p className="mt-0.5 pl-5 text-xs text-gray-500">
            {signal.description}
          </p>
          <p className="mt-1 pl-5 text-xs text-gray-400">{signal.evidence}</p>
        </div>
        <div className="shrink-0 text-right">
          {signal.status === "n/a" ? (
            <span className="text-xs text-gray-500">N/A</span>
          ) : (
            <>
              <div className={cn("text-sm font-bold tabular-nums", scoreColor(signal.score))}>
                {signal.score}
              </div>
              <div className="text-[10px] uppercase tracking-wider text-gray-500">
                weight {signal.weight}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function PillarCard({ pillar }: { pillar: PillarScore }) {
  const [open, setOpen] = useState(false);
  const Icon = PILLAR_ICONS[pillar.pillar];
  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between gap-3 text-left"
      >
        <div className="flex min-w-0 items-center gap-3">
          {open ? (
            <ChevronDown className="h-4 w-4 shrink-0 text-gray-500" />
          ) : (
            <ChevronRight className="h-4 w-4 shrink-0 text-gray-500" />
          )}
          <Icon className="h-5 w-5 shrink-0 text-gray-300" />
          <div className="min-w-0">
            <h3 className="truncate text-sm font-semibold text-white">
              {pillar.label}
            </h3>
            <p className="line-clamp-2 text-xs text-gray-500">
              {pillar.description}
            </p>
          </div>
        </div>
        <div className="shrink-0 text-right">
          <div className={cn("text-2xl font-bold tabular-nums", scoreColor(pillar.score))}>
            {pillar.score}
          </div>
          <div className="text-[10px] uppercase tracking-wider text-gray-500">
            / 100
          </div>
        </div>
      </button>

      {/* Always-visible bar */}
      <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-gray-800">
        <div
          className={cn("h-full transition-all duration-700", barColor(pillar.score))}
          style={{ width: `${pillar.score}%` }}
        />
      </div>

      {open && (
        <div className="mt-3 space-y-1.5 border-t border-gray-800 pt-3">
          {pillar.signals.map((s) => (
            <SignalRow key={s.id} signal={s} />
          ))}
        </div>
      )}
    </div>
  );
}

export function ZeroTrustScorecardCard({ scorecard }: Props) {
  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
      <div className="mb-4 flex items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <Sparkles className="h-4 w-4 text-blue-400" />
            <h2 className="text-base font-semibold text-white">
              Zero Trust Scorecard
            </h2>
          </div>
          <p className="mt-1 max-w-xl text-xs text-gray-400">
            Posture against{" "}
            <a
              href="https://learn.microsoft.com/security/zero-trust/zero-trust-overview"
              target="_blank"
              rel="noreferrer"
              className="text-blue-400 hover:underline"
            >
              Microsoft&apos;s three Zero Trust principles
            </a>
            . Each pillar rolls up 4–5 weighted signals from existing analyzer
            evidence - click a card to see its breakdown.
          </p>
        </div>
        <div className="shrink-0 text-right">
          <div className={cn("text-3xl font-bold tabular-nums", scoreColor(scorecard.overall))}>
            {scorecard.overall}
          </div>
          <div className="text-[10px] uppercase tracking-wider text-gray-500">
            Overall ZT
          </div>
        </div>
      </div>
      <div className="grid gap-3 lg:grid-cols-3">
        {scorecard.pillars.map((p) => (
          <PillarCard key={p.pillar} pillar={p} />
        ))}
      </div>
    </div>
  );
}
