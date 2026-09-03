"use client";

/**
 * Step-by-step progress for an analysis run. Replaces the single progress line
 * that used to sit inside the Run Analysis button - a long run is a lot easier
 * to wait through when you can see which step is holding it up.
 */

import { Check, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";

interface RunProgressProps {
  /** Ordered labels for this run, from liveStepList() or offlineStepList. */
  steps: string[];
  /** The label currently being worked on. */
  current: string;
  /** Optional line under the bar, e.g. which step was skipped and why. */
  note?: string;
}

export function RunProgress({ steps, current, note }: RunProgressProps) {
  const activeIndex = steps.indexOf(current);
  // A label that isn't in the list would otherwise render as "nothing running".
  // ponytail: show it as its own trailing line rather than reconciling lists.
  const unlisted = current !== "" && activeIndex === -1;
  const done = activeIndex < 0 ? 0 : activeIndex;
  const percent = Math.round((done / steps.length) * 100);

  return (
    <div className="w-full max-w-lg text-left">
      <ul className="space-y-2">
        {steps.map((step, i) => {
          const isDone = i < done;
          const isActive = i === activeIndex;
          return (
            <li
              key={step}
              className={cn(
                "flex items-center gap-2.5 text-sm",
                isDone && "text-gray-400",
                isActive && "text-white",
                !isDone && !isActive && "text-gray-600"
              )}
            >
              <span className="flex h-4 w-4 shrink-0 items-center justify-center">
                {isDone ? (
                  <Check className="h-3.5 w-3.5 text-green-500" />
                ) : isActive ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin text-blue-400" />
                ) : (
                  <span className="h-1.5 w-1.5 rounded-full bg-gray-700" />
                )}
              </span>
              <span>{step}</span>
            </li>
          );
        })}
        {unlisted && (
          <li className="flex items-center gap-2.5 text-sm text-white">
            <span className="flex h-4 w-4 shrink-0 items-center justify-center">
              <Loader2 className="h-3.5 w-3.5 animate-spin text-blue-400" />
            </span>
            <span>{current}</span>
          </li>
        )}
      </ul>

      <div className="mt-4 h-1.5 overflow-hidden rounded-full bg-gray-800">
        <div
          className="h-full rounded-full bg-blue-500 transition-all duration-300"
          style={{ width: `${percent}%` }}
        />
      </div>
      <p className="mt-2 text-xs text-gray-500">
        Step {Math.min(done + 1, steps.length)} of {steps.length}
        {note && <span className="text-gray-600"> - {note}</span>}
      </p>
    </div>
  );
}
