/**
 * The run-progress and scan-complete panels, rendered. Covers what typecheck
 * cannot: that the wording matches the numbers, that the tone follows the
 * result instead of congratulating a broken tenant, and that the progress list
 * carries no per-step annotations.
 *
 * Run: npx tsx scripts/check-scan-complete.tsx
 */

import assert from "node:assert/strict";
import React from "react";
import { renderToString } from "react-dom/server";
import { RunProgress } from "../src/components/run-progress";
import { ScanComplete } from "../src/components/scan-complete";
import { liveStepList } from "../src/lib/run-steps";
import type { TenantSummary } from "../src/lib/analyzer";

/** renderToString inserts `<!-- -->` between adjacent nodes; normalize so
 * assertions match the text a user reads. */
function text(node: React.ReactElement): string {
  return renderToString(node)
    .replace(/<!--\s*-->/g, "")
    .replace(/<[^>]+>/g, " ")
    .replace(/&quot;/g, '"')
    .replace(/&#x27;|&apos;/g, "'")
    .replace(/&amp;/g, "&")
    .replace(/\s+/g, " ")
    .trim();
}

function summary(over: Partial<TenantSummary> = {}): TenantSummary {
  return {
    totalPolicies: 24,
    enabledPolicies: 19,
    reportOnlyPolicies: 3,
    disabledPolicies: 2,
    totalFindings: 12,
    criticalFindings: 0,
    highFindings: 2,
    mediumFindings: 4,
    lowFindings: 6,
    infoFindings: 0,
    ...over,
  };
}

function complete(props: Partial<React.ComponentProps<typeof ScanComplete>> = {}) {
  return text(
    <ScanComplete
      summary={summary()}
      score={88}
      grade="A-"
      steps={12}
      seconds={48}
      signInScanRan={true}
      onRescanWithSignInLogs={() => {}}
      onDismiss={() => {}}
      {...props}
    />
  );
}

const checks: Array<[string, () => void]> = [
  [
    "a clean tenant is told so, with the counts and the duration",
    () => {
      const out = complete();
      assert.match(out, /Analysis complete/);
      assert.match(out, /No critical findings/);
      assert.match(out, /24 policies read in 48s/);
      assert.match(out, /Grade A-/);
      assert.match(out, /12 steps complete/);
    },
  ],
  [
    "criticals get named, not celebrated",
    () => {
      const out = complete({
        summary: summary({ criticalFindings: 4, totalFindings: 31 }),
        score: 52,
        grade: "D",
        seconds: 72,
      });
      assert.match(out, /4 critical findings need attention/);
      assert.ok(!/No critical findings/.test(out));
      assert.match(out, /24 policies read in 1m 12s/);
    },
  ],
  [
    "one of a thing reads as one",
    () => {
      const out = complete({
        summary: summary({ criticalFindings: 1, totalPolicies: 1 }),
      });
      assert.match(out, /1 critical finding needs attention/);
      assert.match(out, /1 policy read/);
    },
  ],
  [
    "a whole number of minutes drops the seconds",
    () => {
      assert.match(complete({ seconds: 120 }), /read in 2m\./);
      assert.match(complete({ seconds: 61 }), /read in 1m 1s\./);
      assert.match(complete({ seconds: 1 }), /read in 1s\./);
    },
  ],
  [
    "a skipped scan says so and offers the re-scan",
    () => {
      const out = complete({ signInScanRan: false });
      assert.match(out, /Sign-in log scan skipped/);
      assert.match(out, /Re-scan with sign-in logs/);
    },
  ],
  [
    "offline runs mention the skip but do not offer a live re-scan",
    () => {
      const out = complete({ signInScanRan: false, onRescanWithSignInLogs: null });
      assert.match(out, /Sign-in log scan skipped/);
      assert.ok(!/Re-scan with sign-in logs/.test(out));
    },
  ],
  [
    "a scan that ran says nothing about skipping",
    () => {
      const out = complete({ signInScanRan: true });
      assert.ok(!/skipped/i.test(out));
    },
  ],
  [
    "the progress list annotates no individual step",
    () => {
      const steps = liveStepList(true);
      const out = text(<RunProgress steps={steps} current={steps[5]} />);
      assert.ok(!/slowest/i.test(out));
      assert.ok(!/heaviest/i.test(out));
    },
  ],
  [
    "progress counts the current step, and reports a skip in the footnote",
    () => {
      const steps = liveStepList(false);
      const out = text(
        <RunProgress steps={steps} current={steps[2]} note="sign-in log scan skipped" />
      );
      assert.match(out, new RegExp(`Step 3 of ${steps.length}`));
      assert.match(out, /sign-in log scan skipped/);
    },
  ],
  [
    "an unlisted label still renders as the running step",
    () => {
      const steps = liveStepList(true);
      const out = text(<RunProgress steps={steps} current="Something unexpected" />);
      assert.match(out, /Something unexpected/);
      assert.match(out, new RegExp(`Step 1 of ${steps.length}`));
    },
  ],
];

let failed = 0;
for (const [name, fn] of checks) {
  try {
    fn();
    console.log(`  ok   ${name}`);
  } catch (e) {
    failed += 1;
    console.error(`  FAIL ${name}`);
    console.error(`       ${e instanceof Error ? e.message : String(e)}`);
  }
}

console.log(`\n${checks.length - failed}/${checks.length} checks passed`);
if (failed > 0) process.exit(1);
