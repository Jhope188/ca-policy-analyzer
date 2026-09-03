/**
 * The scope set and the step list must agree, or the UI shows a step that never
 * completes - or asks for AuditLog.Read.All on a run that never uses it.
 * Run: npx tsx scripts/check-run-steps.ts
 */

import assert from "node:assert/strict";
import { graphScopes, scopesFor } from "../src/lib/msal-config";
import { RUN_STEPS, liveStepList, offlineStepList } from "../src/lib/run-steps";

const checks: Array<[string, () => void]> = [
  [
    "scan off asks for three read scopes, none of them AuditLog",
    () => {
      const scopes = scopesFor(false);
      assert.equal(scopes.length, 3);
      assert.ok(!scopes.includes(graphScopes.auditLogRead));
      assert.ok(scopes.includes(graphScopes.policyRead));
    },
  ],
  [
    "scan on adds AuditLog.Read.All and nothing else",
    () => {
      const scopes = scopesFor(true);
      assert.equal(scopes.length, 4);
      assert.ok(scopes.includes(graphScopes.auditLogRead));
      assert.deepEqual(scopes.slice(0, 3), scopesFor(false));
    },
  ],
  [
    "scan off drops the sign-in step from the list, keeps every other one",
    () => {
      const on = liveStepList(true);
      const off = liveStepList(false);
      assert.ok(on.includes(RUN_STEPS.signInLogs));
      assert.ok(!off.includes(RUN_STEPS.signInLogs));
      assert.equal(off.length, on.length - 1);
      assert.deepEqual(off, on.filter((s) => s !== RUN_STEPS.signInLogs));
    },
  ],
  [
    "every label is unique - indexOf locates the current step",
    () => {
      for (const list of [liveStepList(true), liveStepList(false), offlineStepList]) {
        assert.equal(new Set(list).size, list.length);
      }
    },
  ],
  [
    "the offline list has no Graph steps and does not promise a sign-in scan",
    () => {
      assert.equal(offlineStepList[0], RUN_STEPS.parseOffline);
      assert.ok(!offlineStepList.includes(RUN_STEPS.signInLogs));
      assert.ok(!offlineStepList.includes(RUN_STEPS.policies));
    },
  ],
  [
    "the analysis tail is identical live and offline - same emitters run it",
    () => {
      const tail = [RUN_STEPS.analyzePolicies, RUN_STEPS.templates, RUN_STEPS.posture];
      assert.deepEqual(offlineStepList.slice(-3), tail);
      assert.deepEqual(liveStepList(true).slice(-3), tail);
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
