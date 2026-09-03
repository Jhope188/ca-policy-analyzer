/**
 * Stale MSAL auth-response detection. A regression here shows up as every Graph
 * call failing with `block_nested_popups` for the rest of the session.
 *
 * Run: npx tsx scripts/check-auth-url.ts
 */

import assert from "node:assert/strict";
import { hasAuthResponseInUrl } from "../src/lib/msal-config";

const checks: Array<[string, () => void]> = [
  [
    "clean URL is not treated as an auth response",
    () => {
      assert.equal(hasAuthResponseInUrl("", ""), false);
      assert.equal(hasAuthResponseInUrl("#", "?"), false);
    },
  ],
  [
    "response in the hash is detected",
    () => {
      assert.equal(
        hasAuthResponseInUrl("#code=abc&state=eyJpZCI6IjEifQ", ""),
        true
      );
    },
  ],
  [
    "response in the query is detected (hybrid format)",
    () => {
      assert.equal(
        hasAuthResponseInUrl("", "?code=abc&state=eyJpZCI6IjEifQ"),
        true
      );
    },
  ],
  [
    "leading # and ? are optional",
    () => {
      assert.equal(hasAuthResponseInUrl("state=x", ""), true);
      assert.equal(hasAuthResponseInUrl("", "state=x"), true);
    },
  ],
  [
    "an error response still counts - it also carries state",
    () => {
      assert.equal(
        hasAuthResponseInUrl("#error=access_denied&state=x", ""),
        true
      );
    },
  ],
  [
    "unrelated fragments and query strings are left alone",
    () => {
      assert.equal(hasAuthResponseInUrl("#dashboard", "?tab=findings"), false);
      // "state" must be its own parameter, not a substring of another one
      assert.equal(hasAuthResponseInUrl("#estate=1", "?statement=2"), false);
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
