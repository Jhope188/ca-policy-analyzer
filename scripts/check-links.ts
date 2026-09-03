/**
 * The links an admin clicks to verify a finding, so a broken one undermines it.
 * Structure is asserted offline; --network only proves the hosts answer, never
 * that a fragment resolves.
 *
 * Run: npx tsx scripts/check-links.ts [--network]
 */

import assert from "node:assert/strict";
import fs from "node:fs";
import {
  ENTRA_SIGNIN_LOGS_URL,
  ENTRA_SIGNIN_LOGS_PATH,
  buildSignInLogQueryUrl,
} from "../src/lib/graph-client";

const APP_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46";
const WINDOW_START = "2026-08-03T00:00:00.000Z";

const unqualified = buildSignInLogQueryUrl(APP_ID, WINDOW_START);
const interactive = buildSignInLogQueryUrl(APP_ID, WINDOW_START, "interactiveUser");
const nonInteractive = buildSignInLogQueryUrl(APP_ID, WINDOW_START, "nonInteractiveUser");
const servicePrincipal = buildSignInLogQueryUrl(APP_ID, WINDOW_START, "servicePrincipal");
const managedIdentity = buildSignInLogQueryUrl(APP_ID, WINDOW_START, "managedIdentity");

const checks: Array<[string, () => void]> = [
  [
    "Graph Explorer URL parses and targets the documented host and path",
    () => {
      const u = new URL(interactive);
      assert.equal(u.protocol, "https:");
      assert.equal(u.host, "developer.microsoft.com");
      assert.equal(u.pathname, "/graph/graph-explorer");
    },
  ],
  [
    "carries every parameter Microsoft's own doc links use",
    () => {
      const p = new URL(interactive).searchParams;
      assert.ok(p.get("request"), "request");
      assert.equal(p.get("method"), "GET");
      assert.equal(p.get("version"), "beta");
      assert.equal(p.get("GraphUrl"), "https://graph.microsoft.com");
      assert.ok(p.get("headers"), "headers");
    },
  ],
  [
    "the request round-trips to a valid Graph query for this app",
    () => {
      const request = new URL(interactive).searchParams.get("request")!;
      assert.ok(request.startsWith("auditLogs/signIns?"));
      assert.ok(
        request.includes(`appId eq '${APP_ID}'`),
        "the app ID must survive encoding unmangled"
      );
      assert.ok(request.includes(`createdDateTime ge ${WINDOW_START}`));
      assert.ok(request.includes("$top=50"));
      // Double-encoding was a real bug here
      assert.ok(!request.includes("%27"), "app ID quotes must not be double-encoded");
      assert.ok(!request.includes("%24"), "$ must not be double-encoded");
    },
  ],
  [
    "headers decode to the Prefer header the beta endpoint needs",
    () => {
      const raw = new URL(interactive).searchParams.get("headers")!;
      const decoded = JSON.parse(Buffer.from(raw, "base64").toString("utf8"));
      assert.deepEqual(decoded, [
        { name: "Prefer", value: "include-unknown-enum-members" },
      ]);
    },
  ],
  [
    "every non-interactive event type gets its own clause",
    () => {
      const req = (url: string) =>
        new URL(url).searchParams.get("request")!;
      for (const [url, type] of [
        [nonInteractive, "nonInteractiveUser"],
        [servicePrincipal, "servicePrincipal"],
        [managedIdentity, "managedIdentity"],
      ] as const) {
        assert.ok(
          req(url).includes(`signInEventTypes/any(t: t eq '${type}')`),
          `${type} clause missing`
        );
      }
    },
  ],
  [
    "interactive carries no clause - the endpoint returns it by default",
    () => {
      const req = (url: string) => new URL(url).searchParams.get("request")!;
      assert.ok(!req(interactive).includes("signInEventTypes"));
      // Used for apps with no evidence row; asserting "interactive" there is
      // what made those links come back empty.
      assert.equal(req(unqualified), req(interactive));
    },
  ],
  [
    "the sign-in logs link uses the live-captured Entra blade",
    () => {
      const u = new URL(ENTRA_SIGNIN_LOGS_URL);
      assert.equal(u.host, "entra.microsoft.com");
      // A fragment is never sent to the server, so it can't be verified
      // automatically. Pin the live-captured blade and fail loudly on a swap.
      assert.ok(u.hash.startsWith("#view/Microsoft_AAD_IAM/SignInLogsList.ReactView"));
      assert.ok(u.hash.includes("showApplicationSignIns~/true"));

      for (const dead of ["SignInEventsV3", "ActiveDirectoryMenuBlade"]) {
        assert.ok(
          !ENTRA_SIGNIN_LOGS_URL.includes(dead),
          `${dead} does not resolve and must not come back`
        );
      }
      // The link must not change the reader's portal session
      assert.equal(u.search, "", "no feature.* query flags");

      const source = fs.readFileSync(
        new URL("../src/components/findings-list.tsx", import.meta.url).pathname,
        "utf8"
      );
      assert.ok(!source.includes("SignInEventsV3"));
      assert.ok(!source.includes("portal.azure.com"));
      assert.ok(ENTRA_SIGNIN_LOGS_PATH.includes("Sign-in logs"));
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

async function probeHosts(): Promise<number> {
  console.log("\n  network reachability (hosts only, not fragments):");
  let networkFailures = 0;
  for (const url of [
    "https://developer.microsoft.com/graph/graph-explorer",
    new URL(ENTRA_SIGNIN_LOGS_URL).origin,
  ]) {
    try {
      const res = await fetch(url, { redirect: "follow" });
      // A 403 is the host responding, which is all this can establish
      const ok = res.status < 500;
      console.log(`  ${ok ? "ok  " : "FAIL"} ${url} -> ${res.status}`);
      if (!ok) networkFailures += 1;
    } catch (e) {
      console.error(`  FAIL ${url} -> ${e instanceof Error ? e.message : e}`);
      networkFailures += 1;
    }
  }
  return networkFailures;
}

async function main() {
  if (process.argv.includes("--network")) {
    failed += await probeHosts();
  }
  console.log(`\n${failed === 0 ? "all" : `${failed} failed —`} link checks done`);
  if (failed > 0) process.exit(1);
}

void main();
