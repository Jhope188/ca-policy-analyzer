/**
 * Offline export JSON -> context -> findings -> rendered HTML.
 * Run: npx tsx scripts/check-findings-render.tsx
 */

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import React from "react";
import { renderToString } from "react-dom/server";
import {
  buildTenantContextFromOfflineExport,
  type OfflineExportPayload,
} from "../src/lib/offline-import";
import {
  analyzeSignInAppGap,
  buildCreateServicePrincipalsScript,
  SIGNIN_APP_GAP_CATEGORY,
} from "../src/lib/signin-app-gap";
import {
  FindingsList,
  DiscoveredAppsBlock,
  blockingPolicies,
  summarizeObserved,
} from "../src/components/findings-list";
import {
  analyzeAllPolicies,
  withExtraFindings,
  type DiscoveredAppDetail,
  type Finding,
} from "../src/lib/analyzer";

/** renderToString splits adjacent nodes with `<!-- -->` and escapes quotes. */
function text(html: string): string {
  return html
    .replace(/<!--\s*-->/g, "")
    .replace(/<[^>]+>/g, " ")
    .replace(/&quot;/g, '"')
    .replace(/&#x27;|&apos;/g, "'")
    .replace(/&amp;/g, "&")
    .replace(/\s+/g, " ");
}

const fixturePath = path.join(
  path.dirname(new URL(import.meta.url).pathname),
  "../docs/fixtures/offline-export-with-signin-apps.json"
);
const payload = JSON.parse(
  fs.readFileSync(fixturePath, "utf8")
) as OfflineExportPayload;

const ctx = buildTenantContextFromOfflineExport(payload);
const gap = analyzeSignInAppGap(ctx);

const findingsHtml = renderToString(
  React.createElement(FindingsList, {
    findings: gap.findings,
    title: "All Findings",
    tenantDisplayName: ctx.tenantDisplayName,
    tenantId: ctx.tenantId,
  })
);
const blockHtml = renderToString(
  React.createElement(DiscoveredAppsBlock, {
    apps: gap.apps,
    tenantDisplayName: ctx.tenantDisplayName,
    tenantId: ctx.tenantId,
  })
);
const blockText = text(blockHtml);

const manyApps: DiscoveredAppDetail[] = Array.from({ length: 30 }, (_, i) => ({
  ...gap.apps[i % gap.apps.length],
  appId: `aaaaaaaa-0000-0000-0000-${String(i).padStart(12, "0")}`,
  displayName: `Bulk app ${i}`,
}));
const bulkText = text(
  renderToString(React.createElement(DiscoveredAppsBlock, { apps: manyApps }))
);

const script = buildCreateServicePrincipalsScript(gap.apps, {
  tenantDisplayName: ctx.tenantDisplayName,
  generatedAt: "2026-09-02T00:00:00.000Z",
});

const checks: Array<[string, () => void]> = [
  [
    "an app that already has a service principal is filtered out",
    () => {
      assert.equal(gap.apps.length, 3);
      assert.ok(
        !gap.apps.some((a) => a.appId.startsWith("44444444")),
        "the fixture's existing service principal must not be reported as missing"
      );
    },
  ],
  [
    "severities are graded from the impact analysis",
    () => {
      const byName = Object.fromEntries(gap.apps.map((a) => [a.displayName, a]));
      assert.equal(byName["Microsoft Azure CLI"].severity, "critical");
      assert.equal(byName["Microsoft Office"].severity, "critical");
      assert.equal(byName["Unknown app"].severity, "info");
      assert.equal(byName["Unknown app"].isWorkloadIdentity, true);
      assert.equal(byName["Unknown app"].seenIn, "Service principal");
    },
  ],
  [
    "unresolvable app IDs still get a label, never a bare GUID",
    () => {
      assert.equal(
        gap.apps.find((a) => a.appId.startsWith("99999999"))?.displayName,
        "Unknown app"
      );
      assert.equal(
        gap.apps.find((a) => a.appId.startsWith("d3590ed6"))?.displayName,
        "Microsoft Office"
      );
    },
  ],
  [
    "only one finding carries the app list - subsets reference it in text",
    () => {
      const withApps = gap.findings.filter((f) => f.discoveredApps?.length);
      assert.equal(withApps.length, 1);
      assert.equal(gap.findings.length, 3);
      const bypass = gap.findings.find((f) => f.title.includes("bypass apps"));
      assert.ok(bypass?.description.includes("Microsoft Azure CLI"));
      const phantom = gap.findings.find((f) => f.title.includes("does not exist"));
      assert.ok(
        phantom?.description.includes("is excluded by Fixture - MFA except Azure CLI")
      );
    },
  ],
  [
    "the renamed category reaches the UI",
    () => {
      assert.ok(text(findingsHtml).includes(SIGNIN_APP_GAP_CATEGORY));
      assert.ok(!findingsHtml.includes("Enterprise apps bypassing"));
    },
  ],
  [
    "the decision summary renders before the app list",
    () => {
      assert.ok(
        blockHtml.indexOf("Before you create these") <
          blockHtml.indexOf("Apps without a service principal"),
        "the summary and buttons must come first - the list buries them otherwise"
      );
    },
  ],
  [
    "banner counts match the analyzer summary exactly",
    () => {
      assert.equal(gap.summary.wouldBlock, 1);
      assert.match(blockText, /1 could be blocked/);
      assert.equal(gap.summary.stillUncovered, 1);
      assert.match(blockText, /1 still unreached/);
      assert.ok(!blockText.includes("controls enforced"));
    },
  ],
  [
    "both script actions are offered",
    () => {
      assert.ok(blockText.includes("Download PowerShell script"));
      assert.ok(blockText.includes("Copy script"));
    },
  ],
  [
    "worst severity tier open, lower tiers collapsed",
    () => {
      assert.ok(blockText.includes("Needs a decision first"));
      assert.ok(blockText.includes("Microsoft Azure CLI"), "critical tier open");
      assert.ok(
        !blockText.includes("Unknown app"),
        "the medium tier must start collapsed"
      );
    },
  ],
  [
    "a long list folds instead of dumping every row",
    () => {
      assert.match(bulkText, /Show \d+ more/);
      const rendered = (bulkText.match(/Bulk app \d+/g) ?? []).length;
      assert.ok(
        rendered <= 8,
        `expected at most 8 rows before the fold, rendered ${rendered}`
      );
    },
  ],
  [
    "the warning is stated once, not four times over",
    () => {
      const finding = gap.findings.find((f) => f.discoveredApps?.length)!;
      const words = (t: string) => t.split(/\s+/).length;
      assert.ok(
        words(finding.description) < 110,
        `description is ${words(finding.description)} words`
      );
      assert.ok(
        words(finding.recommendation) < 30,
        `recommendation is ${words(finding.recommendation)} words`
      );
      for (const text of [finding.description, finding.recommendation]) {
        assert.ok(!/in waves/.test(text));
        assert.ok(!/report-only first/.test(text));
      }
      assert.ok(blockText.includes("create in\n              waves") || /create in\s+waves/.test(blockText));
    },
  ],
  [
    "no -IncludeBlocked switch - the UI already made that decision visible",
    () => {
      assert.ok(!script.includes("IncludeBlocked"));
      assert.ok(!script.includes("$blockedAppIds"));
      assert.ok(!blockText.includes("IncludeBlocked"));

      const entries = script.match(/^\s+@\{ AppId = .*$/gm) ?? [];
      assert.equal(entries.length, gap.apps.length);
      assert.ok(!/continue\s*$/m.test(script.split("foreach")[0] ?? ""));

      const blockedEntry = entries.find((e) => e.includes("Azure CLI"));
      assert.match(blockedEntry ?? "", /# BLOCKED BY: Fixture - Block legacy auth/);
      assert.equal(
        entries.filter((e) => e.includes("BLOCKED BY")).length,
        gap.summary.wouldBlock
      );
      assert.ok(blockText.includes("BLOCKED BY"));
      assert.ok(script.includes("-WhatIf"));
    },
  ],
  [
    "per-app impact surfaces only blocking policies",
    () => {
      const byName = Object.fromEntries(gap.apps.map((a) => [a.displayName, a]));

      const cli = blockingPolicies(byName["Microsoft Azure CLI"].predictedImpact);
      assert.equal(cli.length, 1);
      assert.equal(cli[0].policyName, "Fixture - Block legacy auth");
      assert.ok(cli[0].blocks);

      assert.equal(
        blockingPolicies(byName["Microsoft Office"].predictedImpact).length,
        0
      );
      assert.ok(
        byName["Microsoft Office"].predictedImpact.some(
          (i) => i.state === "enabled" && i.verdict === "willApply"
        ),
        "…yet policies do apply - proving the filter is by blocking, not by applying"
      );

      for (const app of gap.apps) {
        for (const i of blockingPolicies(app.predictedImpact)) {
          assert.equal(i.state, "enabled");
          assert.ok(i.blocks);
          assert.notEqual(i.verdict, "willNotApply");
        }
      }
    },
  ],
  [
    "observed policies are condensed to a count plus the ones that fired",
    () => {
      const cli = gap.apps.find((a) => a.displayName === "Microsoft Azure CLI")!;
      const observed = summarizeObserved(cli.observedPolicies);
      assert.ok(observed);
      assert.equal(observed.total, 1);
      assert.equal(observed.outsideTargetResources, 1);
      assert.equal(observed.applied.length, 0);
      assert.equal(summarizeObserved(undefined), null);
      assert.equal(summarizeObserved([]), null);
    },
  ],
  [
    "the removed impact sections stay removed",
    () => {
      const source = fs.readFileSync(
        new URL("../src/components/findings-list.tsx", import.meta.url).pathname,
        "utf8"
      );
      for (const gone of [
        "Would enforce controls",
        "Might apply",
        "Report-only",
        "No effect",
        "Conditions not satisfied",
      ]) {
        assert.ok(
          !source.includes(gone),
          `"${gone}" was cut as noise and should not return`
        );
      }
    },
  ],
  [
    "each app's evidence link matches the event type it was seen with",
    () => {
      const request = (app: DiscoveredAppDetail) =>
        decodeURIComponent(
          new URL(app.logQueryUrl).searchParams.get("request") ?? ""
        );
      const byName = Object.fromEntries(gap.apps.map((a) => [a.displayName, a]));

      assert.ok(
        !request(byName["Microsoft Azure CLI"]).includes("signInEventTypes")
      );
      // Without its clause the query returns an empty result for this app
      assert.ok(
        request(byName["Unknown app"]).includes(
          "signInEventTypes/any(t: t eq 'servicePrincipal')"
        )
      );
      for (const app of gap.apps) {
        assert.ok(
          request(app).includes(`appId eq '${app.appId}'`),
          `${app.displayName} link must filter on its own app ID`
        );
      }
    },
  ],
  [
    "script contains every app in one loopable array",
    () => {
      assert.ok(script.includes("$appsToCreate = @("));
      for (const app of gap.apps) {
        assert.ok(
          script.includes(`AppId = '${app.appId}'`),
          `${app.displayName} must be in the array, not commented out`
        );
      }
      const entries = script.match(/^\s+@\{ AppId = .*$/gm) ?? [];
      assert.equal(entries.length, gap.apps.length);
      for (const entry of entries) {
        assert.match(
          entry,
          /^\s+@\{ AppId = '[^']+'; Name = '.*' \}(   # BLOCKED BY: .+)?$/
        );
      }
      assert.match(script, /# BLOCKED BY: /);
    },
  ],
  [
    "script talks to Graph directly - Connect-MgGraph is the only cmdlet",
    () => {
      assert.ok(script.includes("Connect-MgGraph"));
      assert.ok(script.includes("Invoke-MgGraphRequest -Method GET"));
      assert.ok(script.includes("Invoke-MgGraphRequest -Method POST"));
      for (const cmdlet of [
        "Get-MgServicePrincipal",
        "New-MgServicePrincipal",
        "Microsoft.Graph.Applications",
      ]) {
        assert.ok(!script.includes(cmdlet), `${cmdlet} should no longer be used`);
      }
      assert.ok(script.includes("Import-Module Microsoft.Graph.Authentication"));
    },
  ],
  [
    "script defaults to a dry run and carries the warning",
    () => {
      assert.ok(script.includes("[CmdletBinding(SupportsShouldProcess)]"));
      assert.ok(script.includes("-WhatIf"));
      assert.ok(script.includes("READ THIS FIRST"));
    },
  ],
  [
    "generated script carries no author or organization attribution",
    () => {
      // The pattern, not bare words: "409 - created by a parallel run" is code
      const attribution = /^\s*#?\s*(created by|author|organization|company)\s*:/im;
      const match = script.match(attribution);
      assert.equal(
        match,
        null,
        `script must not carry attribution, found: ${match?.[0]?.trim()}`
      );
      assert.ok(script.includes("Generated by CA Policy Analyzer"));
    },
  ],
  [
    "an empty signInApps export means scanned-and-clean, not unavailable",
    () => {
      // Regression: an empty array used to read as "never scanned"
      const clean = buildTenantContextFromOfflineExport({
        ...payload,
        signInApps: [],
      });
      assert.ok(clean.unregisteredSignInApps, "empty export must still be a result");
      assert.equal(clean.unregisteredSignInApps!.apps.length, 0);

      const cleanGap = analyzeSignInAppGap(clean);
      assert.equal(cleanGap.scanUnavailable, false);
      assert.ok(!cleanGap.findings.some((f) => /not available/i.test(f.title)));

      const rest = { ...payload };
      delete (rest as { signInApps?: unknown }).signInApps;
      const absent = buildTenantContextFromOfflineExport(rest);
      assert.equal(absent.unregisteredSignInApps, undefined);
      assert.equal(analyzeSignInAppGap(absent).scanUnavailable, true);
    },
  ],
  [
    "merging tenant-wide findings re-derives the summary and score",
    () => {
      // Regression: summary and scores were built from the pre-merge list
      const base = analyzeAllPolicies(ctx);
      const extra: Finding[] = [
        {
          id: "X-1",
          policyId: "tenant-wide",
          policyName: "Tenant-Wide Analysis",
          severity: "critical",
          category: SIGNIN_APP_GAP_CATEGORY,
          title: "extra critical",
          description: "",
          recommendation: "",
        },
      ];
      const merged = withExtraFindings(ctx, base, extra);

      assert.equal(merged.findings.length, base.findings.length + 1);
      assert.equal(
        merged.tenantSummary.criticalFindings,
        base.tenantSummary.criticalFindings + 1
      );
      assert.equal(merged.tenantSummary.totalFindings, merged.findings.length);
      assert.ok(merged.overallScore <= base.overallScore);

      assert.equal(withExtraFindings(ctx, base, []), base);
    },
  ],
  [
    "no placeholder values leak into the UI",
    () => {
      assert.ok(!/NaN|>undefined<|>null</.test(blockHtml + findingsHtml));
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
