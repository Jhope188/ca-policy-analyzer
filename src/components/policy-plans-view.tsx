"use client";

import { useState } from "react";
import {
  ConditionalAccessPolicyPlanWithRules,
  ConditionalAccessPolicyRule,
} from "@/lib/graph-client";
import {
  summarizeConditionSet,
  summarizeControls,
  PLAN_RULE_STATE_LABEL,
  type PlanVisualizerContext,
} from "@/lib/policy-plan-visualizer";
import { resolveGuidList, type GuidResolverMaps } from "@/lib/role-names";
import { cn } from "@/lib/utils";
import {
  ChevronDown,
  ChevronRight,
  Users,
  Cloud,
  Filter,
  ShieldCheck,
  Clock,
  Tags,
  FlaskConical,
} from "lucide-react";

function SummaryRow({
  icon: Icon,
  label,
  value,
  emptyText = "Not set",
}: {
  icon: typeof Users;
  label: string;
  value: string | string[] | null;
  emptyText?: string;
}) {
  const items = Array.isArray(value) ? value : value ? [value] : [];
  return (
    <div className="flex items-start gap-2">
      <Icon className="mt-0.5 h-4 w-4 shrink-0 text-gray-500" />
      <div>
        <p className="text-xs font-medium text-gray-400">{label}</p>
        {items.length > 0 ? (
          <ul className="mt-0.5">
            {items.map((item, i) => (
              <li key={i} className="text-sm text-gray-300">
                {item}
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-gray-600">{emptyText}</p>
        )}
      </div>
    </div>
  );
}

function RuleCard({
  rule,
  context,
}: {
  rule: ConditionalAccessPolicyRule;
  context: PlanVisualizerContext;
}) {
  const [expanded, setExpanded] = useState(false);
  const conditionSummary = summarizeConditionSet(rule.conditions, context);
  const controlsSummary = summarizeControls(rule.controls);

  return (
    <div className="rounded-lg border border-gray-800 bg-gray-950/40">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex w-full items-center gap-3 p-3 text-left"
      >
        {expanded ? (
          <ChevronDown className="h-4 w-4 shrink-0 text-gray-500" />
        ) : (
          <ChevronRight className="h-4 w-4 shrink-0 text-gray-500" />
        )}
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span
              className={cn(
                "text-xs font-medium rounded px-1.5 py-0.5",
                rule.state === "enabled"
                  ? "bg-green-500/10 text-green-400"
                  : rule.state === "enabledForReportingButNotEnforced"
                  ? "bg-yellow-500/10 text-yellow-400"
                  : "bg-gray-800 text-gray-500"
              )}
            >
              {PLAN_RULE_STATE_LABEL[rule.state] ?? rule.state}
            </span>
            <h4 className="text-sm font-semibold text-white truncate">
              {rule.displayName}
            </h4>
          </div>
          <div className="mt-1 flex flex-wrap gap-3 text-xs text-gray-500">
            <span>{conditionSummary.targetUsers ?? "Inherited from plan"}</span>
            <span>→</span>
            <span>{conditionSummary.targetApps ?? "Inherited from plan"}</span>
            <span>→</span>
            <span>
              {controlsSummary.grantControls.length > 0
                ? controlsSummary.grantControls.join(", ")
                : "No grant controls"}
            </span>
          </div>
        </div>
      </button>

      {expanded && (
        <div className="border-t border-gray-800 p-3">
          {rule.description && (
            <p className="mb-3 text-xs text-gray-400">{rule.description}</p>
          )}
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
            <SummaryRow icon={Users} label="Users (rule-level)" value={conditionSummary.targetUsers} emptyText="None added - plan's shared targeting applies" />
            <SummaryRow icon={Cloud} label="Cloud Apps (rule-level)" value={conditionSummary.targetApps} emptyText="None added - plan's shared targeting applies" />
            <SummaryRow icon={Filter} label="Conditions (rule-level)" value={conditionSummary.conditions} emptyText="None" />
            <SummaryRow icon={ShieldCheck} label="Grant Controls" value={controlsSummary.grantControls} emptyText="No grant controls" />
            <SummaryRow icon={Clock} label="Session Controls" value={controlsSummary.sessionControls} emptyText="No session controls" />
          </div>
          <p className="mt-3 text-xs text-gray-700 font-mono">ID: {rule.id}</p>
        </div>
      )}
    </div>
  );
}

function PlanCard({
  plan,
  context,
  resolverMaps,
}: {
  plan: ConditionalAccessPolicyPlanWithRules;
  context: PlanVisualizerContext;
  resolverMaps?: GuidResolverMaps;
}) {
  const [expanded, setExpanded] = useState(true);
  const sharedSummary = summarizeConditionSet(plan.sharedConditions, context);

  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex w-full items-center gap-3 p-4 text-left"
      >
        {expanded ? (
          <ChevronDown className="h-5 w-5 shrink-0 text-gray-500" />
        ) : (
          <ChevronRight className="h-5 w-5 shrink-0 text-gray-500" />
        )}
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="text-sm font-semibold text-white truncate">
              {plan.displayName}
            </h3>
            <span className="text-xs text-gray-500">
              {plan.rules.length} rule{plan.rules.length !== 1 ? "s" : ""}
            </span>
          </div>
          {plan.description && (
            <p className="mt-1 text-xs text-gray-500">{plan.description}</p>
          )}
        </div>
      </button>

      {expanded && (
        <div className="border-t border-gray-800 p-4 space-y-4">
          {(plan.tags?.length || plan.owners?.length) ? (
            <div className="flex flex-wrap gap-4 text-xs">
              {plan.tags && plan.tags.length > 0 && (
                <div className="flex items-start gap-1.5">
                  <Tags className="mt-0.5 h-3.5 w-3.5 shrink-0 text-gray-500" />
                  <span className="text-gray-400">{plan.tags.join(", ")}</span>
                </div>
              )}
              {plan.owners && plan.owners.length > 0 && (
                <div className="flex items-start gap-1.5">
                  <Users className="mt-0.5 h-3.5 w-3.5 shrink-0 text-gray-500" />
                  <span className="text-gray-400">
                    Owners: {resolveGuidList(plan.owners, resolverMaps)}
                  </span>
                </div>
              )}
            </div>
          ) : null}

          <div>
            <h4 className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-2">
              Shared conditions (apply to every rule below)
            </h4>
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 rounded-lg border border-gray-800 bg-gray-950/40 p-3">
              <SummaryRow icon={Users} label="Users" value={sharedSummary.targetUsers} emptyText="Left to each rule" />
              <SummaryRow icon={Cloud} label="Cloud Apps" value={sharedSummary.targetApps} emptyText="Left to each rule" />
              <SummaryRow icon={Filter} label="Other conditions" value={sharedSummary.conditions} emptyText="None" />
            </div>
          </div>

          <div>
            <h4 className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-2">
              Rules
            </h4>
            <div className="space-y-2">
              {plan.rules.length === 0 ? (
                <p className="text-sm text-gray-600">This plan has no rules yet.</p>
              ) : (
                plan.rules.map((rule) => (
                  <RuleCard key={rule.id} rule={rule} context={context} />
                ))
              )}
            </div>
          </div>

          <p className="text-xs text-gray-700 font-mono">
            ID: {plan.id}
            {plan.version != null ? ` · v${plan.version}` : ""}
            {plan.templateId ? ` · template: ${plan.templateId}` : ""}
          </p>
        </div>
      )}
    </div>
  );
}

export function PolicyPlansView({
  plans,
  context,
  resolverMaps,
}: {
  /** Undefined when the scan was skipped or the tenant doesn't expose the preview endpoint. */
  plans: ConditionalAccessPolicyPlanWithRules[] | undefined;
  context: PlanVisualizerContext;
  resolverMaps?: GuidResolverMaps;
}) {
  return (
    <div className="space-y-4">
      <div className="flex items-start gap-3 rounded-xl border border-indigo-500/30 bg-indigo-500/5 p-4">
        <FlaskConical className="mt-0.5 h-5 w-5 shrink-0 text-indigo-400" />
        <div className="text-sm text-gray-300">
          <p className="font-medium text-white">Conditional Access policy plans (preview)</p>
          <p className="mt-1 text-gray-400">
            Policy plans group shared targeting and exclusions across related rules. This is a
            read-only, early look at plan data for this tenant - it doesn&apos;t yet feed the
            Findings, Templates, or CIS tabs.{" "}
            <a
              href="https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-policy-plans"
              target="_blank"
              rel="noreferrer"
              className="underline hover:text-white"
            >
              Learn more
            </a>
            .
          </p>
        </div>
      </div>

      {plans === undefined ? (
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-6 text-sm text-gray-400">
          No policy plan data was collected for this tenant. This can mean the preview feature
          isn&apos;t enabled for this tenant, the signed-in account lacks{" "}
          <code className="text-gray-300">Policy.Read.ConditionalAccess</code>, or the endpoint
          isn&apos;t reachable. Re-scan to try again.
        </div>
      ) : plans.length === 0 ? (
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-6 text-sm text-gray-400">
          No Conditional Access policy plans found in this tenant yet.
        </div>
      ) : (
        <div className="space-y-3">
          {plans.map((plan) => (
            <PlanCard key={plan.id} plan={plan} context={context} resolverMaps={resolverMaps} />
          ))}
        </div>
      )}
    </div>
  );
}
