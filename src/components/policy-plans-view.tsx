"use client";

import { useMemo, useState } from "react";
import {
  ConditionalAccessPolicy,
  ConditionalAccessPolicyPlanWithRules,
  ConditionalAccessPolicyRule,
} from "@/lib/graph-client";
import {
  summarizeConditionSet,
  summarizeControls,
  PLAN_RULE_STATE_LABEL,
  type PlanVisualizerContext,
} from "@/lib/policy-plan-visualizer";
import {
  detectPlanRulePolicyConflicts,
  DECOMMISSION_DOC_URL,
  type PlanRulePolicyConflict,
} from "@/lib/policy-plan-conflict-detector";
import { SeverityBadge } from "@/components/ui-primitives";
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
  AlertTriangle,
  ExternalLink,
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

const CONFLICT_BOX_CLASS: Record<PlanRulePolicyConflict["severity"], string> = {
  critical: "border-red-500/30 bg-red-500/5",
  high: "border-orange-500/30 bg-orange-500/5",
  medium: "border-yellow-500/30 bg-yellow-500/5",
  low: "border-blue-500/30 bg-blue-500/5",
  info: "border-gray-700 bg-gray-800/30",
};

/** Flags that this rule's likely source policy is still active and needs to be turned off to avoid conflicting enforcement. */
function ConflictNotice({ conflict }: { conflict: PlanRulePolicyConflict }) {
  return (
    <div className={cn("mt-3 rounded-lg border p-3", CONFLICT_BOX_CLASS[conflict.severity])}>
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={conflict.severity} />
        <span className="text-sm font-medium text-white">{conflict.title}</span>
      </div>
      <p className="mt-2 text-xs text-gray-300">{conflict.description}</p>
      <p className="mt-2 text-xs font-medium text-gray-100">{conflict.recommendation}</p>
      <p className="mt-2 text-xs text-gray-500">
        Matched policy: <span className="font-mono text-gray-400">{conflict.matchedPolicyDisplayName}</span> (
        {PLAN_RULE_STATE_LABEL[conflict.matchedPolicyState] ?? conflict.matchedPolicyState}) ·{" "}
        {conflict.matchType === "exact-name" ? "same name" : `~${conflict.confidence}% field match`}
      </p>
    </div>
  );
}

function RuleCard({
  rule,
  context,
  conflict,
}: {
  rule: ConditionalAccessPolicyRule;
  context: PlanVisualizerContext;
  conflict?: PlanRulePolicyConflict;
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
            {conflict && (
              <span title={conflict.title}>
                <AlertTriangle className="h-4 w-4 shrink-0 text-orange-400" />
              </span>
            )}
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
          {conflict && <ConflictNotice conflict={conflict} />}
          <p className="mt-3 text-xs text-gray-700 font-mono">ID: {rule.id}</p>
        </div>
      )}
      {!expanded && conflict && (
        <div className="border-t border-gray-800 p-3">
          <ConflictNotice conflict={conflict} />
        </div>
      )}
    </div>
  );
}

function PlanCard({
  plan,
  context,
  resolverMaps,
  conflictsByRuleId,
}: {
  plan: ConditionalAccessPolicyPlanWithRules;
  context: PlanVisualizerContext;
  resolverMaps?: GuidResolverMaps;
  conflictsByRuleId: Map<string, PlanRulePolicyConflict>;
}) {
  const [expanded, setExpanded] = useState(true);
  const sharedSummary = summarizeConditionSet(plan.sharedConditions, context);
  const planConflictCount = plan.rules.filter((r) => conflictsByRuleId.has(r.id)).length;

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
            {planConflictCount > 0 && (
              <span className="inline-flex items-center gap-1 rounded-full border border-orange-500/30 bg-orange-500/10 px-2 py-0.5 text-xs font-medium text-orange-400">
                <AlertTriangle className="h-3 w-3" />
                {planConflictCount} {planConflictCount === 1 ? "rule needs" : "rules need"} the original policy turned off
              </span>
            )}
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
                  <RuleCard key={rule.id} rule={rule} context={context} conflict={conflictsByRuleId.get(rule.id)} />
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
  policies,
  context,
  resolverMaps,
}: {
  /** Undefined when the scan was skipped or the tenant doesn't expose the preview endpoint. */
  plans: ConditionalAccessPolicyPlanWithRules[] | undefined;
  /** Standalone CA policies for this tenant - used to flag plan rules whose likely source policy is still active. */
  policies: ConditionalAccessPolicy[];
  context: PlanVisualizerContext;
  resolverMaps?: GuidResolverMaps;
}) {
  const conflicts = useMemo(
    () => (plans ? detectPlanRulePolicyConflicts(plans, policies) : []),
    [plans, policies]
  );
  const conflictsByRuleId = useMemo(
    () => new Map(conflicts.map((c) => [c.ruleId, c])),
    [conflicts]
  );

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

      {conflicts.length > 0 && (
        <div className="flex items-start gap-3 rounded-xl border border-orange-500/30 bg-orange-500/5 p-4">
          <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-orange-400" />
          <div className="text-sm text-gray-300">
            <p className="font-medium text-white">
              {conflicts.length} plan rule{conflicts.length !== 1 ? "s" : ""} likely{" "}
              {conflicts.length !== 1 ? "still have" : "still has"} their original policy active
            </p>
            <p className="mt-1 text-gray-400">
              The biggest hurdle when migrating to policy plans: the original standalone policies
              aren&apos;t changed or removed by migration. They keep evaluating independently
              alongside their plan rule, which can mean redundant - or conflicting - enforcement.
              Decommission (turn off, then delete per your retention policy) each original policy
              once you&apos;ve validated and turned on its matching rule.{" "}
              <a
                href={DECOMMISSION_DOC_URL}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1 underline hover:text-white"
              >
                Learn more <ExternalLink className="h-3 w-3" />
              </a>
            </p>
          </div>
        </div>
      )}

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
            <PlanCard
              key={plan.id}
              plan={plan}
              context={context}
              resolverMaps={resolverMaps}
              conflictsByRuleId={conflictsByRuleId}
            />
          ))}
        </div>
      )}
    </div>
  );
}
