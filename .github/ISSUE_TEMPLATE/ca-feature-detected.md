---
name: Conditional Access Feature Detected
about: Automated detection of new CA feature from Microsoft Entra What's New
title: '🔔 New Conditional Access Feature Detected - [MONTH YEAR]'
labels: enhancement, conditional-access, needs-review, automated-detection
assignees: ''
---

## 🚨 New Conditional Access Feature Detected

**Source**: [Microsoft Entra What's New](https://learn.microsoft.com/en-us/entra/fundamentals/whats-new)

**Detection Date**: <!-- Auto-filled by workflow -->

---

## 📋 Manual Detection Entry

If manually creating this issue, provide:

### Feature Details
- **Announcement Title**: 
- **Announcement Type**: (Plan for Change / General Availability / Public Preview / Deprecation)
- **Enforcement Date**: 
- **Service Category**: Conditional Access
- **Product Capability**: 

### Impact Assessment
- **Affects Existing Policies**: Yes / No / Maybe
- **Requires Analyzer Update**: Yes / No
- **Estimated Severity**: Critical / High / Medium / Low / Info

### Links
- **MS Learn Article**: 
- **Message Center ID** (if applicable): 

---

## 🤖 Automated Implementation

Once you've reviewed and want to implement:

**Option 1**: Comment `@github-copilot implement this check` on this issue

**Option 2**: Add the label `approved-for-implementation`

The GitHub Copilot coding agent will:
1. Create a new branch
2. Implement the analyzer check based on the details above
3. Update category metadata in findings-list.tsx
4. Update CHANGELOG.md with version bump
5. Open a PR for your review

---

## 📚 Implementation Guidance

### Check Function Template

```typescript
// Add to src/lib/analyzer.ts after existing checks

/**
 * Check: [Feature Name]
 * [Brief description of what this check does]
 * 
 * Reference: [MS Learn URL]
 * Enforcement Date: [Date]
 */
function check[FeatureName](
  policy: ConditionalAccessPolicy,
  context: TenantContext
): Finding[] {
  const findings: Finding[] = [];

  // Only check enabled policies (or remove this if disabled matters)
  if (policy.state === "disabled") return findings;

  // Check if policy targets the relevant user action/app/condition
  const targets[Condition] = policy.conditions.[...];
  
  if (!targets[Condition]) return findings;

  // Identify problematic constraints
  const grant = policy.grantControls;
  const conditions = policy.conditions;
  
  // [Your constraint checks here]

  if ([found issues]) {
    findings.push({
      id: nextFindingId(),
      policyId: policy.id,
      policyName: policy.displayName,
      severity: "[critical|high|medium|low|info]",
      category: "[Category Name]",
      title: "[Finding title]",
      description: "[Detailed description with context]",
      recommendation: "[Actionable remediation steps]",
    });
  }

  return findings;
}
```

### Integration Checklist

- [ ] Add function to `src/lib/analyzer.ts`
- [ ] Add to `analyzeAllPolicies()` call chain (around line 151)
- [ ] Add category to `CATEGORY_META` in `src/components/findings-list.tsx`
- [ ] Update `CHANGELOG.md`:
  - Add to `## [Unreleased]` or new version section
  - Document the new check under `### Added`
- [ ] Test TypeScript compilation: `npx tsc --noEmit`
- [ ] Build app: `npm run build`
- [ ] Commit with conventional commit message: `feat: add [feature name] check`

---

## 🔍 Related Issues

<!-- Link any related issues or PRs here -->

---

**Note**: This template can be used for both automated detections and manual entries.
