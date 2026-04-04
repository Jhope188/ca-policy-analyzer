# CA Policy Analyzer Update - April 4, 2026

## 🚀 New Feature: Windows Hello / Platform SSO Registration Constraint Check

### Summary

The CA Policy Analyzer now detects policies that may **block Windows Hello for Business and macOS Platform SSO credential setup** on new devices, ahead of Microsoft's May 2026 enforcement change.

### Background

**Starting May 2026**, Microsoft will enforce Conditional Access policies targeting the **"Register security info"** user action during Windows Hello for Business and macOS Platform SSO credential provisioning — not just during sign-in.

📢 **Reference**: Microsoft Entra "What's New" - March 2026  
🔗 https://learn.microsoft.com/entra/fundamentals/whats-new#march-2026

### What's New

The analyzer now flags policies with these potentially problematic constraints:

- ✅ **Device compliance requirements** - Will block new device setup (device isn't enrolled yet)
- ✅ **Trusted location requirements** - Will block users setting up devices from home/remote locations
- ✅ **Approved/protected app requirements** - May block setup before apps are installed
- ✅ **Device filter rules** - May not evaluate correctly during initial provisioning

### Severity Levels

- 🔴 **HIGH**: Device compliance or restrictive location requirements (will definitely block users)
- 🟠 **MEDIUM**: App requirements or device filters (may cause setup issues)

### Recommendations Provided

The analyzer suggests:

1. **Separate policies** - One for sign-in (with compliance), one for registration (MFA only)
2. **Temporary Access Pass (TAP)** - Use TAP for new device enrollment flows
3. **Location bypass** - Allow registration from all locations (even if blocking for sign-in)
4. **Report-only mode** - Test impact in April 2026 before May enforcement

### Example Finding

```
Category: Credential Registration Constraints
Severity: HIGH
Title: Policy may block Windows Hello / Platform SSO setup on new devices (May 2026 enforcement)

Description:
Starting May 2026, this policy will be enforced during Windows Hello for Business 
and macOS Platform SSO credential registration (not just sign-in). This policy has 
the following constraints that may prevent users from completing device setup:

• Device compliance: Users provisioning WHfB/Platform SSO on a NEW device cannot 
  satisfy this requirement during initial setup (device isn't enrolled yet)
• Trusted location requirement: Policy requires access from: Corporate HQ. Users 
  setting up credentials from home/remote locations (common for new device setup) 
  will be blocked

Recommendation:
Remove device compliance requirements from this policy or create separate policies 
for sign-in vs registration. Use report-only mode before May 2026 to test impact.
```

### Action Items for Admins

**⏰ Before Late April 2026**:
1. Review any policies targeting "Register security info" in your tenant
2. Use the analyzer to identify potentially problematic constraints
3. Enable **report-only mode** on affected policies to monitor impact
4. Adjust policies or create separate registration policies as recommended

**⚠️ Microsoft's Guidance**:
> "Consider whether users setting up a new device for the first time can satisfy your 
> policy requirements. If your policy requires methods users may not have during initial 
> provisioning, you may need to adjust conditions or add exclusions."

### Technical Details

- **New analyzer function**: `checkCredentialRegistrationConstraints()`
- **Category**: "Credential Registration Constraints"
- **Icon**: 🛡️ ShieldAlert (orange)
- **Files modified**:
  - `src/lib/analyzer.ts` - Added new check logic
  - `src/components/findings-list.tsx` - Added UI category

### Deployment

Changes are now live on GitHub Pages: https://jhope188.github.io/ca-policy-analyzer

---

## 🔍 2026 CA Changes Review

All significant Conditional Access changes through 2026 were reviewed:

- ✅ **May 2026: WHfB/Platform SSO Registration** - Now detected (new check)
- ✅ **January 2026: "All resources" enforcement** - Covered by existing Device Registration Bypass check
- 📋 **October 2025: Soft delete for CA policies** - Operational feature (no analysis needed)
- 📋 **November 2025: CA for Agents** - Preview feature, monitoring for adoption

**Conclusion**: The CA Policy Analyzer is up to date with all significant 2026 CA policy changes.

---

**Commit**: `fc3c2b2` - feat: add May 2026 credential registration constraint check  
**Date**: April 4, 2026
