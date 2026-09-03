/**
 * Shared phishing-resistant authentication detection.
 *
 * Used by:
 *   - src/lib/zero-trust-scorecard.ts        (Verify Explicitly pillar signal)
 *   - src/lib/persona-coverage.ts            (Persona × Control matrix)
 *   - src/lib/analyzer.ts                    (Guest auth strength + Protected
 *                                             Actions findings)
 *
 * A policy is treated as phishing-resistant when ANY of the following hold:
 *
 *   1. Its `authenticationStrength.id` matches the well-known built-in
 *      Microsoft "Phishing-resistant MFA" strength id.
 *   2. The strength's `displayName` matches a defensive regex (used as a
 *      fallback when the tenant strength catalog hasn't loaded, or when a
 *      baseline policy names the strength explicitly in the policy name).
 *   3. The strength resolves against `TenantContext.authStrengthPolicies` and
 *      its `allowedCombinations` contains at least one phishing-resistant
 *      authentication-method token. **This is the authoritative signal** -
 *      it correctly catches custom strengths whose displayName does not
 *      mention "phishing-resistant" but whose underlying methods ARE (e.g.
 *      "Modern MFA + TAP" → fido2, windowsHelloForBusiness,
 *      x509CertificateMultiFactor).
 *
 * Reference:
 *   https://learn.microsoft.com/entra/identity/authentication/concept-authentication-strengths
 */
import type { ConditionalAccessPolicy, TenantContext } from "./graph-client";

/** Well-known Microsoft built-in "Phishing-resistant MFA" strength id. */
export const BUILTIN_PHISHING_RESISTANT_ID =
  "00000000-0000-0000-0000-000000000004";

/**
 * Authentication-method tokens Microsoft classifies as phishing-resistant.
 * Compared lower-case against tokens parsed out of `allowedCombinations`
 * entries, which can be either a single token (e.g. "fido2") or a
 * comma-separated combo (e.g. "federatedMultiFactor,fido2").
 *
 * Reference:
 *   https://learn.microsoft.com/entra/identity/authentication/concept-authentication-strengths#authentication-method-combinations
 */
export const PHISHING_RESISTANT_METHOD_TOKENS: ReadonlyArray<string> = [
  "fido2",
  "windowshelloforbusiness",
  "x509certificatemultifactor",
  "x509certificatesinglefactor",
  "deviceboundpasskey",
  "hardwareoath",
];

/**
 * Defensive displayName regex. Used only as a fallback when the strength
 * catalog isn't available. Matches names that explicitly mention
 * phishing-resistant or one of its canonical methods.
 */
export const PHISHING_RESISTANT_NAME_REGEX =
  /phishing.?resistant|fido2|windows hello|certificate.?based/i;

/**
 * Resolve whether a CA policy enforces a phishing-resistant authentication
 * strength. Pass `context` whenever possible - without it, only the built-in
 * id and displayName heuristics are available, so custom strengths whose
 * names don't mention phishing-resistance will be missed.
 */
export function policyUsesPhishingResistant(
  p: ConditionalAccessPolicy,
  context?: TenantContext
): boolean {
  const strength = p.grantControls?.authenticationStrength;
  if (!strength?.id) {
    // Last-ditch: some baselines name the policy itself "... phishing-resistant ...".
    return /phishing.?resistant/i.test(p.displayName);
  }

  // Signal 1: built-in phishing-resistant id.
  if (strength.id === BUILTIN_PHISHING_RESISTANT_ID) return true;

  // Signal 2: displayName regex (defensive fallback).
  const dn = strength.displayName ?? "";
  if (PHISHING_RESISTANT_NAME_REGEX.test(dn)) return true;

  // Signal 3 (authoritative): resolve the strength id against the tenant
  // catalog and inspect its allowedCombinations.
  const resolved = context?.authStrengthPolicies?.get(strength.id);
  const combos = resolved?.allowedCombinations ?? [];
  for (const combo of combos) {
    const tokens = combo.toLowerCase().split(/[,\s]+/).filter(Boolean);
    if (tokens.some((t) => PHISHING_RESISTANT_METHOD_TOKENS.includes(t))) {
      return true;
    }
  }

  // Final fallback: policy displayName explicitly mentions phishing-resistant.
  return /phishing.?resistant/i.test(p.displayName);
}
