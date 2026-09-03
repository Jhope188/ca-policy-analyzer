/**
 * MSAL Authentication Configuration
 *
 * Configures Microsoft Authentication Library for reading
 * Conditional Access policies from any Entra ID tenant.
 */

import { Configuration, LogLevel, RedirectRequest } from "@azure/msal-browser";

// The client ID for a multi-tenant SPA (register in Entra ID → App registrations)
// Override via NEXT_PUBLIC_MSAL_CLIENT_ID env var if you fork this project
const CLIENT_ID =
  process.env.NEXT_PUBLIC_MSAL_CLIENT_ID || "b8fe9cbf-f32d-4af7-87ae-0781bc0126c7";

// Auto-detect redirect URI at runtime so it works on both localhost and GitHub Pages
const REDIRECT_URI =
  typeof window !== "undefined"
    ? window.location.origin + (window.location.pathname.replace(/\/+$/, "") || "")
    : process.env.NEXT_PUBLIC_MSAL_REDIRECT_URI ?? "http://localhost:3000";

export const msalConfig: Configuration = {
  auth: {
    clientId: CLIENT_ID,
    authority: "https://login.microsoftonline.com/common",
    redirectUri: REDIRECT_URI,
  },
  cache: {
    cacheLocation: "sessionStorage",
  },
  system: {
    loggerOptions: {
      loggerCallback: (level, message, containsPii) => {
        if (containsPii) return;
        switch (level) {
          case LogLevel.Error:
            console.error(message);
            break;
          case LogLevel.Warning:
            console.warn(message);
            break;
          case LogLevel.Info:
            // console.info(message);
            break;
          case LogLevel.Verbose:
            // console.debug(message);
            break;
        }
      },
      logLevel: LogLevel.Warning,
    },
  },
};

// ─── Graph Permission Scopes ─────────────────────────────────────────────────
// These are the delegated permissions needed to read CA policies and resolve
// the service principals / named locations they reference.

export const graphScopes = {
  /** Read Conditional Access policies */
  policyRead: "Policy.Read.All",
  /** Read service principal metadata (to describe excluded apps) */
  applicationRead: "Application.Read.All",
  /** Read directory objects (groups, roles, users referenced in policies) */
  directoryRead: "Directory.Read.All",
  /** Read sign-in logs, to find apps with no service principal */
  auditLogRead: "AuditLog.Read.All",
};

export const loginRequest: RedirectRequest = {
  scopes: [
    graphScopes.policyRead,
    graphScopes.applicationRead,
    graphScopes.directoryRead,
    graphScopes.auditLogRead,
  ],
};

export const graphTokenRequest = {
  scopes: ["https://graph.microsoft.com/.default"],
};

/**
 * True when the URL still carries an MSAL auth response. One MSAL didn't consume
 * makes its `isInPopup()` preflight true, after which every
 * `acquireTokenSilent` fails with `block_nested_popups` for the whole session.
 * Both hash and query - MSAL supports a hybrid response format.
 */
export function hasAuthResponseInUrl(hash: string, search: string): boolean {
  const hashParams = new URLSearchParams(hash.replace(/^#/, ""));
  if (hashParams.has("state")) return true;
  const queryParams = new URLSearchParams(search.replace(/^\?/, ""));
  return queryParams.has("state");
}
