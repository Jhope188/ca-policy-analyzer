"use client";

/**
 * MSAL Provider — wraps the app with MsalProvider for auth context.
 * Must be rendered as a Client Component.
 */

import { ReactNode, useEffect, useRef, useState } from "react";
import {
  PublicClientApplication,
  EventType,
  EventMessage,
  AuthenticationResult,
} from "@azure/msal-browser";
import { MsalProvider } from "@azure/msal-react";
import { msalConfig } from "@/lib/msal-config";

// Lazily create the MSAL instance only in the browser (avoids SSR "window is not defined")
let msalInstance: PublicClientApplication | null = null;
function getMsalInstance(): PublicClientApplication {
  if (!msalInstance) {
    msalInstance = new PublicClientApplication(msalConfig);
  }
  return msalInstance;
}

export default function AuthProvider({ children }: { children: ReactNode }) {
  const [isInitialized, setIsInitialized] = useState(false);
  const initStarted = useRef(false);

  useEffect(() => {
    // Prevent double-init in React Strict Mode
    if (initStarted.current) return;
    initStarted.current = true;

    const init = async () => {
      const pca = getMsalInstance();
      await pca.initialize();

      // Handle redirect response (comes back after loginRedirect)
      try {
        const response = await pca.handleRedirectPromise();
        if (response?.account) {
          pca.setActiveAccount(response.account);
        }
      } catch (e) {
        console.error("Redirect error:", e);
      }

      // Set active account from cache
      const accounts = pca.getAllAccounts();
      if (accounts.length > 0 && !pca.getActiveAccount()) {
        pca.setActiveAccount(accounts[0]);
      }

      // Listen for login events
      pca.addEventCallback((event: EventMessage) => {
        if (
          event.eventType === EventType.LOGIN_SUCCESS &&
          event.payload
        ) {
          const payload = event.payload as AuthenticationResult;
          pca.setActiveAccount(payload.account);
        }
      });

      setIsInitialized(true);
    };

    init();
  }, []);

  if (!isInitialized) {
    return (
      <div className="flex h-screen items-center justify-center bg-gray-950 text-gray-400">
        <div className="flex flex-col items-center gap-3">
          <div className="h-8 w-8 animate-spin rounded-full border-2 border-gray-600 border-t-blue-500" />
          <p className="text-sm">Initializing authentication…</p>
        </div>
      </div>
    );
  }

  return <MsalProvider instance={getMsalInstance()}>{children}</MsalProvider>;
}
