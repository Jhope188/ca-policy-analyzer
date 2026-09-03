import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import AuthProvider from "@/components/auth-provider";
import Header from "@/components/header";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "CA Policy Analyzer",
  description:
    "Analyze Conditional Access policies for best practices, FOCI risks, and known bypasses.",
};

// Security meta tags - GitHub Pages does not allow custom HTTP response headers
// (Fastly CDN, no server config access). These meta equivalents cover what is
// possible: CSP restricts resource loading; referrer-policy limits referrer
// leakage. X-Frame-Options, X-Content-Type-Options, Permissions-Policy, and
// HSTS require HTTP headers and cannot be set on GitHub Pages.
export const viewport = {
  width: "device-width",
  initialScale: 1,
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <head>
        {/*
          Content-Security-Policy via meta tag.
          GitHub Pages does not support custom HTTP headers - this is the only
          way to set a CSP on a static GitHub Pages deployment.
          Limitations: frame-ancestors and report-uri are ignored in meta CSPs.

          Allowed origins:
            - 'self'                    app assets
            - login.microsoftonline.com MSAL auth redirects & token endpoint
            - graph.microsoft.com       Microsoft Graph API calls
            - 'unsafe-inline' styles    Tailwind CSS-in-JS / Next.js inline styles
            - data:                     inline SVG data URIs used by Next.js Image
        */}
        <meta
          httpEquiv="Content-Security-Policy"
          content={[
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline'",
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data: blob:",
            "font-src 'self' data:",
            "connect-src 'self' https://graph.microsoft.com https://login.microsoftonline.com https://*.microsoftonline.com https://api.github.com https://raw.githubusercontent.com",
            "frame-src 'none'",
            "object-src 'none'",
            "base-uri 'self'",
            "form-action 'self'",
          ].join("; ")}
        />
        {/* Referrer-Policy - do not send referrer to cross-origin requests */}
        <meta name="referrer" content="strict-origin-when-cross-origin" />
      </head>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased bg-gray-950 text-gray-100`}
      >
        <AuthProvider>
          <Header />
          <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
            {children}
          </main>
        </AuthProvider>
      </body>
    </html>
  );
}
