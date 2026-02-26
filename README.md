# CA Policy Analyzer

> Analyze your Entra ID Conditional Access policies for best practices, FOCI token-sharing risks, and known CA bypasses — **directly in your browser, no install required.**

[![Live App](https://img.shields.io/badge/Launch%20App-GitHub%20Pages-blue?logo=github)](https://jhope188.github.io/ca-policy-analyzer)
![Next.js](https://img.shields.io/badge/Next.js-16-black?logo=next.js) ![TypeScript](https://img.shields.io/badge/TypeScript-5-blue?logo=typescript) ![Tailwind CSS](https://img.shields.io/badge/Tailwind-4-38bdf8?logo=tailwindcss)

## 🚀 Try It Now

**No download. No install. No server.**

👉 **[https://jhope188.github.io/ca-policy-analyzer](https://jhope188.github.io/ca-policy-analyzer)**

1. Click **Connect Tenant**
2. Sign in with your Entra ID credentials
3. Click **Run Analysis**
4. Review your security score, findings, and policy details

The app runs **100% in your browser** — your data never leaves your machine. It connects directly to Microsoft Graph using your own credentials (delegated permissions).

## What It Does

CA Policy Analyzer connects to your Entra ID tenant via Microsoft Graph and:

1. **Reads all Conditional Access policies** including users, apps, conditions, and grant/session controls
2. **Checks for best-practice violations** using research from [Fabian Bader](https://cloudbrothers.info/en/conditional-access-bypasses/) and [EntraScopes.com](https://entrascopes.com)
3. **Detects FOCI risks** — if a policy excludes one FOCI app, ALL 45+ family members can share tokens
4. **Flags known CA bypasses** including CA-immune resources, Device Registration Service bypass, resource exclusion scope leaks, and more
5. **Generates a Security Posture Score** (0-100) with severity-ranked findings and actionable recommendations
6. **Visualizes each policy** showing the flow: Users → Conditions → Apps → Grant Controls

## Key Checks

| Category | What It Detects |
|---|---|
| **FOCI Token Sharing** | Excluded apps that belong to the Family of Client IDs — tokens interchangeable across 45+ Microsoft apps |
| **Resource Exclusion Bypass** | Excluding ANY app from "All cloud apps" leaks Azure AD Graph & MS Graph basic scopes |
| **CA-Immune Resources** | 6 Microsoft resources completely excluded from CA enforcement (always notApplied) |
| **Device Registration Bypass** | Device Registration Service ignores location and device compliance — only MFA works |
| **Swiss Cheese Model** | Grant controls using OR instead of AND, missing MFA baseline layer |
| **Legacy Authentication** | Legacy auth clients targeted but not blocked |
| **Known CA Bypass Apps** | Apps with documented CA bypass capabilities (Azure CLI, PowerShell, AAD Connect, etc.) |
| **Tenant-Wide Gaps** | Missing MFA-for-all, no legacy auth block, no break-glass accounts |

## Privacy & Security

- **No backend server** — the app is static HTML/JS/CSS hosted on GitHub Pages
- **No data collection** — your policies, tokens, and tenant data stay in your browser session
- **Delegated auth only** — the app can only do what your signed-in user can do
- **Open source** — review every line of code in this repo

### Required Permissions

The app requests these Microsoft Graph **delegated** permissions when you sign in:

| Permission | Why |
|---|---|
| `Policy.Read.All` | Read Conditional Access policies |
| `Application.Read.All` | Resolve service principal names referenced in policies |
| `Directory.Read.All` | Resolve groups, roles, and users referenced in policies |

Your tenant admin must grant consent for these permissions. The app uses a multi-tenant app registration — no per-tenant setup needed.

## For Developers

If you want to run locally, fork, or contribute:

### Prerequisites

- Node.js 18+
- npm

### Local Development

```bash
git clone https://github.com/Jhope188/ca-policy-analyzer.git
cd ca-policy-analyzer
npm install
npm run dev
```

Open http://localhost:3000 and click **Connect Tenant**.

> **Note:** The app comes with a built-in Client ID for the hosted app registration. If you fork this project and want to use your own, set `NEXT_PUBLIC_MSAL_CLIENT_ID` in a `.env.local` file.

### Building for Production

```bash
npm run build    # Outputs static site to ./out
```

The GitHub Actions workflow in `.github/workflows/deploy-pages.yml` automatically builds and deploys to GitHub Pages on every push to `main`.

### Architecture

```
src/
├── app/            # Next.js App Router — main page with tab views
├── components/     # Auth provider, header, dashboard, policy list, findings
├── data/           # FOCI database (45 apps) + CA bypass database (13 apps)
└── lib/            # MSAL config, Graph client, analyzer engine (13 checks)
```

### Tech Stack

- **Next.js 16** — Static export with App Router
- **MSAL.js** — Entra ID authentication (redirect flow)
- **Microsoft Graph** — Reads CA policies, service principals, named locations
- **Tailwind CSS 4** — Dark theme UI
- **TypeScript** — Full type safety across Graph responses and analysis results

## Research Credits

- **Fabian Bader** — Conditional Access bypasses (TROOPERS25)
- **Dirk-jan Mollema & Fabian Bader** — EntraScopes.com
- **Secureworks** — Family of Client IDs Research

## License

MIT
