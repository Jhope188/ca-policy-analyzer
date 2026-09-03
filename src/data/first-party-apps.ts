/**
 * appId → display name, so a GUID with no service principal is never shown
 * without a label. Last-resort fallback: `app-descriptions.ts`,
 * `ca-bypass-database.ts` and `foci-families.ts` are richer and checked first.
 * Name-only by design - risk and rationale live in `app-descriptions.ts`.
 */

const MICROSOFT_FIRST_PARTY_APPS: Record<string, string> = {
  // ─── Identity, directory & API ─────────────────────────────────────────────
  "00000002-0000-0000-c000-000000000000": "Windows Azure Active Directory",
  "00000003-0000-0000-c000-000000000000": "Microsoft Graph",
  "797f4846-ba00-4fd7-ba43-dac1f8f63013": "Azure Resource Manager",
  "1b912ec3-a9dd-4c4d-a53e-76aa7adb28d7": "AADReporting",
  "19db86c3-b2b9-44cc-b339-36da233a3be2": "My Signins",
  "8c59ead7-d703-4a27-9e55-c96a0054c8d2": "My Profile",
  "0000000c-0000-0000-c000-000000000000": "Microsoft App Access Panel",
  "ba9ff945-a723-4ab5-a977-bd8c9044fe61": "My Staff",
  "ea890292-c8c8-4433-b5ea-b09d0668e1a6":
    "Azure Credential Configuration Endpoint Service",
  "f9885e6e-6f74-46b3-b595-350157a27541": "Microsoft_AAD_UsersAndTenants",
  "50aaa389-5a33-4f1a-91d7-2c45ecd8dac8": "Microsoft_Azure_PIMCommon",
  "74658136-14ec-4630-ad9b-26e160ff0fc6": "ADIbizaUX",
  "38aa3b87-a06d-4817-b275-7a316988d93b": "Windows Sign In",
  "29d9ed98-a469-4536-ade2-f981bc1d605e": "Microsoft Authentication Broker",
  "4813382a-8fa7-425e-ab75-3b753aab3abb": "Microsoft Authenticator App",

  // ─── Exchange & Outlook ────────────────────────────────────────────────────
  "00000002-0000-0ff1-ce00-000000000000": "Office 365 Exchange Online",
  "00000007-0000-0ff1-ce00-000000000000":
    "Microsoft Exchange Online Protection",
  "27922004-5251-4030-b22d-91ecd9a37ea4": "Outlook Mobile",
  "5d661950-3475-41cd-a2c3-d671a3162bc1": "Microsoft Outlook",
  "87223343-80b1-4097-be13-2332ffa1d666": "Outlook Web App Widgets",
  "9199bf20-a13f-4107-85dc-02114787ef48": "One Outlook Web",
  "bc59ab01-8403-45c6-8796-ac3ef710b3e3": "Outlook Online Add-in App",
  "e9b154d0-7658-433b-bb25-6b8e0a8a7c59": "Outlook Lite",
  "765fe668-04e7-42ba-aec0-2c96f1d8b652":
    "Exchange Office Graph Client for AAD - Noninteractive",
  "6da466b6-1d13-4a2c-97bd-51a99e8d4d74":
    "Exchange Office Graph Client for AAD - Interactive",
  "789e8929-0390-42a2-8934-0f9dafb8ec89": "Exchange Rbac",
  "a150d169-7d37-47dd-9b20-156207b7b02f": "MIP Exchange Solutions",

  // ─── Office, Copilot & productivity ────────────────────────────────────────
  "d3590ed6-52b3-4102-aeff-aad2292ab01c": "Microsoft Office",
  "fb8d773d-7ef8-4ec0-a117-179f88add510": "Microsoft 365 Copilot",
  "c0ab8ce9-e9a0-42e7-b064-33d422df41f1": "M365ChatClient",
  "4354e225-50c9-4423-9ece-2d5afd904870": "Augmentation Loop",
  "5a6fd92b-8a2c-41d2-b3bb-98d35d258d9e": "Azure Portal Fx Copilot Web",
  "ffe59ab3-5993-4931-863a-2e78afcf0d1f": "Entra-Copilot-UX",
  "5f00fd34-f302-417f-81ef-1adda179d8fd": "Microsoft Forms Web",
  "89bee1f7-5e6e-4d8a-9f3d-ecd601259da7": "Office365 Shell WCSS-Client",
  "4765445b-32c6-49b0-83e6-1d93765276ca": "OfficeHome",
  "af124e86-4e96-495a-b70a-90f90ab96707": "OneDrive iOS App",
  "ab9b8c07-8f02-4f72-87fa-80105867a763": "OneDrive SyncEngine",
  "6dec647e-42c4-45a6-8f13-e8250d34e033": "WeveAgave",
  "bb893c22-978d-4cd4-a6f7-bb6cc0d6e6ce": "Olympus",
  "3a4d129e-7f50-4e0d-a7fd-033add0a29f4": "Enterprise Dashboard Project",
  "4b0964e4-58f1-47f4-a552-e2e1fc56dcd7": "FXIrisClient",
  "16aeb910-ce68-41d1-9ac3-9e1673ac9575": "IrisSelectionFrontDoor",
  "6f7e0f60-9401-4f5b-98e2-cf15bd5fd5e3":
    "Microsoft Application Command Service",
  "8fbcdaa8-9342-48c2-927f-3a15d30f7b8b": "Code Center Premium",

  // ─── Device management & endpoints ─────────────────────────────────────────
  "d4ebce55-015a-49b5-a083-c84d1797ae8c": "Microsoft Intune Enrollment",
  "fc0f3af4-6835-4174-b806-f7db311fd2f3": "Microsoft Intune Windows Agent",
  "de50c81f-5f80-4771-b66b-cebd28ccdfc1": "Device Management Client",
  "3678c9e9-9681-447a-974d-d19f668fcd88": "Microsoft Tunnel Gateway",
  "45a330b1-b1ec-4cc1-9161-9f03992aa49f": "Windows Store for Business",
  "268761a2-03f3-40df-8a8b-c3db24145b6b": "Universal Store Native Client",
  "26a7ee05-5602-4d76-a7ba-eae8b7b67941": "Windows Search",
  "ecd6b820-32c2-49b6-98a6-444530e5a77a": "Microsoft Edge",
  "d7b530a4-7680-4c23-a8bf-c52c121d2e87":
    "Microsoft Edge Enterprise New Tab Page",

  // ─── Remote desktop & Cloud PC ─────────────────────────────────────────────
  "9cdead84-a844-4324-93f2-b2e6bb768d07": "Azure Virtual Desktop",
  "0af06dc6-e4b5-4f28-818e-e78e62d137a5": "Windows 365",
  "a4a365df-50f1-4397-bc59-1a1564b8bb9c": "Microsoft Remote Desktop",

  // ─── Defender & security ───────────────────────────────────────────────────
  "dd47d17a-3194-4d86-bfd5-c6ae6f5651e3": "Microsoft Defender for Mobile",
  "a0e84e36-b067-4d5c-ab4a-3db38e598ae2": "MicrosoftDefenderATP XPlat",
  "e724aa31-0f56-4018-b8be-f8cb82ca1196":
    "Microsoft Defender for Mobile TVM",
  "cab96880-db5b-4e15-90a7-f3f1d62ffe39": "Microsoft Defender Platform",
  "8a0c2593-9cbc-4f86-a247-beb7aab00d83":
    "Microsoft Defender for Cloud Apps - Session Controls",

  // ─── Global Secure Access / ZTNA ───────────────────────────────────────────
  "cde6adac-58fd-4b78-8d6d-9beaf1b0d668": "Global Secure Access Client",
  "760282b4-0cfc-4952-b467-c8e0298fee16":
    "ZTNA Network Access Client -- Private",
  "ca01d00c-bfd6-46d6-ae7d-be5b5267d037": "ZTNA Policy Service Client",
  "b3fa0115-39b3-4bec-8cc6-8c4fcd33e69d": "ZTNA Policy Service",
  "ea8d014c-04e7-450c-a600-eaa309e42309": "ZTNA UX Portal",

  // ─── Developer tooling ─────────────────────────────────────────────────────
  "499b84ac-1321-427f-aa17-267ca6975798": "Azure DevOps",
  "aebc6443-996d-45c2-90f0-388ff96faa56": "Visual Studio Code",
};

/** Keys above are lowercase; sign-in logs are inconsistent about GUID casing. */
export function getFirstPartyAppName(appId: string): string | undefined {
  return MICROSOFT_FIRST_PARTY_APPS[appId.toLowerCase()];
}
