import Link from "next/link";

export default function OfflineExportGuidePage() {
  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <div className="flex items-center gap-4">
        <Link
          href="/"
          className="inline-flex items-center gap-1 text-sm text-gray-400 hover:text-gray-200"
        >
          ← Back to analyzer
        </Link>
      </div>

      <div className="rounded-xl border border-gray-800 bg-gray-900 p-6">
        <h2 className="text-2xl font-bold text-white">Offline Export Guide</h2>
        <p className="mt-2 text-sm text-gray-400">
          Use this workflow when CA Policy Analyzer cannot access Microsoft Graph directly.
          Export once from an online admin workstation, then import the JSON file into offline mode.
        </p>
      </div>

      <div className="rounded-xl border border-gray-800 bg-gray-900 p-6 space-y-4">
        <h3 className="text-lg font-semibold text-white">1) Prepare PowerShell</h3>
        <p className="text-sm text-gray-400">
          Run these commands on a workstation that can reach Microsoft Graph.
          This installs only the required submodules.
        </p>
        <pre className="overflow-x-auto rounded-lg border border-gray-800 bg-gray-950 p-4 text-xs text-gray-300">
{`Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Install-Module Microsoft.Graph.Beta.Identity.SignIns -Scope CurrentUser
Install-Module Microsoft.Graph.Applications -Scope CurrentUser
Install-Module Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser

Import-Module Microsoft.Graph.Authentication
Import-Module Microsoft.Graph.Beta.Identity.SignIns
Import-Module Microsoft.Graph.Applications
Import-Module Microsoft.Graph.Identity.DirectoryManagement`}
        </pre>
      </div>

      <div className="rounded-xl border border-gray-800 bg-gray-900 p-6 space-y-4">
        <h3 className="text-lg font-semibold text-white">2) Run export script</h3>
        <p className="text-sm text-gray-400">
          This creates a single file named <code>ca-offline-export.json</code> with
          all required datasets.
        </p>
        <pre className="overflow-x-auto rounded-lg border border-gray-800 bg-gray-950 p-4 text-xs text-gray-300">
{`Connect-MgGraph -Scopes \`
  "Policy.Read.All", \`
  "Application.Read.All", \`
  "Directory.Read.All", \`
  "Policy.Read.ConditionalAccess", \`
  "Organization.Read.All", \`
  "AuditLog.Read.All"

$tenant = Get-MgOrganization -Top 1
$policies = Get-MgBetaIdentityConditionalAccessPolicy -All
$namedLocations = Get-MgBetaIdentityConditionalAccessNamedLocation -All
$servicePrincipals = Get-MgServicePrincipal -All -Property "id,appId,displayName,servicePrincipalType,appOwnerOrganizationId,tags"
$authStrengthPolicies = Get-MgBetaPolicyAuthenticationStrengthPolicy -All
$subscribedSkus = Get-MgSubscribedSku -All

$objectIds = [System.Collections.Generic.HashSet[string]]::new()
foreach ($p in $policies) {
  $u = $p.Conditions.Users
  foreach ($id in @($u.IncludeUsers + $u.ExcludeUsers + $u.IncludeGroups + $u.ExcludeGroups + $u.IncludeRoles + $u.ExcludeRoles)) {
    if ($id -match '^[0-9a-fA-F-]{36}$') { [void]$objectIds.Add($id) }
  }
}

$directoryObjects = foreach ($id in $objectIds) {
  try { Get-MgDirectoryObject -DirectoryObjectId $id -ErrorAction Stop } catch { $null }
}

# ── Enterprise apps that sign in but have no service principal ─────────────
# Such an app cannot be selected in a CA policy at all, so it sits outside every
# policy. One row per app over the last 30 days, diffed against the SPs above.
$spAppIds = [System.Collections.Generic.HashSet[string]]::new(
  [string[]]($servicePrincipals.AppId), [System.StringComparer]::OrdinalIgnoreCase)

$appSummary = (Invoke-MgGraphRequest -Method GET \`
  -Uri "https://graph.microsoft.com/beta/auditLogs/signInEventsAppSummary").value
$signInAppsTruncated = @($appSummary).Count -ge 1000

$startIso = (Get-Date).ToUniversalTime().AddDays(-30).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
$select = "id,createdDateTime,userPrincipalName,ipAddress,appDisplayName,clientAppUsed," +
          "resourceDisplayName,conditionalAccessStatus,appliedConditionalAccessPolicies"

$signInApps = foreach ($row in $appSummary) {
  if (-not $row.appId -or $spAppIds.Contains($row.appId)) { continue }

  # /auditLogs/signIns returns interactive sign-ins unless another event type is
  # named, so probe all four - a service-principal-only app is invisible otherwise.
  $evidence = $null; $eventType = $null
  foreach ($mode in @('interactiveUser','nonInteractiveUser','servicePrincipal','managedIdentity')) {
    $filter = "appId eq '$($row.appId)' and createdDateTime ge $startIso"
    if ($mode -ne 'interactiveUser') {
      $filter += " and signInEventTypes/any(t: t eq '$mode')"
    }
    $uri = "https://graph.microsoft.com/beta/auditLogs/signIns?" +
           "\\$filter=$filter&\\$top=1&\\$select=$select"
    try {
      $hit = (Invoke-MgGraphRequest -Method GET -Uri $uri -Headers @{
        Prefer = 'include-unknown-enum-members' }).value | Select-Object -First 1
      if ($hit) { $evidence = $hit; $eventType = $mode; break }
    } catch { }
  }

  [ordered]@{
    appId                            = $row.appId
    signInCount                      = $row.signInCount
    signInEventType                  = $eventType
    displayName                      = $evidence.appDisplayName
    lastSeen                         = $evidence.createdDateTime
    requestId                        = $evidence.id
    userPrincipalName                = $evidence.userPrincipalName
    ipAddress                        = $evidence.ipAddress
    clientAppUsed                    = $evidence.clientAppUsed
    resourceDisplayName              = $evidence.resourceDisplayName
    conditionalAccessStatus          = $evidence.conditionalAccessStatus
    appliedConditionalAccessPolicies = $evidence.appliedConditionalAccessPolicies
  }
}

$export = [ordered]@{
  tenantId                       = $tenant.Id
  tenantDisplayName              = $tenant.DisplayName
  conditionalAccessPolicies      = $policies
  namedLocations                 = $namedLocations
  servicePrincipals              = $servicePrincipals
  directoryObjects               = $directoryObjects
  authenticationStrengthPolicies = $authStrengthPolicies
  subscribedSkus                 = $subscribedSkus
  signInApps                     = @($signInApps)
  signInAppsTruncated            = $signInAppsTruncated
}

$export | ConvertTo-Json -Depth 25 | Out-File ".\\ca-offline-export.json" -Encoding utf8`}
        </pre>
        <p className="text-xs text-gray-500">
          The sign-in block needs <code className="text-gray-400">AuditLog.Read.All</code>{" "}
          and Entra ID P1 or higher. It makes one small request per unregistered
          app, so on a large tenant this is the slowest part of the export. An
          export created before this block existed still imports fine - the
          &quot;Missing Service Principals&quot; category simply
          reports itself as unavailable.
        </p>
      </div>

      <div className="rounded-xl border border-gray-800 bg-gray-900 p-6 space-y-3">
        <h3 className="text-lg font-semibold text-white">3) Import into analyzer</h3>
        <ol className="list-decimal space-y-2 pl-5 text-sm text-gray-300">
          <li>Open CA Policy Analyzer.</li>
          <li>On the landing screen, click <strong>Import Offline Export</strong>.</li>
          <li>Select <code>ca-offline-export.json</code>.</li>
          <li>Run analysis as usual.</li>
        </ol>
      </div>
    </div>
  );
}
