# ===========================================
# GitHound GraphQL Collector
# A GraphQL-based collector for GitHub organization data
# Outputs BloodHound-compatible JSON files
# ===========================================

# ===========================================
# Metrics Tracking for Performance Analysis
# ===========================================
$script:GitHoundMetrics = @{
    Enabled = $false
    CurrentPhase = $null
    Phases = @{}
    TotalApiCalls = 0
    TotalStartTime = $null
}

function Initialize-GitHoundMetrics {
    $script:GitHoundMetrics = @{
        Enabled = $true
        CurrentPhase = $null
        Phases = @{}
        TotalApiCalls = 0
        TotalStartTime = [System.Diagnostics.Stopwatch]::StartNew()
    }
}

function Start-GitHoundPhaseMetrics {
    param([string]$PhaseName)
    if (-not $script:GitHoundMetrics.Enabled) { return }
    $script:GitHoundMetrics.CurrentPhase = $PhaseName
    $script:GitHoundMetrics.Phases[$PhaseName] = @{
        StartTime = [System.Diagnostics.Stopwatch]::StartNew()
        ApiCalls = 0
        GraphQLCalls = 0
    }
}

function Add-GitHoundApiCall {
    if (-not $script:GitHoundMetrics.Enabled) { return }
    $script:GitHoundMetrics.TotalApiCalls++
    $phase = $script:GitHoundMetrics.CurrentPhase
    if ($phase -and $script:GitHoundMetrics.Phases.ContainsKey($phase)) {
        $script:GitHoundMetrics.Phases[$phase].ApiCalls++
        $script:GitHoundMetrics.Phases[$phase].GraphQLCalls++
    }
}

function Stop-GitHoundPhaseMetrics {
    param([string]$PhaseName)
    if (-not $script:GitHoundMetrics.Enabled) { return }
    if ($script:GitHoundMetrics.Phases.ContainsKey($PhaseName)) {
        $phase = $script:GitHoundMetrics.Phases[$PhaseName]
        $phase.StartTime.Stop()
        $phase.Duration = $phase.StartTime.Elapsed
        $duration = $phase.Duration.ToString("mm\:ss\.fff")
        Write-Host "    [Metrics] $PhaseName completed: $($phase.ApiCalls) GraphQL calls in $duration" -ForegroundColor Cyan
    }
    $script:GitHoundMetrics.CurrentPhase = $null
}

function Write-GitHoundMetricsSummary {
    if (-not $script:GitHoundMetrics.Enabled) { return }
    $script:GitHoundMetrics.TotalStartTime.Stop()
    $totalDuration = $script:GitHoundMetrics.TotalStartTime.Elapsed

    Write-Host ""
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "COLLECTION METRICS SUMMARY" -ForegroundColor Cyan
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host ("{0,-20} {1,10} {2,10} {3,12}" -f "Phase", "GraphQL", "REST", "Duration") -ForegroundColor Yellow
    Write-Host ("{0,-20} {1,10} {2,10} {3,12}" -f "-----", "-------", "----", "--------") -ForegroundColor Yellow

    $totalGraphQL = 0
    $totalRest = 0
    $sortedPhases = $script:GitHoundMetrics.Phases.GetEnumerator() | Sort-Object { $_.Value.Duration } -Descending
    foreach ($entry in $sortedPhases) {
        $phase = $entry.Value
        $duration = if ($phase.Duration) { $phase.Duration.ToString("mm\:ss\.fff") } else { "N/A" }
        $graphqlCalls = if ($phase.GraphQLCalls) { $phase.GraphQLCalls } else { 0 }
        $restCalls = if ($phase.RestCalls) { $phase.RestCalls } else { 0 }
        $totalGraphQL += $graphqlCalls
        $totalRest += $restCalls
        Write-Host ("{0,-20} {1,10} {2,10} {3,12}" -f $entry.Key, $graphqlCalls, $restCalls, $duration)
    }

    Write-Host ""
    Write-Host ("{0,-20} {1,10} {2,10} {3,12}" -f "TOTAL", $totalGraphQL, $totalRest, $totalDuration.ToString("mm\:ss\.fff")) -ForegroundColor Green
    Write-Host ("{0,-20} {1,10}" -f "Combined API Calls", $script:GitHoundMetrics.TotalApiCalls) -ForegroundColor Green
    Write-Host ""
    Write-Host "=============================================" -ForegroundColor Cyan
}

# ===========================================
# Session Management
# ===========================================
function New-GithubSession {
    [OutputType('GitHound.Session')]
    [CmdletBinding()]
    Param(
        [Parameter(Position=0, Mandatory = $true)]
        [string]$OrganizationName,

        [Parameter(Position=1, Mandatory = $false)]
        [string]$ApiUri = 'https://api.github.com/',

        [Parameter(Position=2, Mandatory = $false)]
        [string]$Token,

        [Parameter(Position=3, Mandatory = $false)]
        [string]$UserAgent = 'GitHound-GraphQL/1.0',

        [Parameter(Position=4, Mandatory = $false)]
        [HashTable]$Headers = @{},

        [Parameter(Position=5, Mandatory = $false)]
        [datetime]$TokenExpiry = [datetime]::MaxValue
    )

    $Headers['Accept'] = 'application/vnd.github+json'
    $Headers['X-GitHub-Api-Version'] = '2022-11-28'
    $Headers['User-Agent'] = $UserAgent

    if ($Token) {
        $Headers['Authorization'] = "Bearer $Token"
    }

    [PSCustomObject]@{
        PSTypeName = 'GitHound.Session'
        Uri = $ApiUri
        GraphQLUri = 'https://api.github.com/graphql'
        Headers = $Headers
        OrganizationName = $OrganizationName
        TokenExpiry = $TokenExpiry
        # App credentials for token refresh (null for PAT sessions)
        AppCredentials = $null
    }
}

function New-GitHubJwtSession {
    <#
    .SYNOPSIS
        Creates a GitHub session using App installation token with auto-refresh capability.

    .DESCRIPTION
        Creates a session that can automatically refresh its token when expired.
        Installation tokens expire after 1 hour, so this stores the credentials
        needed to generate new tokens during long-running operations.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Position=0, Mandatory = $true)]
        [string]$OrganizationName,

        [Parameter(Position=1, Mandatory = $true)]
        [string]$ClientId,

        [Parameter(Position=2, Mandatory = $true)]
        [string]$PrivateKeyPath,

        [Parameter(Position=3, Mandatory = $true)]
        [string]$AppId
    )

    # Store credentials for token refresh
    $appCredentials = @{
        ClientId = $ClientId
        PrivateKeyPath = $PrivateKeyPath
        AppId = $AppId
    }

    # Get initial token
    $tokenInfo = Get-GitHubAppInstallationToken -ClientId $ClientId -PrivateKeyPath $PrivateKeyPath -AppId $AppId

    $session = New-GithubSession -OrganizationName $OrganizationName -Token $tokenInfo.Token -TokenExpiry $tokenInfo.Expiry
    $session.AppCredentials = $appCredentials

    Write-Host "[*] GitHub App session created (token expires: $($tokenInfo.Expiry.ToLocalTime().ToString('HH:mm:ss')))" -ForegroundColor Cyan

    return $session
}

function Get-GitHubAppInstallationToken {
    <#
    .SYNOPSIS
        Generates a new GitHub App installation access token.
    #>
    Param(
        [Parameter(Mandatory=$true)][string]$ClientId,
        [Parameter(Mandatory=$true)][string]$PrivateKeyPath,
        [Parameter(Mandatory=$true)][string]$AppId
    )

    # Create JWT
    $header = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject @{
        alg = "RS256"
        typ = "JWT"
    }))).TrimEnd('=').Replace('+', '-').Replace('/', '_')

    $payload = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject @{
        iat = [System.DateTimeOffset]::UtcNow.AddSeconds(-10).ToUnixTimeSeconds()
        exp = [System.DateTimeOffset]::UtcNow.AddMinutes(10).ToUnixTimeSeconds()
        iss = $ClientId
    }))).TrimEnd('=').Replace('+', '-').Replace('/', '_')

    $rsa = [System.Security.Cryptography.RSA]::Create()
    $rsa.ImportFromPem((Get-Content $PrivateKeyPath -Raw))

    $signature = [Convert]::ToBase64String($rsa.SignData(
        [System.Text.Encoding]::UTF8.GetBytes("$header.$payload"),
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )).TrimEnd('=').Replace('+', '-').Replace('/', '_')

    $jwt = "$header.$payload.$signature"

    # Get installation access token
    $jwtHeaders = @{
        'Accept' = 'application/vnd.github+json'
        'X-GitHub-Api-Version' = '2022-11-28'
        'Authorization' = "Bearer $jwt"
    }

    $body = @{} | ConvertTo-Json
    $response = Invoke-RestMethod -Uri "https://api.github.com/app/installations/$AppId/access_tokens" -Headers $jwtHeaders -Method POST -Body $body -ContentType 'application/json'

    # Parse expiry time (tokens last 1 hour, but we'll refresh 5 min early)
    $expiry = if ($response.expires_at) {
        [datetime]::Parse($response.expires_at).ToUniversalTime()
    } else {
        [datetime]::UtcNow.AddMinutes(55)  # Conservative: refresh after 55 min
    }

    return @{
        Token = $response.token
        Expiry = $expiry
    }
}

function Update-GitHubSessionToken {
    <#
    .SYNOPSIS
        Refreshes the GitHub App installation token if expired or expiring soon.

    .DESCRIPTION
        Checks if the session token is expired or will expire within 5 minutes.
        If so, generates a new installation token and updates the session.

    .PARAMETER Session
        The GitHound.Session object to refresh.

    .PARAMETER Force
        Force token refresh even if not expired.

    .OUTPUTS
        Returns $true if token was refreshed, $false otherwise.
    #>
    Param(
        [Parameter(Mandatory=$true)]
        [PSTypeName('GitHound.Session')]$Session,

        [switch]$Force
    )

    # PAT sessions don't need refresh
    if ($null -eq $Session.AppCredentials) {
        return $false
    }

    # Check if token needs refresh (expired or expiring within 5 minutes)
    $refreshThreshold = [datetime]::UtcNow.AddMinutes(5)
    if (-not $Force -and $Session.TokenExpiry -gt $refreshThreshold) {
        return $false
    }

    Write-Host "[*] Refreshing GitHub App token (was expiring: $($Session.TokenExpiry.ToLocalTime().ToString('HH:mm:ss')))..." -ForegroundColor Yellow

    try {
        $tokenInfo = Get-GitHubAppInstallationToken `
            -ClientId $Session.AppCredentials.ClientId `
            -PrivateKeyPath $Session.AppCredentials.PrivateKeyPath `
            -AppId $Session.AppCredentials.AppId

        # Update session in place
        $Session.Headers['Authorization'] = "Bearer $($tokenInfo.Token)"
        $Session.TokenExpiry = $tokenInfo.Expiry

        Write-Host "[+] Token refreshed (new expiry: $($tokenInfo.Expiry.ToLocalTime().ToString('HH:mm:ss')))" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Warning "Failed to refresh token: $_"
        throw "Token refresh failed: $_"
    }
}

# ===========================================
# GraphQL API Functions
# ===========================================
function Invoke-GitHubGraphQL {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [PSTypeName('GitHound.Session')]$Session,

        [Parameter(Mandatory=$true)]
        [string]$Query,

        [Parameter(Mandatory=$false)]
        [hashtable]$Variables = @{}
    )

    # Proactively refresh token if expiring soon
    $null = Update-GitHubSessionToken -Session $Session

    $body = @{
        query = $Query
        variables = $Variables
    } | ConvertTo-Json -Depth 100 -Compress

    $requestSuccessful = $false
    $retryCount = 0

    while (-not $requestSuccessful -and $retryCount -lt 5) {
        try {
            $result = Invoke-RestMethod -Uri $Session.GraphQLUri -Headers $Session.Headers -Method POST -Body $body -ContentType 'application/json'
            $requestSuccessful = $true
            Add-GitHoundApiCall

            # Check for GraphQL errors
            if ($result.errors) {
                $errorMessages = ($result.errors | ForEach-Object { $_.message }) -join "; "
                if ($errorMessages -match "rate limit") {
                    throw "Rate limit exceeded"
                }
                Write-Warning "GraphQL errors: $errorMessages"
            }
        }
        catch {
            $statusCode = $_.Exception.Response.StatusCode

            # Handle token expiration (401 Unauthorized)
            if ($statusCode -eq 401) {
                Write-Warning "Token expired. Refreshing..."
                try {
                    $null = Update-GitHubSessionToken -Session $Session -Force
                    $retryCount++
                    continue
                }
                catch {
                    throw "Authentication failed and token refresh failed: $_"
                }
            }

            # Handle rate limiting (429 or 403)
            if ($_.Exception.Message -match "rate limit" -or $statusCode -eq 429 -or $statusCode -eq 403) {
                $retryCount++
                Write-Warning "GraphQL rate limit hit. Checking rate limit status... (Retry $retryCount/5)"
                Wait-GitHubGraphQLRateLimit -Session $Session
            }
            else {
                throw $_
            }
        }
    }

    if (-not $requestSuccessful) {
        throw "Failed after 5 retry attempts due to rate limiting"
    }

    return $result
}

# ===========================================
# Node and Edge Creation
# ===========================================
function Normalize-Null {
    param($Value)
    if ($null -eq $Value) { return "" }
    return $Value
}

function New-GitHoundNode {
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [String]$Id,

        [Parameter(Position = 1, Mandatory = $true)]
        [String[]]$Kind,

        [Parameter(Position = 2, Mandatory = $true)]
        [PSObject]$Properties
    )

    [pscustomobject]@{
        id = $Id
        kinds = @($Kind)
        properties = $Properties
    }
}

function New-GitHoundEdge {
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [String]$Kind,

        [Parameter(Position = 1, Mandatory = $true)]
        [PSObject]$StartId,

        [Parameter(Position = 2, Mandatory = $true)]
        [PSObject]$EndId,

        [Parameter(Mandatory = $false)]
        [String]$StartKind,

        [Parameter(Mandatory = $false)]
        [ValidateSet('id', 'name')]
        [String]$StartMatchBy = 'id',

        [Parameter(Mandatory = $false)]
        [String]$EndKind,

        [Parameter(Mandatory = $false)]
        [ValidateSet('id', 'name')]
        [String]$EndMatchBy = 'id',

        [Parameter(Mandatory = $false)]
        [Hashtable]$Properties = @{}
    )

    $edge = [pscustomobject]@{
        kind = $Kind
        start = @{ value = $StartId }
        end = @{ value = $EndId }
        properties = $Properties
    }

    if ($PSBoundParameters.ContainsKey('StartKind')) { $edge.start.Add('kind', $StartKind) }
    if ($PSBoundParameters.ContainsKey('StartMatchBy')) { $edge.start.Add('match_by', $StartMatchBy) }
    if ($PSBoundParameters.ContainsKey('EndKind')) { $edge.end.Add('kind', $EndKind) }
    if ($PSBoundParameters.ContainsKey('EndMatchBy')) { $edge.end.Add('match_by', $EndMatchBy) }

    $edge
}

function ConvertTo-PascalCase {
    param ([string]$String)
    if ([string]::IsNullOrEmpty($String)) { return $String }
    $cleanedString = $String -replace '[-_]', ' ' | ForEach-Object { $_.ToLower() }
    (Get-Culture).TextInfo.ToTitleCase($cleanedString).Replace(' ', '')
}

# ===========================================
# Checkpoint and Output Functions
# ===========================================
function Write-GitHoundPayload {
    Param(
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [Parameter(Mandatory = $true)][string]$OrgName,
        [Parameter(Mandatory = $true)][string]$PhaseName,
        [Parameter(Mandatory = $true)][int]$Tier,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][AllowNull()]$Nodes,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][AllowNull()]$Edges
    )

    $safeNodes = if ($null -eq $Nodes) { @() } else { @($Nodes) }
    $safeEdges = if ($null -eq $Edges) { @() } else { @($Edges) }

    $filename = "githound_${PhaseName}_${OrgName}.json"
    $filepath = Join-Path -Path $OutputPath -ChildPath $filename

    $payload = [PSCustomObject]@{
        metadata = [PSCustomObject]@{ source_kind = "GitHub" }
        graph = [PSCustomObject]@{
            nodes = $safeNodes
            edges = $safeEdges
        }
    }

    $payload | ConvertTo-Json -Depth 10 | Out-File -FilePath $filepath

    if ($Tier -gt 0) {
        Write-Host "[+] Tier $Tier - Wrote $($safeNodes.Count) nodes and $($safeEdges.Count) edges to $filename"
    } else {
        Write-Host "[+] Wrote combined output with $($safeNodes.Count) nodes and $($safeEdges.Count) edges to $filename"
    }

    return $filepath
}

function Save-GitHoundCheckpoint {
    Param(
        [Parameter(Mandatory = $true)][string]$OutputFolder,
        [Parameter(Mandatory = $true)][hashtable]$Checkpoint
    )
    if (-not $Checkpoint.ContainsKey('version')) { $Checkpoint['version'] = 3 }
    $checkpointPath = Join-Path -Path $OutputFolder -ChildPath "_checkpoint.json"
    $Checkpoint | ConvertTo-Json -Depth 10 | Out-File -FilePath $checkpointPath -Force
}

function Get-GitHoundCheckpoint {
    Param([Parameter(Mandatory = $true)][string]$OutputFolder)

    $checkpointPath = Join-Path -Path $OutputFolder -ChildPath "_checkpoint.json"
    if (Test-Path $checkpointPath) {
        $checkpoint = Get-Content -Path $checkpointPath -Raw | ConvertFrom-Json
        $checkpointVersion = if ($checkpoint.version) { $checkpoint.version } else { 1 }

        $result = @{
            version = $checkpointVersion
            timestamp = $checkpoint.timestamp
            orgId = $checkpoint.orgId
            completedPhases = @($checkpoint.completedPhases)
            collect = @($checkpoint.collect)
            userLimit = $checkpoint.userLimit
            repoFilter = $checkpoint.repoFilter
            repoVisibility = $checkpoint.repoVisibility
            # Version 3 fields for batching
            batchSize = if ($checkpoint.batchSize) { $checkpoint.batchSize } else { 10 }
            throttleLimit = if ($checkpoint.throttleLimit) { $checkpoint.throttleLimit } else { 25 }
        }

        if ($checkpoint.phaseProgress) {
            $result.phaseProgress = @{}
            foreach ($prop in $checkpoint.phaseProgress.PSObject.Properties) {
                $phaseData = @{
                    cursor = $prop.Value.cursor
                    itemsCollected = $prop.Value.itemsCollected
                }
                # Version 3: Support for batch-based progress (processedRepoIds, currentBatch, totalRepos)
                if ($prop.Value.processedRepoIds) {
                    $phaseData.processedRepoIds = @($prop.Value.processedRepoIds)
                }
                if ($prop.Value.currentBatch) {
                    $phaseData.currentBatch = $prop.Value.currentBatch
                }
                if ($prop.Value.totalRepos) {
                    $phaseData.totalRepos = $prop.Value.totalRepos
                }
                $result.phaseProgress[$prop.Name] = $phaseData
            }
        } else {
            $result.phaseProgress = @{}
        }

        return $result
    }
    return $null
}

function Read-GitHoundPhaseData {
    Param([Parameter(Mandatory = $true)][string]$FilePath)

    if (-not (Test-Path $FilePath)) {
        Write-Warning "Phase file not found for resume: $FilePath"
        return $null
    }

    try {
        $content = Get-Content -Path $FilePath -Raw | ConvertFrom-Json
        return [PSCustomObject]@{
            Nodes = @($content.graph.nodes)
            Edges = @($content.graph.edges)
        }
    } catch {
        Write-Warning "Failed to read phase file: $FilePath - $_"
        return $null
    }
}

# ===========================================
# Rate Limit Functions (based on og-githound.ps1 pattern)
# ===========================================
function Get-RateLimitInformation {
    <#
    .SYNOPSIS
        Queries the GitHub rate limit API and returns rate limit resources.
    #>
    Param(
        [Parameter(Mandatory=$true)]
        [PSTypeName('GitHound.Session')]$Session
    )

    $rateLimitInfo = Invoke-RestMethod -Uri "$($Session.Uri)rate_limit" -Headers $Session.Headers -Method GET -ErrorAction Stop
    return $rateLimitInfo.resources
}

function Wait-GitHubRateLimitReached {
    <#
    .SYNOPSIS
        Sleeps until the rate limit resets if we have exhausted our API calls.
    .DESCRIPTION
        Checks the remaining calls and reset timestamp. If remaining is 0,
        sleeps until the reset time. After sleeping, refreshes the GitHub App
        token since it likely expired during the wait.
    #>
    Param(
        [Parameter(Mandatory=$true)]
        [PSObject]$RateLimitInfo,

        [Parameter(Mandatory=$true)]
        [PSTypeName('GitHound.Session')]$Session
    )

    $resetTime = $RateLimitInfo.reset
    $timeNow = [DateTimeOffset]::Now.ToUnixTimeSeconds()
    $timeToSleep = $resetTime - $timeNow

    if ($RateLimitInfo.remaining -eq 0 -and $timeToSleep -gt 0) {
        $resetLocal = ([System.DateTimeOffset]::FromUnixTimeSeconds($resetTime)).LocalDateTime
        Write-Host "[!] Rate limit exhausted (0 remaining). Sleeping for $timeToSleep seconds until $($resetLocal.ToString('HH:mm:ss'))..." -ForegroundColor Yellow
        Start-Sleep -Seconds ($timeToSleep + 2)

        # Refresh token after sleeping - app tokens expire in 1 hour
        $null = Update-GitHubSessionToken -Session $Session -Force
        Write-Host "[+] Rate limit reset. Token refreshed. Resuming..." -ForegroundColor Green
    }
}

function Wait-GitHubRestRateLimit {
    <#
    .SYNOPSIS
        Checks the REST API rate limit and waits if exhausted.
    #>
    Param(
        [Parameter(Mandatory=$true)]
        [PSTypeName('GitHound.Session')]$Session
    )

    # Proactively refresh token if expiring soon
    $null = Update-GitHubSessionToken -Session $Session

    try {
        $rateLimitInfo = Get-RateLimitInformation -Session $Session
        Wait-GitHubRateLimitReached -RateLimitInfo $rateLimitInfo.core -Session $Session
    }
    catch {
        Write-Warning "Could not check rate limit: $_"
    }
}

function Wait-GitHubGraphQLRateLimit {
    <#
    .SYNOPSIS
        Checks the GraphQL API rate limit and waits if exhausted.
    #>
    Param(
        [Parameter(Mandatory=$true)]
        [PSTypeName('GitHound.Session')]$Session
    )

    $null = Update-GitHubSessionToken -Session $Session

    try {
        $rateLimitInfo = Get-RateLimitInformation -Session $Session
        Wait-GitHubRateLimitReached -RateLimitInfo $rateLimitInfo.graphql -Session $Session
    }
    catch {
        Write-Warning "Could not check GraphQL rate limit: $_"
    }
}

function Wait-GitHubRateLimit {
    <#
    .SYNOPSIS
        Pre-phase rate limit check. Waits if remaining calls are below a threshold.
    .DESCRIPTION
        Called before each collection phase to ensure we have enough API calls
        to make meaningful progress. If below the threshold, waits for reset.
    #>
    Param(
        [Parameter(Mandatory=$true)]
        [PSTypeName('GitHound.Session')]$Session,

        [Parameter(Mandatory=$false)]
        [int]$MinRemaining = 100
    )

    $null = Update-GitHubSessionToken -Session $Session

    try {
        $rateLimitInfo = Get-RateLimitInformation -Session $Session
        $core = $rateLimitInfo.core
        $resetLocal = ([System.DateTimeOffset]::FromUnixTimeSeconds($core.reset)).LocalDateTime

        Write-Host "[*] Rate limit: $($core.remaining)/$($core.limit) remaining (resets at $($resetLocal.ToString('HH:mm:ss')))"

        if ($core.remaining -lt $MinRemaining) {
            $timeToSleep = $core.reset - [DateTimeOffset]::Now.ToUnixTimeSeconds()
            if ($timeToSleep -gt 0) {
                Write-Host "[!] Rate limit low ($($core.remaining) remaining). Sleeping $timeToSleep seconds until $($resetLocal.ToString('HH:mm:ss'))..." -ForegroundColor Yellow
                Start-Sleep -Seconds ($timeToSleep + 2)

                # Refresh token after sleeping - app tokens expire in 1 hour
                $null = Update-GitHubSessionToken -Session $Session -Force
                Write-Host "[+] Rate limit reset. Token refreshed. Resuming..." -ForegroundColor Green
            }
        }
    }
    catch {
        Write-Warning "Could not check rate limit: $_. Continuing..."
    }
}

function Get-PacedChunkInfo {
    <#
    .SYNOPSIS
        Calculates chunk size and per-worker delay for paced REST execution.
    .DESCRIPTION
        Queries the GitHub REST rate limit and computes how many repos can fit
        in the current rate limit budget, plus the delay each parallel worker
        should sleep between calls to spread requests evenly.
    #>
    Param(
        [Parameter(Mandatory=$true)]
        [PSTypeName('GitHound.Session')]$Session,

        [Parameter(Mandatory=$false)]
        [decimal]$CallsPerRepo = 1,

        [Parameter(Mandatory=$false)]
        [int]$ThrottleLimit = 25
    )

    $null = Update-GitHubSessionToken -Session $Session

    $rateLimitInfo = Get-RateLimitInformation -Session $Session
    $core = $rateLimitInfo.core
    $remaining = [int]$core.remaining
    $resetUnix = [long]$core.reset
    $secondsToReset = [Math]::Max($resetUnix - [DateTimeOffset]::Now.ToUnixTimeSeconds(), 1)

    # Use 90% of remaining budget to leave headroom for retries
    $chunkSize = [Math]::Floor($remaining * 0.9 / $CallsPerRepo)
    $chunkSize = [Math]::Max($chunkSize, 0)

    $delayMs = 0
    if ($chunkSize -gt 0) {
        # Spread calls evenly: total seconds / (chunkSize / workers) = seconds per worker-call
        $callsPerWorker = [Math]::Max($chunkSize / $ThrottleLimit, 1)
        $delayMs = [Math]::Floor(($secondsToReset * 1000) / $callsPerWorker)
        # Cap delay at 60 seconds - anything longer indicates very low budget
        $delayMs = [Math]::Min($delayMs, 60000)
    }

    $resetLocal = ([System.DateTimeOffset]::FromUnixTimeSeconds($resetUnix)).LocalDateTime

    [PSCustomObject]@{
        ChunkSize    = [int]$chunkSize
        DelayMs      = [int]$delayMs
        Remaining    = $remaining
        ResetAt      = $resetLocal
        SecondsToReset = [int]$secondsToReset
    }
}

# ===========================================
# REST API Helper
# ===========================================
function Invoke-GitHubRest {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [PSTypeName('GitHound.Session')]$Session,

        [Parameter(Mandatory=$true)]
        [string]$Path,

        [Parameter(Mandatory=$false)]
        [string]$Method = 'GET'
    )

    # Proactively refresh token if expiring soon
    $null = Update-GitHubSessionToken -Session $Session

    $requestSuccessful = $false
    $retryCount = 0
    $uri = "$($Session.Uri)$Path"

    while (-not $requestSuccessful -and $retryCount -lt 5) {
        try {
            $result = Invoke-RestMethod -Uri $uri -Headers $Session.Headers -Method $Method
            $requestSuccessful = $true
            Add-GitHoundRestApiCall

            return $result
        }
        catch {
            $statusCode = $_.Exception.Response.StatusCode

            # Handle token expiration (401 Unauthorized)
            if ($statusCode -eq 401) {
                Write-Warning "Token expired. Refreshing..."
                try {
                    $null = Update-GitHubSessionToken -Session $Session -Force
                    $retryCount++
                    continue
                }
                catch {
                    throw "Authentication failed and token refresh failed: $_"
                }
            }

            # Handle rate limiting (429 or 403)
            if ($statusCode -eq 429 -or $statusCode -eq 403) {
                $retryCount++
                Write-Warning "Rate limit hit. Checking rate limit status... (Retry $retryCount/5)"
                Wait-GitHubRestRateLimit -Session $Session
            }
            elseif ($statusCode -eq 404) {
                # Resource not found - return empty result
                return $null
            }
            else {
                throw $_
            }
        }
    }

    if (-not $requestSuccessful) {
        throw "Failed after 5 retry attempts due to rate limiting"
    }
}

function Add-GitHoundRestApiCall {
    if (-not $script:GitHoundMetrics.Enabled) { return }
    $script:GitHoundMetrics.TotalApiCalls++
    $phase = $script:GitHoundMetrics.CurrentPhase
    if ($phase -and $script:GitHoundMetrics.Phases.ContainsKey($phase)) {
        $script:GitHoundMetrics.Phases[$phase].ApiCalls++
        if (-not $script:GitHoundMetrics.Phases[$phase].ContainsKey('RestCalls')) {
            $script:GitHoundMetrics.Phases[$phase].RestCalls = 0
        }
        $script:GitHoundMetrics.Phases[$phase].RestCalls++
    }
}

# ===========================================
# Batched GraphQL Query Builder
# ===========================================
function New-BatchedRepoDetailsQuery {
    <#
    .SYNOPSIS
        Builds a batched GraphQL query using aliases to fetch details for multiple repositories.

    .DESCRIPTION
        Creates a single GraphQL query that fetches branches, protection rules, collaborators,
        and environments for multiple repositories using GraphQL aliases.

    .PARAMETER Repositories
        Array of repository objects with properties.name and properties.full_name.

    .PARAMETER OrgLogin
        The organization login name.

    .PARAMETER IncludeBranches
        Include branch refs in the query.

    .PARAMETER IncludeProtection
        Include branch protection rules in the query.

    .PARAMETER IncludeCollaborators
        Include direct collaborators in the query.

    .PARAMETER IncludeEnvironments
        Include environments in the query.

    .OUTPUTS
        A GraphQL query string with aliases for each repository.
    #>
    Param(
        [Parameter(Mandatory=$true)]
        [array]$Repositories,

        [Parameter(Mandatory=$true)]
        [string]$OrgLogin,

        [switch]$IncludeBranches = $true,
        [switch]$IncludeProtection = $true,
        [switch]$IncludeCollaborators = $true,
        [switch]$IncludeEnvironments = $true
    )

    $queryParts = New-Object System.Collections.ArrayList

    for ($i = 0; $i -lt $Repositories.Count; $i++) {
        $repo = $Repositories[$i]
        $repoName = $repo.properties.name
        $alias = "repo$i"

        $repoQuery = @"
    $alias`: repository(owner: "$OrgLogin", name: "$repoName") {
        id
        databaseId
        name
        nameWithOwner
"@

        if ($IncludeBranches) {
            $repoQuery += @"

        refs(refPrefix: "refs/heads/", first: 50) {
            pageInfo { hasNextPage endCursor }
            nodes {
                id
                name
                target {
                    ... on Commit { oid url }
                }
            }
        }
"@
        }

        if ($IncludeProtection) {
            $repoQuery += @"

        branchProtectionRules(first: 50) {
            nodes {
                id
                pattern
                requiresApprovingReviews
                requiredApprovingReviewCount
                requiresCodeOwnerReviews
                requiresStatusChecks
                requiresStrictStatusChecks
                restrictsPushes
                restrictsReviewDismissals
                allowsForcePushes
                allowsDeletions
                isAdminEnforced
                lockBranch
                requireLastPushApproval
                bypassPullRequestAllowances(first: 25) {
                    nodes {
                        actor {
                            ... on User { id login }
                            ... on Team { id name }
                        }
                    }
                }
                pushAllowances(first: 25) {
                    nodes {
                        actor {
                            ... on User { id login }
                            ... on Team { id name }
                        }
                    }
                }
            }
        }
"@
        }

        if ($IncludeCollaborators) {
            $repoQuery += @"

        collaborators(first: 50, affiliation: DIRECT) {
            pageInfo { hasNextPage }
            edges {
                permission
                node { id login }
            }
        }
"@
        }

        if ($IncludeEnvironments) {
            $repoQuery += @"

        environments(first: 50) {
            nodes {
                id
                databaseId
                name
            }
        }
"@
        }

        $repoQuery += "`n    }"
        $null = $queryParts.Add($repoQuery)
    }

    $fullQuery = "query BatchedRepoDetails {`n" + ($queryParts -join "`n") + "`n}"
    return $fullQuery
}

function Get-GraphQLBatchedRepoDetails {
    <#
    .SYNOPSIS
        Fetches repository details for multiple repos in a single GraphQL call using batched aliases.

    .DESCRIPTION
        Uses batched alias queries to fetch branches, protection rules, collaborators, and environments
        for 10-15 repositories at once, significantly reducing API calls.

    .PARAMETER Session
        A GitHound.Session object used for authentication.

    .PARAMETER OrgLogin
        The organization login name.

    .PARAMETER OrgId
        The organization node ID.

    .PARAMETER Repositories
        Array of repository objects to process.

    .PARAMETER BatchSize
        Number of repositories to fetch per batch. Default 10.

    .PARAMETER ProcessedRepoIds
        HashSet of already processed repo IDs (for resume support).

    .OUTPUTS
        PSCustomObject with Nodes and Edges arrays.
    #>
    Param(
        [Parameter(Mandatory=$true)]
        [PSTypeName('GitHound.Session')]$Session,

        [Parameter(Mandatory=$true)]
        [string]$OrgLogin,

        [Parameter(Mandatory=$true)]
        [string]$OrgId,

        [Parameter(Mandatory=$true)]
        [array]$Repositories,

        [Parameter(Mandatory=$false)]
        [int]$BatchSize = 10,

        [Parameter(Mandatory=$false)]
        [System.Collections.Generic.HashSet[string]]$ProcessedRepoIds = $null
    )

    $nodes = New-Object System.Collections.ArrayList
    $edges = New-Object System.Collections.ArrayList
    $totalRepos = $Repositories.Count
    $processedCount = 0
    $batchNum = 0

    # Filter out already processed repos if resuming
    if ($null -ne $ProcessedRepoIds -and $ProcessedRepoIds.Count -gt 0) {
        $Repositories = $Repositories | Where-Object { -not $ProcessedRepoIds.Contains($_.id) }
        $processedCount = $totalRepos - $Repositories.Count
        Write-Host "[*] Resuming: $processedCount repos already processed, $($Repositories.Count) remaining"
    }

    # Helper: Process the GraphQL result for a batch of repos
    $ProcessBatchResult = {
        param($result, $batch)
        for ($j = 0; $j -lt $batch.Count; $j++) {
            $repo = $batch[$j]
            $repoData = $result.data."repo$j"

            if (-not $repoData) { continue }

            $repoId = $repo.id
            $repoName = $repo.properties.name
            $repoFullName = $repo.properties.full_name

            # Build protection rules map
            $protectionRules = @{}
            if ($repoData.branchProtectionRules) {
                foreach ($rule in $repoData.branchProtectionRules.nodes) {
                    $protectionRules[$rule.pattern] = $rule
                }
            }

            # Process branches
            if ($repoData.refs) {
                foreach ($branch in $repoData.refs.nodes) {
                    $branchId = [System.BitConverter]::ToString(
                        [System.Security.Cryptography.MD5]::Create().ComputeHash(
                            [System.Text.Encoding]::UTF8.GetBytes("${OrgId}_${repoFullName}_$($branch.name)")
                        )
                    ).Replace('-', '')

                    # Find matching protection rule
                    $protection = $null
                    foreach ($pattern in $protectionRules.Keys) {
                        if ($branch.name -like $pattern -or $branch.name -eq $pattern) {
                            $protection = $protectionRules[$pattern]
                            break
                        }
                    }

                    $props = [pscustomobject]@{
                        name = "$repoName\$($branch.name)"
                        id = $branchId
                        short_name = $branch.name
                        commit_hash = Normalize-Null $branch.target.oid
                        commit_url = Normalize-Null $branch.target.url
                        protected = ($null -ne $protection)
                        organization = $OrgLogin
                        organization_id = $OrgId
                        repository_name = $repoFullName
                        repository_id = $repoId
                        protection_enforce_admins = $false
                        protection_lock_branch = $false
                        protection_required_pull_request_reviews = $false
                        protection_required_approving_review_count = 0
                        protection_require_code_owner_reviews = $false
                        protection_require_last_push_approval = $false
                        protection_push_restrictions = $false
                        query_branch_write = "MATCH p=(:GHUser)-[:GHCanWriteBranch|GHCanEditAndWriteBranch]->(:GHBranch {objectid:'$($branchId)'}) RETURN p"
                    }

                    if ($protection) {
                        $props.protection_enforce_admins = $protection.isAdminEnforced
                        $props.protection_lock_branch = $protection.lockBranch
                        $props.protection_required_pull_request_reviews = $protection.requiresApprovingReviews
                        $props.protection_required_approving_review_count = $protection.requiredApprovingReviewCount
                        $props.protection_require_code_owner_reviews = $protection.requiresCodeOwnerReviews
                        $props.protection_require_last_push_approval = $protection.requireLastPushApproval
                        $props.protection_push_restrictions = ($protection.pushAllowances.nodes.Count -gt 0)

                        # Bypass PR allowances
                        foreach ($allowance in $protection.bypassPullRequestAllowances.nodes) {
                            if ($allowance.actor.id) {
                                $null = $edges.Add((New-GitHoundEdge -Kind 'GHBypassRequiredPullRequest' -StartId $allowance.actor.id -EndId $branchId -Properties @{ traversable = $false }))
                            }
                        }

                        # Push allowances
                        foreach ($allowance in $protection.pushAllowances.nodes) {
                            if ($allowance.actor.id) {
                                $null = $edges.Add((New-GitHoundEdge -Kind 'GHRestrictionsCanPush' -StartId $allowance.actor.id -EndId $branchId -Properties @{ traversable = $false }))
                            }
                        }
                    }

                    $null = $nodes.Add((New-GitHoundNode -Id $branchId -Kind 'GHBranch' -Properties $props))
                    $null = $edges.Add((New-GitHoundEdge -Kind 'GHHasBranch' -StartId $repoId -EndId $branchId -Properties @{ traversable = $true }))
                }
            }

            # Process environments (basic info only - secrets need REST)
            if ($repoData.environments) {
                foreach ($env in $repoData.environments.nodes) {
                    $envProps = [pscustomobject]@{
                        name = "$repoName\$($env.name)"
                        id = Normalize-Null $env.databaseId
                        node_id = Normalize-Null $env.id
                        organization = $OrgLogin
                        organization_id = $OrgId
                        repository_name = $repoFullName
                        repository_id = $repoId
                        short_name = Normalize-Null $env.name
                        can_admins_bypass = ""
                    }

                    $null = $nodes.Add((New-GitHoundNode -Id $env.id -Kind 'GHEnvironment' -Properties $envProps))
                    $null = $edges.Add((New-GitHoundEdge -Kind 'GHHasEnvironment' -StartId $repoId -EndId $env.id -Properties @{ traversable = $true }))
                }
            }

            $processedCount++
        }
    }

    # Process in batches with adaptive retry and split on failure
    for ($i = 0; $i -lt $Repositories.Count; $i += $BatchSize) {
        $batchNum++
        $batch = $Repositories[$i..([Math]::Min($i + $BatchSize - 1, $Repositories.Count - 1))]

        # Queue for adaptive splitting: start with the full batch
        $batchQueue = [System.Collections.Queue]::new()
        $batchQueue.Enqueue($batch)

        while ($batchQueue.Count -gt 0) {
            $currentBatch = $batchQueue.Dequeue()
            $success = $false

            # Try up to 2 attempts before splitting
            for ($attempt = 1; $attempt -le 2; $attempt++) {
                try {
                    $query = New-BatchedRepoDetailsQuery -Repositories $currentBatch -OrgLogin $OrgLogin
                    $result = Invoke-GitHubGraphQL -Session $Session -Query $query

                    # Process the results
                    & $ProcessBatchResult $result $currentBatch
                    $success = $true
                    break
                }
                catch {
                    if ($attempt -lt 2) {
                        Write-Warning "Batch of $($currentBatch.Count) repos failed (attempt $attempt/2). Retrying in 10 seconds..."
                        Start-Sleep -Seconds 10
                    }
                }
            }

            if (-not $success) {
                if ($currentBatch.Count -gt 1) {
                    # Split the batch in half and re-queue both halves
                    $mid = [Math]::Floor($currentBatch.Count / 2)
                    $firstHalf = $currentBatch[0..($mid - 1)]
                    $secondHalf = $currentBatch[$mid..($currentBatch.Count - 1)]
                    Write-Warning "Batch of $($currentBatch.Count) repos failed after retries. Splitting into batches of $($firstHalf.Count) and $($secondHalf.Count)..."
                    $batchQueue.Enqueue($firstHalf)
                    $batchQueue.Enqueue($secondHalf)
                }
                else {
                    # Single repo still failing - skip it
                    Write-Warning "Skipping repo $($currentBatch[0].properties.full_name) after repeated failures"
                    $processedCount++
                }
            }
        }

        Write-Host "[*] batched-details: Processed $processedCount/$totalRepos repositories (batch $batchNum)..."
    }

    [PSCustomObject]@{
        Nodes = $nodes
        Edges = $edges
    }
}

function Invoke-PacedRestPhase {
    <#
    .SYNOPSIS
        Wraps a REST phase with chunked execution and even-spread delay for pacing.
    .DESCRIPTION
        Splits repos into hour-sized chunks based on current rate limit budget.
        Within each chunk, passes a per-worker delay so calls are evenly distributed.
        Between chunks, refreshes the token. Merges results from all chunks.
    #>
    Param(
        [Parameter(Mandatory=$true)]
        [PSTypeName('GitHound.Session')]$Session,

        [Parameter(Mandatory=$true)]
        [array]$Repositories,

        [Parameter(Mandatory=$false)]
        [decimal]$CallsPerRepo = 1,

        [Parameter(Mandatory=$false)]
        [int]$ThrottleLimit = 25,

        [Parameter(Mandatory=$true)]
        [string]$PhaseName,

        [Parameter(Mandatory=$true)]
        [scriptblock]$InvokePhase
    )

    $allNodes = New-Object System.Collections.ArrayList
    $allEdges = New-Object System.Collections.ArrayList
    $totalRepos = $Repositories.Count
    $processedSoFar = 0
    $chunkNum = 0

    while ($processedSoFar -lt $totalRepos) {
        $chunkNum++
        $remaining = $totalRepos - $processedSoFar

        # Calculate chunk size and delay from current rate limit
        try {
            $chunkInfo = Get-PacedChunkInfo -Session $Session -CallsPerRepo $CallsPerRepo -ThrottleLimit $ThrottleLimit
        }
        catch {
            Write-Warning "[Paced] Could not query rate limit: $_. Using conservative defaults."
            $chunkInfo = [PSCustomObject]@{
                ChunkSize = [Math]::Min(100, $remaining)
                DelayMs = 5000
                Remaining = 0
                ResetAt = (Get-Date).AddMinutes(60)
                SecondsToReset = 3600
            }
        }

        $chunkSize = $chunkInfo.ChunkSize

        # If chunk size is 0, we need to wait for rate limit reset
        if ($chunkSize -le 0) {
            $waitSec = $chunkInfo.SecondsToReset + 2
            Write-Host "[Paced] ${PhaseName}: Rate limit exhausted ($($chunkInfo.Remaining) remaining). Waiting $waitSec seconds until $($chunkInfo.ResetAt.ToString('HH:mm:ss'))..." -ForegroundColor Yellow
            Start-Sleep -Seconds $waitSec
            $null = Update-GitHubSessionToken -Session $Session -Force
            Write-Host "[Paced] ${PhaseName}: Rate limit reset. Token refreshed." -ForegroundColor Green
            continue
        }

        # Don't overshoot
        $chunkSize = [Math]::Min($chunkSize, $remaining)
        $delayMs = $chunkInfo.DelayMs

        # Slice repos for this chunk
        $startIdx = $processedSoFar
        $endIdx = $startIdx + $chunkSize - 1
        $chunkRepos = $Repositories[$startIdx..$endIdx]

        Write-Host "[Paced] $PhaseName chunk $chunkNum`: $($chunkRepos.Count) repos (${processedSoFar}/${totalRepos} done), delay ${delayMs}ms/worker, budget $($chunkInfo.Remaining) calls, resets $($chunkInfo.ResetAt.ToString('HH:mm:ss'))" -ForegroundColor Cyan

        # Invoke the phase function with this chunk
        $result = & $InvokePhase $chunkRepos $delayMs

        # Merge results
        if ($result.Nodes -and $result.Nodes.Count -gt 0) {
            $null = $allNodes.AddRange(@($result.Nodes))
        }
        if ($result.Edges -and $result.Edges.Count -gt 0) {
            $null = $allEdges.AddRange(@($result.Edges))
        }

        $processedSoFar += $chunkRepos.Count
        Write-Host "[Paced] ${PhaseName}: $processedSoFar/$totalRepos repos complete" -ForegroundColor Cyan

        # Refresh token between chunks if more work remains
        if ($processedSoFar -lt $totalRepos) {
            $null = Update-GitHubSessionToken -Session $Session -Force
        }
    }

    [PSCustomObject]@{
        Nodes = $allNodes
        Edges = $allEdges
    }
}

# ===========================================
# REST API Fallback Functions (Parallel Processing)
# ===========================================

function Get-RestWorkflows {
    <#
    .SYNOPSIS
        Fetches GitHub Actions workflows for repositories using REST API with parallel processing.

    .DESCRIPTION
        Uses REST API to fetch workflows since GitHub GraphQL API doesn't support Actions/Workflows.

    .PARAMETER Session
        A GitHound.Session object.

    .PARAMETER Repositories
        Array of repository node objects.

    .PARAMETER ThrottleLimit
        Maximum parallel threads. Default 25.

    .PARAMETER RequestDelayMs
        Per-worker delay in milliseconds before each API call for pacing. Default 0.
    #>
    Param(
        [Parameter(Mandatory=$true)]
        [PSTypeName('GitHound.Session')]$Session,

        [Parameter(Mandatory=$true)]
        [array]$Repositories,

        [Parameter(Mandatory=$false)]
        [int]$ThrottleLimit = 25,

        [Parameter(Mandatory=$false)]
        [int]$RequestDelayMs = 0
    )

    # Refresh token before parallel operation (parallel workers get a copy of headers)
    $null = Update-GitHubSessionToken -Session $Session

    $nodes = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
    $edges = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
    $totalRepos = $Repositories.Count
    $processedCount = [ref]0

    $Repositories | ForEach-Object -Parallel {
        $repo = $_
        $Session = $using:Session
        $nodes = $using:nodes
        $edges = $using:edges
        $processedCount = $using:processedCount
        $totalRepos = $using:totalRepos
        $RequestDelayMs = $using:RequestDelayMs

        # Import helper functions
        function Normalize-Null { param($Value); if ($null -eq $Value) { return "" }; return $Value }
        function New-GitHoundNode {
            Param([String]$Id, [String[]]$Kind, [PSObject]$Properties)
            [pscustomobject]@{ id = $Id; kinds = @($Kind); properties = $Properties }
        }
        function New-GitHoundEdge {
            Param([String]$Kind, [PSObject]$StartId, [PSObject]$EndId, [Hashtable]$Properties = @{})
            [pscustomobject]@{ kind = $Kind; start = @{ value = $StartId }; end = @{ value = $EndId }; properties = $Properties }
        }
        function Invoke-RestWithRetry {
            param([string]$Uri, [hashtable]$Headers, [string]$ApiBase = 'https://api.github.com/', [int]$MaxRetries = 3)
            for ($r = 0; $r -lt $MaxRetries; $r++) {
                try { return Invoke-RestMethod -Uri $Uri -Headers $Headers -Method GET -ErrorAction Stop }
                catch {
                    $code = $null; if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
                    if (($code -eq 403 -or $code -eq 429) -and $r -lt ($MaxRetries - 1)) {
                        # Query the rate limit endpoint to get exact reset time
                        $waitSec = 60
                        try {
                            $rlInfo = Invoke-RestMethod -Uri "${ApiBase}rate_limit" -Headers $Headers -Method GET -ErrorAction Stop
                            $remaining = $rlInfo.resources.core.remaining
                            $resetUnix = $rlInfo.resources.core.reset
                            if ($remaining -eq 0 -and $resetUnix) {
                                $waitSec = [Math]::Max($resetUnix - [DateTimeOffset]::Now.ToUnixTimeSeconds() + 2, 10)
                            }
                        } catch { }
                        $resetAt = (Get-Date).AddSeconds($waitSec).ToString('HH:mm:ss')
                        Write-Warning "Rate limit hit - waiting $([Math]::Ceiling($waitSec))s until ~$resetAt (retry $($r+1)/$MaxRetries)"
                        Start-Sleep -Seconds $waitSec
                        continue
                    }
                    throw $_
                }
            }
        }

        try {
            if ($RequestDelayMs -gt 0) { Start-Sleep -Milliseconds $RequestDelayMs }
            $uri = "$($Session.Uri)repos/$($repo.properties.full_name)/actions/workflows"
            $result = Invoke-RestWithRetry -Uri $uri -Headers $Session.Headers

            foreach ($workflow in $result.workflows) {
                $props = [pscustomobject]@{
                    name = Normalize-Null "$($repo.properties.name)\$($workflow.name)"
                    id = Normalize-Null $workflow.id
                    node_id = Normalize-Null $workflow.node_id
                    organization_name = Normalize-Null $repo.properties.organization_name
                    organization_id = Normalize-Null $repo.properties.organization_id
                    repository_name = Normalize-Null $repo.properties.full_name
                    repository_id = Normalize-Null $repo.id
                    short_name = Normalize-Null $workflow.name
                    path = Normalize-Null $workflow.path
                    state = Normalize-Null $workflow.state
                    url = Normalize-Null $workflow.url
                }

                $null = $nodes.Add((New-GitHoundNode -Id $workflow.node_id -Kind 'GHWorkflow' -Properties $props))
                $null = $edges.Add((New-GitHoundEdge -Kind 'GHHasWorkflow' -StartId $repo.id -EndId $workflow.node_id -Properties @{ traversable = $false }))
            }
        }
        catch {
            # Silently skip repos where we can't access workflows
        }

        $count = [System.Threading.Interlocked]::Increment($processedCount)
        if ($count % 500 -eq 0 -or $count -eq $totalRepos) {
            Write-Host "[*] workflows: Processed $count/$totalRepos repositories..."
        }
    } -ThrottleLimit $ThrottleLimit

    Write-Host "[*] workflows: Processed $totalRepos repositories"

    [PSCustomObject]@{
        Nodes = @($nodes.ToArray())
        Edges = @($edges.ToArray())
    }
}

function Get-RestEnvironmentsWithSecrets {
    <#
    .SYNOPSIS
        Fetches environments with secrets and deployment branch policies using REST API.

    .DESCRIPTION
        Uses REST API to fetch environment secrets and deployment branch policies
        since GraphQL only provides basic environment info.
    #>
    Param(
        [Parameter(Mandatory=$true)]
        [PSTypeName('GitHound.Session')]$Session,

        [Parameter(Mandatory=$true)]
        [string]$OrgLogin,

        [Parameter(Mandatory=$true)]
        [string]$OrgId,

        [Parameter(Mandatory=$true)]
        [array]$Repositories,

        [Parameter(Mandatory=$false)]
        [int]$ThrottleLimit = 25,

        [Parameter(Mandatory=$false)]
        [int]$RequestDelayMs = 0
    )

    # Refresh token before parallel operation
    $null = Update-GitHubSessionToken -Session $Session

    $nodes = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
    $edges = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
    $totalRepos = $Repositories.Count
    $processedCount = [ref]0

    $Repositories | ForEach-Object -Parallel {
        $repo = $_
        $Session = $using:Session
        $OrgLogin = $using:OrgLogin
        $OrgId = $using:OrgId
        $nodes = $using:nodes
        $edges = $using:edges
        $processedCount = $using:processedCount
        $totalRepos = $using:totalRepos
        $RequestDelayMs = $using:RequestDelayMs

        function Normalize-Null { param($Value); if ($null -eq $Value) { return "" }; return $Value }
        function New-GitHoundNode {
            Param([String]$Id, [String[]]$Kind, [PSObject]$Properties)
            [pscustomobject]@{ id = $Id; kinds = @($Kind); properties = $Properties }
        }
        function New-GitHoundEdge {
            Param([String]$Kind, [PSObject]$StartId, [PSObject]$EndId, [Hashtable]$Properties = @{})
            [pscustomobject]@{ kind = $Kind; start = @{ value = $StartId }; end = @{ value = $EndId }; properties = $Properties }
        }
        function Invoke-RestWithRetry {
            param([string]$Uri, [hashtable]$Headers, [string]$ApiBase = 'https://api.github.com/', [int]$MaxRetries = 3)
            for ($r = 0; $r -lt $MaxRetries; $r++) {
                try { return Invoke-RestMethod -Uri $Uri -Headers $Headers -Method GET -ErrorAction Stop }
                catch {
                    $code = $null; if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
                    if (($code -eq 403 -or $code -eq 429) -and $r -lt ($MaxRetries - 1)) {
                        # Query the rate limit endpoint to get exact reset time
                        $waitSec = 60
                        try {
                            $rlInfo = Invoke-RestMethod -Uri "${ApiBase}rate_limit" -Headers $Headers -Method GET -ErrorAction Stop
                            $remaining = $rlInfo.resources.core.remaining
                            $resetUnix = $rlInfo.resources.core.reset
                            if ($remaining -eq 0 -and $resetUnix) {
                                $waitSec = [Math]::Max($resetUnix - [DateTimeOffset]::Now.ToUnixTimeSeconds() + 2, 10)
                            }
                        } catch { }
                        $resetAt = (Get-Date).AddSeconds($waitSec).ToString('HH:mm:ss')
                        Write-Warning "Rate limit hit - waiting $([Math]::Ceiling($waitSec))s until ~$resetAt (retry $($r+1)/$MaxRetries)"
                        Start-Sleep -Seconds $waitSec
                        continue
                    }
                    throw $_
                }
            }
        }

        try {
            if ($RequestDelayMs -gt 0) { Start-Sleep -Milliseconds $RequestDelayMs }
            $envUri = "$($Session.Uri)repos/$($repo.properties.full_name)/environments"
            $envResult = Invoke-RestWithRetry -Uri $envUri -Headers $Session.Headers

            foreach ($environment in $envResult.environments) {
                # Create environment node with can_admins_bypass from REST data
                $repoName = ($repo.properties.full_name -split '/')[-1]
                $envNodeProps = [pscustomobject]@{
                    name = "$repoName\$($environment.name)"
                    id = Normalize-Null $environment.id
                    node_id = Normalize-Null $environment.node_id
                    organization = Normalize-Null $OrgLogin
                    organization_id = Normalize-Null $OrgId
                    repository_name = Normalize-Null $repo.properties.full_name
                    repository_id = Normalize-Null $repo.id
                    short_name = Normalize-Null $environment.name
                    can_admins_bypass = Normalize-Null $environment.can_admins_bypass
                }
                $null = $nodes.Add((New-GitHoundNode -Id $environment.node_id -Kind 'GHEnvironment' -Properties $envNodeProps))

                # Fetch deployment branch policies if custom policies enabled
                if ($environment.deployment_branch_policy.custom_branch_policies -eq $true) {
                    try {
                        $policyUri = "$($Session.Uri)repos/$($repo.properties.full_name)/environments/$($environment.name)/deployment-branch-policies"
                        $policyResult = Invoke-RestWithRetry -Uri $policyUri -Headers $Session.Headers

                        foreach ($policy in $policyResult.branch_policies) {
                            $branchId = [System.BitConverter]::ToString(
                                [System.Security.Cryptography.MD5]::Create().ComputeHash(
                                    [System.Text.Encoding]::UTF8.GetBytes("${OrgId}_$($repo.properties.full_name)_$($policy.name)")
                                )
                            ).Replace('-', '')
                            $null = $edges.Add((New-GitHoundEdge -Kind 'GHHasEnvironment' -StartId $branchId -EndId $environment.node_id -Properties @{ traversable = $false }))
                        }
                    }
                    catch { }
                }

                # Fetch environment secrets
                try {
                    $secretUri = "$($Session.Uri)repos/$($repo.properties.full_name)/environments/$($environment.name)/secrets"
                    $secretResult = Invoke-RestWithRetry -Uri $secretUri -Headers $Session.Headers

                    foreach ($secret in $secretResult.secrets) {
                        $secretId = "GHEnvironmentSecret_$($environment.node_id)_$($secret.name)"
                        $secretProps = [pscustomobject]@{
                            id = Normalize-Null $secretId
                            name = Normalize-Null $secret.name
                            organization_name = Normalize-Null $OrgLogin
                            organization_id = Normalize-Null $OrgId
                            environment_name = Normalize-Null $environment.name
                            environment_id = Normalize-Null $environment.node_id
                            created_at = Normalize-Null $secret.created_at
                            updated_at = Normalize-Null $secret.updated_at
                        }

                        $null = $nodes.Add((New-GitHoundNode -Id $secretId -Kind 'GHEnvironmentSecret' -Properties $secretProps))
                        $null = $edges.Add((New-GitHoundEdge -Kind 'GHContains' -StartId $environment.node_id -EndId $secretId -Properties @{ traversable = $false }))
                        $null = $edges.Add((New-GitHoundEdge -Kind 'GHHasSecret' -StartId $environment.node_id -EndId $secretId -Properties @{ traversable = $false }))
                    }
                }
                catch { }
            }
        }
        catch { }

        $count = [System.Threading.Interlocked]::Increment($processedCount)
        if ($count % 500 -eq 0 -or $count -eq $totalRepos) {
            Write-Host "[*] environment-secrets: Processed $count/$totalRepos repositories..."
        }
    } -ThrottleLimit $ThrottleLimit

    Write-Host "[*] environment-secrets: Processed $totalRepos repositories"

    [PSCustomObject]@{
        Nodes = @($nodes.ToArray())
        Edges = @($edges.ToArray())
    }
}

function Get-RestSecrets {
    <#
    .SYNOPSIS
        Fetches organization and repository secrets using REST API.
    #>
    Param(
        [Parameter(Mandatory=$true)]
        [PSTypeName('GitHound.Session')]$Session,

        [Parameter(Mandatory=$true)]
        [string]$OrgLogin,

        [Parameter(Mandatory=$true)]
        [string]$OrgId,

        [Parameter(Mandatory=$true)]
        [array]$Repositories,

        [Parameter(Mandatory=$false)]
        [int]$ThrottleLimit = 25,

        [Parameter(Mandatory=$false)]
        [int]$RequestDelayMs = 0
    )

    # Refresh token before operations
    $null = Update-GitHubSessionToken -Session $Session

    $nodes = New-Object System.Collections.ArrayList
    $edges = New-Object System.Collections.ArrayList

    # Fetch organization secrets (not parallel - single call)
    try {
        $orgSecrets = Invoke-GitHubRest -Session $Session -Path "orgs/$OrgLogin/actions/secrets"

        foreach ($secret in $orgSecrets.secrets) {
            $secretId = "GHOrgSecret_${OrgId}_$($secret.name)"
            $props = [pscustomobject]@{
                id = Normalize-Null $secretId
                name = Normalize-Null $secret.name
                organization_name = Normalize-Null $OrgLogin
                organization_id = Normalize-Null $OrgId
                created_at = Normalize-Null $secret.created_at
                updated_at = Normalize-Null $secret.updated_at
                visibility = Normalize-Null $secret.visibility
            }

            $null = $nodes.Add((New-GitHoundNode -Id $secretId -Kind 'GHOrgSecret' -Properties $props))
            $null = $edges.Add((New-GitHoundEdge -Kind 'GHContains' -StartId $OrgId -EndId $secretId -Properties @{ traversable = $false }))
        }
    }
    catch {
        Write-Warning "Could not fetch organization secrets: $_"
    }

    # Fetch repository secrets (parallel)
    $repoNodes = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
    $repoEdges = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
    $secretProcessedCount = [ref]0
    $secretTotalRepos = $Repositories.Count

    $Repositories | ForEach-Object -Parallel {
        $repo = $_
        $Session = $using:Session
        $OrgLogin = $using:OrgLogin
        $OrgId = $using:OrgId
        $repoNodes = $using:repoNodes
        $repoEdges = $using:repoEdges
        $processedCount = $using:secretProcessedCount
        $totalRepos = $using:secretTotalRepos
        $RequestDelayMs = $using:RequestDelayMs

        function Normalize-Null { param($Value); if ($null -eq $Value) { return "" }; return $Value }
        function New-GitHoundNode {
            Param([String]$Id, [String[]]$Kind, [PSObject]$Properties)
            [pscustomobject]@{ id = $Id; kinds = @($Kind); properties = $Properties }
        }
        function New-GitHoundEdge {
            Param([String]$Kind, [PSObject]$StartId, [PSObject]$EndId, [Hashtable]$Properties = @{})
            [pscustomobject]@{ kind = $Kind; start = @{ value = $StartId }; end = @{ value = $EndId }; properties = $Properties }
        }
        function Invoke-RestWithRetry {
            param([string]$Uri, [hashtable]$Headers, [string]$ApiBase = 'https://api.github.com/', [int]$MaxRetries = 3)
            for ($r = 0; $r -lt $MaxRetries; $r++) {
                try { return Invoke-RestMethod -Uri $Uri -Headers $Headers -Method GET -ErrorAction Stop }
                catch {
                    $code = $null; if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
                    if (($code -eq 403 -or $code -eq 429) -and $r -lt ($MaxRetries - 1)) {
                        # Query the rate limit endpoint to get exact reset time
                        $waitSec = 60
                        try {
                            $rlInfo = Invoke-RestMethod -Uri "${ApiBase}rate_limit" -Headers $Headers -Method GET -ErrorAction Stop
                            $remaining = $rlInfo.resources.core.remaining
                            $resetUnix = $rlInfo.resources.core.reset
                            if ($remaining -eq 0 -and $resetUnix) {
                                $waitSec = [Math]::Max($resetUnix - [DateTimeOffset]::Now.ToUnixTimeSeconds() + 2, 10)
                            }
                        } catch { }
                        $resetAt = (Get-Date).AddSeconds($waitSec).ToString('HH:mm:ss')
                        Write-Warning "Rate limit hit - waiting $([Math]::Ceiling($waitSec))s until ~$resetAt (retry $($r+1)/$MaxRetries)"
                        Start-Sleep -Seconds $waitSec
                        continue
                    }
                    throw $_
                }
            }
        }

        try {
            if ($RequestDelayMs -gt 0) { Start-Sleep -Milliseconds $RequestDelayMs }
            # Fetch repo secrets
            $secretUri = "$($Session.Uri)repos/$($repo.properties.full_name)/actions/secrets"
            $result = Invoke-RestWithRetry -Uri $secretUri -Headers $Session.Headers

            foreach ($secret in $result.secrets) {
                $secretId = "GHSecret_$($repo.id)_$($secret.name)"
                $props = [pscustomobject]@{
                    id = Normalize-Null $secretId
                    name = Normalize-Null $secret.name
                    organization_name = Normalize-Null $OrgLogin
                    organization_id = Normalize-Null $OrgId
                    repository_name = Normalize-Null $repo.properties.full_name
                    repository_id = Normalize-Null $repo.id
                    created_at = Normalize-Null $secret.created_at
                    updated_at = Normalize-Null $secret.updated_at
                    visibility = Normalize-Null $secret.visibility
                }

                $null = $repoNodes.Add((New-GitHoundNode -Id $secretId -Kind 'GHRepoSecret' -Properties $props))
                $null = $repoEdges.Add((New-GitHoundEdge -Kind 'GHContains' -StartId $repo.id -EndId $secretId -Properties @{ traversable = $false }))
                $null = $repoEdges.Add((New-GitHoundEdge -Kind 'GHHasSecret' -StartId $repo.id -EndId $secretId -Properties @{ traversable = $false }))
            }

            # Fetch org secrets accessible to this repo
            $orgSecretUri = "$($Session.Uri)repos/$($repo.properties.full_name)/actions/organization-secrets"
            $orgSecretResult = Invoke-RestWithRetry -Uri $orgSecretUri -Headers $Session.Headers

            foreach ($secret in $orgSecretResult.secrets) {
                $secretId = "GHOrgSecret_${OrgId}_$($secret.name)"
                $null = $repoEdges.Add((New-GitHoundEdge -Kind 'GHHasSecret' -StartId $repo.id -EndId $secretId -Properties @{ traversable = $false }))
            }
        }
        catch { }

        $count = [System.Threading.Interlocked]::Increment($processedCount)
        if ($count % 500 -eq 0 -or $count -eq $totalRepos) {
            Write-Host "[*] secrets: Processed $count/$totalRepos repositories..."
        }
    } -ThrottleLimit $ThrottleLimit

    $null = $nodes.AddRange(@($repoNodes.ToArray()))
    $null = $edges.AddRange(@($repoEdges.ToArray()))

    Write-Host "[*] secrets: Processed org secrets and $($Repositories.Count) repositories"

    [PSCustomObject]@{
        Nodes = $nodes
        Edges = $edges
    }
}

function Get-RestTeamRepoPermissions {
    <#
    .SYNOPSIS
        Fetches team permissions on repositories using REST API.
    #>
    Param(
        [Parameter(Mandatory=$true)]
        [PSTypeName('GitHound.Session')]$Session,

        [Parameter(Mandatory=$true)]
        [string]$OrgLogin,

        [Parameter(Mandatory=$true)]
        [array]$Repositories,

        [Parameter(Mandatory=$false)]
        [int]$ThrottleLimit = 25,

        [Parameter(Mandatory=$false)]
        [int]$RequestDelayMs = 0
    )

    # Refresh token before parallel operation
    $null = Update-GitHubSessionToken -Session $Session

    $edges = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
    $totalRepos = $Repositories.Count
    $processedCount = [ref]0

    $Repositories | ForEach-Object -Parallel {
        $repo = $_
        $Session = $using:Session
        $OrgLogin = $using:OrgLogin
        $edges = $using:edges
        $processedCount = $using:processedCount
        $totalRepos = $using:totalRepos
        $RequestDelayMs = $using:RequestDelayMs

        function New-GitHoundEdge {
            Param([String]$Kind, [PSObject]$StartId, [PSObject]$EndId, [Hashtable]$Properties = @{})
            [pscustomobject]@{ kind = $Kind; start = @{ value = $StartId }; end = @{ value = $EndId }; properties = $Properties }
        }
        function Invoke-RestWithRetry {
            param([string]$Uri, [hashtable]$Headers, [string]$ApiBase = 'https://api.github.com/', [int]$MaxRetries = 3)
            for ($r = 0; $r -lt $MaxRetries; $r++) {
                try { return Invoke-RestMethod -Uri $Uri -Headers $Headers -Method GET -ErrorAction Stop }
                catch {
                    $code = $null; if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
                    if (($code -eq 403 -or $code -eq 429) -and $r -lt ($MaxRetries - 1)) {
                        # Query the rate limit endpoint to get exact reset time
                        $waitSec = 60
                        try {
                            $rlInfo = Invoke-RestMethod -Uri "${ApiBase}rate_limit" -Headers $Headers -Method GET -ErrorAction Stop
                            $remaining = $rlInfo.resources.core.remaining
                            $resetUnix = $rlInfo.resources.core.reset
                            if ($remaining -eq 0 -and $resetUnix) {
                                $waitSec = [Math]::Max($resetUnix - [DateTimeOffset]::Now.ToUnixTimeSeconds() + 2, 10)
                            }
                        } catch { }
                        $resetAt = (Get-Date).AddSeconds($waitSec).ToString('HH:mm:ss')
                        Write-Warning "Rate limit hit - waiting $([Math]::Ceiling($waitSec))s until ~$resetAt (retry $($r+1)/$MaxRetries)"
                        Start-Sleep -Seconds $waitSec
                        continue
                    }
                    throw $_
                }
            }
        }

        try {
            if ($RequestDelayMs -gt 0) { Start-Sleep -Milliseconds $RequestDelayMs }
            $teamUri = "$($Session.Uri)repos/$($repo.properties.full_name)/teams"
            $result = Invoke-RestWithRetry -Uri $teamUri -Headers $Session.Headers

            foreach ($team in $result) {
                # Map permission to role ID
                $repoRoleId = switch ($team.permission) {
                    'admin' { [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($repo.id)_admin")) }
                    'maintain' { [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($repo.id)_maintain")) }
                    'push' { [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($repo.id)_write")) }
                    'triage' { [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($repo.id)_triage")) }
                    'pull' { [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($repo.id)_read")) }
                    default { [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($repo.id)_$($team.permission)")) }
                }

                $null = $edges.Add((New-GitHoundEdge -Kind 'GHHasRole' -StartId $team.node_id -EndId $repoRoleId -Properties @{ traversable = $true }))
            }
        }
        catch { }

        $count = [System.Threading.Interlocked]::Increment($processedCount)
        if ($count % 500 -eq 0 -or $count -eq $totalRepos) {
            Write-Host "[*] team-repo-permissions: Processed $count/$totalRepos repositories..."
        }
    } -ThrottleLimit $ThrottleLimit

    Write-Host "[*] team-repo-permissions: Processed $totalRepos repositories"

    [PSCustomObject]@{
        Nodes = @()
        Edges = @($edges.ToArray())
    }
}

function Get-RestCollaborators {
    <#
    .SYNOPSIS
        Fetches direct collaborators on repositories using REST API.
    #>
    Param(
        [Parameter(Mandatory=$true)]
        [PSTypeName('GitHound.Session')]$Session,

        [Parameter(Mandatory=$true)]
        [array]$Repositories,

        [Parameter(Mandatory=$false)]
        [int]$ThrottleLimit = 25,

        [Parameter(Mandatory=$false)]
        [int]$RequestDelayMs = 0
    )

    # Refresh token before parallel operation
    $null = Update-GitHubSessionToken -Session $Session

    $edges = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
    $totalRepos = $Repositories.Count
    $processedCount = [ref]0

    $Repositories | ForEach-Object -Parallel {
        $repo = $_
        $Session = $using:Session
        $edges = $using:edges
        $processedCount = $using:processedCount
        $totalRepos = $using:totalRepos
        $RequestDelayMs = $using:RequestDelayMs

        function New-GitHoundEdge {
            Param([String]$Kind, [PSObject]$StartId, [PSObject]$EndId, [Hashtable]$Properties = @{})
            [pscustomobject]@{ kind = $Kind; start = @{ value = $StartId }; end = @{ value = $EndId }; properties = $Properties }
        }
        function Invoke-RestWithRetry {
            param([string]$Uri, [hashtable]$Headers, [string]$ApiBase = 'https://api.github.com/', [int]$MaxRetries = 3)
            for ($r = 0; $r -lt $MaxRetries; $r++) {
                try { return Invoke-RestMethod -Uri $Uri -Headers $Headers -Method GET -ErrorAction Stop }
                catch {
                    $code = $null; if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
                    if (($code -eq 403 -or $code -eq 429) -and $r -lt ($MaxRetries - 1)) {
                        # Query the rate limit endpoint to get exact reset time
                        $waitSec = 60
                        try {
                            $rlInfo = Invoke-RestMethod -Uri "${ApiBase}rate_limit" -Headers $Headers -Method GET -ErrorAction Stop
                            $remaining = $rlInfo.resources.core.remaining
                            $resetUnix = $rlInfo.resources.core.reset
                            if ($remaining -eq 0 -and $resetUnix) {
                                $waitSec = [Math]::Max($resetUnix - [DateTimeOffset]::Now.ToUnixTimeSeconds() + 2, 10)
                            }
                        } catch { }
                        $resetAt = (Get-Date).AddSeconds($waitSec).ToString('HH:mm:ss')
                        Write-Warning "Rate limit hit - waiting $([Math]::Ceiling($waitSec))s until ~$resetAt (retry $($r+1)/$MaxRetries)"
                        Start-Sleep -Seconds $waitSec
                        continue
                    }
                    throw $_
                }
            }
        }

        try {
            if ($RequestDelayMs -gt 0) { Start-Sleep -Milliseconds $RequestDelayMs }
            $collabUri = "$($Session.Uri)repos/$($repo.properties.full_name)/collaborators?affiliation=direct"
            $result = Invoke-RestWithRetry -Uri $collabUri -Headers $Session.Headers

            foreach ($collaborator in $result) {
                # Map role_name to role ID
                $repoRoleId = switch ($collaborator.role_name) {
                    'admin' { [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($repo.id)_admin")) }
                    'maintain' { [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($repo.id)_maintain")) }
                    'write' { [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($repo.id)_write")) }
                    'triage' { [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($repo.id)_triage")) }
                    'read' { [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($repo.id)_read")) }
                    default { [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($repo.id)_$($collaborator.role_name)")) }
                }

                $null = $edges.Add((New-GitHoundEdge -Kind 'GHHasRole' -StartId $collaborator.node_id -EndId $repoRoleId -Properties @{ traversable = $true }))
            }
        }
        catch { }

        $count = [System.Threading.Interlocked]::Increment($processedCount)
        if ($count % 500 -eq 0 -or $count -eq $totalRepos) {
            Write-Host "[*] collaborators: Processed $count/$totalRepos repositories..."
        }
    } -ThrottleLimit $ThrottleLimit

    Write-Host "[*] collaborators: Processed $totalRepos repositories"

    [PSCustomObject]@{
        Nodes = @()
        Edges = @($edges.ToArray())
    }
}

function Get-RestSecretScanningAlerts {
    <#
    .SYNOPSIS
        Fetches secret scanning alerts for the organization using REST API.
    #>
    Param(
        [Parameter(Mandatory=$true)]
        [PSTypeName('GitHound.Session')]$Session,

        [Parameter(Mandatory=$true)]
        [string]$OrgLogin,

        [Parameter(Mandatory=$true)]
        [string]$OrgId
    )

    $nodes = New-Object System.Collections.ArrayList
    $edges = New-Object System.Collections.ArrayList

    try {
        $alerts = Invoke-GitHubRest -Session $Session -Path "orgs/$OrgLogin/secret-scanning/alerts?state=open&per_page=100"

        foreach ($alert in $alerts) {
            $alertId = "GHSecretScanningAlert_${OrgId}_$($alert.number)"
            $props = [pscustomobject]@{
                id = Normalize-Null $alertId
                name = Normalize-Null "Alert #$($alert.number)"
                number = Normalize-Null $alert.number
                organization_name = Normalize-Null $OrgLogin
                organization_id = Normalize-Null $OrgId
                repository_name = Normalize-Null $alert.repository.full_name
                repository_id = Normalize-Null $alert.repository.node_id
                secret_type = Normalize-Null $alert.secret_type
                secret_type_display_name = Normalize-Null $alert.secret_type_display_name
                state = Normalize-Null $alert.state
                created_at = Normalize-Null $alert.created_at
                html_url = Normalize-Null $alert.html_url
            }

            $null = $nodes.Add((New-GitHoundNode -Id $alertId -Kind 'GHSecretScanningAlert' -Properties $props))
            if ($alert.repository.node_id) {
                $null = $edges.Add((New-GitHoundEdge -Kind 'GHHasSecretScanningAlert' -StartId $alert.repository.node_id -EndId $alertId -Properties @{ traversable = $false }))
            }
        }
    }
    catch {
        Write-Warning "Could not fetch secret scanning alerts: $_"
    }

    Write-Host "[*] secret-scanning: Fetched $($nodes.Count) alerts"

    [PSCustomObject]@{
        Nodes = $nodes
        Edges = $edges
    }
}

function Get-RestAppInstallations {
    <#
    .SYNOPSIS
        Fetches GitHub App installations for the organization using REST API.
    #>
    Param(
        [Parameter(Mandatory=$true)]
        [PSTypeName('GitHound.Session')]$Session,

        [Parameter(Mandatory=$true)]
        [string]$OrgLogin,

        [Parameter(Mandatory=$true)]
        [string]$OrgId
    )

    $nodes = New-Object System.Collections.ArrayList
    $edges = New-Object System.Collections.ArrayList

    try {
        $result = Invoke-GitHubRest -Session $Session -Path "orgs/$OrgLogin/installations?per_page=100"

        foreach ($installation in $result.installations) {
            $installId = "GHAppInstallation_${OrgId}_$($installation.id)"
            $props = [pscustomobject]@{
                id = Normalize-Null $installId
                installation_id = Normalize-Null $installation.id
                name = Normalize-Null $installation.app_slug
                app_id = Normalize-Null $installation.app_id
                app_slug = Normalize-Null $installation.app_slug
                organization_name = Normalize-Null $OrgLogin
                organization_id = Normalize-Null $OrgId
                target_type = Normalize-Null $installation.target_type
                repository_selection = Normalize-Null $installation.repository_selection
                created_at = Normalize-Null $installation.created_at
                updated_at = Normalize-Null $installation.updated_at
            }

            $null = $nodes.Add((New-GitHoundNode -Id $installId -Kind 'GHAppInstallation' -Properties $props))
            $null = $edges.Add((New-GitHoundEdge -Kind 'GHHasAppInstallation' -StartId $OrgId -EndId $installId -Properties @{ traversable = $false }))

            # Add permissions as properties
            if ($installation.permissions) {
                foreach ($perm in $installation.permissions.PSObject.Properties) {
                    $props | Add-Member -NotePropertyName "permission_$($perm.Name)" -NotePropertyValue $perm.Value -Force
                }
            }
        }
    }
    catch {
        Write-Warning "Could not fetch app installations: $_"
    }

    Write-Host "[*] app-installations: Fetched $($nodes.Count) installations"

    [PSCustomObject]@{
        Nodes = $nodes
        Edges = $edges
    }
}

# ===========================================
# GraphQL Queries
# ===========================================

$script:GraphQLQueries = @{

    Organization = @'
query Organization($login: String!) {
    organization(login: $login) {
        id
        databaseId
        login
        name
        description
        url
        websiteUrl
        createdAt
        updatedAt
        isVerified
        membersWithRole {
            totalCount
        }
        repositories {
            totalCount
        }
        teams {
            totalCount
        }
    }
}
'@

    OrganizationMembers = @'
query OrganizationMembers($login: String!, $first: Int!, $after: String) {
    organization(login: $login) {
        id
        membersWithRole(first: $first, after: $after) {
            pageInfo {
                hasNextPage
                endCursor
            }
            edges {
                role
                node {
                    id
                    databaseId
                    login
                    name
                    email
                    company
                    bio
                    createdAt
                    updatedAt
                    isSiteAdmin
                }
            }
        }
    }
}
'@

    OrganizationTeams = @'
query OrganizationTeams($login: String!, $first: Int!, $after: String) {
    organization(login: $login) {
        id
        teams(first: $first, after: $after) {
            pageInfo {
                hasNextPage
                endCursor
            }
            nodes {
                id
                databaseId
                name
                slug
                description
                privacy
                createdAt
                updatedAt
                parentTeam {
                    id
                }
                members(first: 100) {
                    edges {
                        role
                        node {
                            id
                            login
                        }
                    }
                }
            }
        }
    }
}
'@

    OrganizationRepositories = @'
query OrganizationRepositories($login: String!, $first: Int!, $after: String) {
    organization(login: $login) {
        id
        repositories(first: $first, after: $after, orderBy: {field: NAME, direction: ASC}) {
            pageInfo {
                hasNextPage
                endCursor
            }
            nodes {
                id
                databaseId
                name
                nameWithOwner
                description
                url
                homepageUrl
                createdAt
                updatedAt
                pushedAt
                isArchived
                isDisabled
                isFork
                isPrivate
                visibility
                forkCount
                stargazerCount
                defaultBranchRef {
                    name
                }
                owner {
                    id
                    login
                }
            }
        }
    }
}
'@

    RepositoryDetails = @'
query RepositoryDetails($owner: String!, $name: String!) {
    repository(owner: $owner, name: $name) {
        id
        databaseId
        name
        nameWithOwner

        # Branches with protection rules
        refs(refPrefix: "refs/heads/", first: 100) {
            nodes {
                id
                name
                target {
                    ... on Commit {
                        oid
                        url
                    }
                }
            }
        }

        # Branch protection rules
        branchProtectionRules(first: 100) {
            nodes {
                id
                pattern
                requiresApprovingReviews
                requiredApprovingReviewCount
                requiresCodeOwnerReviews
                requiresStatusChecks
                requiresStrictStatusChecks
                restrictsPushes
                restrictsReviewDismissals
                allowsForcePushes
                allowsDeletions
                isAdminEnforced
                lockBranch
                requireLastPushApproval
                bypassPullRequestAllowances(first: 100) {
                    nodes {
                        actor {
                            ... on User {
                                id
                                login
                            }
                            ... on Team {
                                id
                                name
                            }
                        }
                    }
                }
                pushAllowances(first: 100) {
                    nodes {
                        actor {
                            ... on User {
                                id
                                login
                            }
                            ... on Team {
                                id
                                name
                            }
                        }
                    }
                }
            }
        }

        # Collaborators
        collaborators(first: 100, affiliation: DIRECT) {
            edges {
                permission
                node {
                    id
                    login
                }
            }
        }

        # Environments
        environments(first: 100) {
            nodes {
                id
                databaseId
                name
            }
        }
    }
}
'@

    RepositoryBranches = @'
query RepositoryBranches($owner: String!, $name: String!, $first: Int!, $after: String) {
    repository(owner: $owner, name: $name) {
        id
        refs(refPrefix: "refs/heads/", first: $first, after: $after) {
            pageInfo {
                hasNextPage
                endCursor
            }
            nodes {
                id
                name
                target {
                    ... on Commit {
                        oid
                        url
                    }
                }
            }
        }
        branchProtectionRules(first: 100) {
            nodes {
                id
                pattern
                requiresApprovingReviews
                requiredApprovingReviewCount
                requiresCodeOwnerReviews
                isAdminEnforced
                lockBranch
                requireLastPushApproval
                restrictsPushes
                bypassPullRequestAllowances(first: 50) {
                    nodes {
                        actor {
                            ... on User { id login }
                            ... on Team { id name }
                        }
                    }
                }
                pushAllowances(first: 50) {
                    nodes {
                        actor {
                            ... on User { id login }
                            ... on Team { id name }
                        }
                    }
                }
            }
        }
    }
}
'@

    SAMLIdentityProvider = @'
query SAML($login: String!, $count: Int!, $after: String) {
    organization(login: $login) {
        id
        name
        samlIdentityProvider {
            id
            digestMethod
            signatureMethod
            ssoUrl
            issuer
            idpCertificate
            externalIdentities(first: $count, after: $after) {
                pageInfo {
                    hasNextPage
                    endCursor
                }
                totalCount
                nodes {
                    guid
                    id
                    samlIdentity {
                        familyName
                        givenName
                        nameId
                        username
                    }
                    scimIdentity {
                        familyName
                        givenName
                        username
                    }
                    user {
                        id
                        login
                    }
                }
            }
        }
    }
}
'@

}

# ===========================================
# Collection Functions
# ===========================================

function Get-GraphQLOrganization {
    Param(
        [Parameter(Mandatory=$true)]
        [PSTypeName('GitHound.Session')]$Session
    )

    $result = Invoke-GitHubGraphQL -Session $Session -Query $script:GraphQLQueries.Organization -Variables @{
        login = $Session.OrganizationName
    }

    $org = $result.data.organization

    $properties = [pscustomobject]@{
        id = Normalize-Null $org.databaseId
        node_id = Normalize-Null $org.id
        name = Normalize-Null $org.name
        login = Normalize-Null $org.login
        description = Normalize-Null $org.description
        html_url = Normalize-Null $org.url
        blog = Normalize-Null $org.websiteUrl
        is_verified = Normalize-Null $org.isVerified
        created_at = Normalize-Null $org.createdAt
        updated_at = Normalize-Null $org.updatedAt
        total_members = Normalize-Null $org.membersWithRole.totalCount
        total_repos = Normalize-Null $org.repositories.totalCount
        total_teams = Normalize-Null $org.teams.totalCount
    }

    $node = New-GitHoundNode -Id $org.id -Kind 'GHOrganization' -Properties $properties

    [PSCustomObject]@{
        Nodes = @($node)
        Edges = @()
        OrgId = $org.id
        OrgLogin = $org.login
    }
}

function Get-GraphQLUsers {
    Param(
        [Parameter(Mandatory=$true)]
        [PSTypeName('GitHound.Session')]$Session,

        [Parameter(Mandatory=$true)]
        [string]$OrgLogin,

        [Parameter(Mandatory=$true)]
        [string]$OrgId,

        [Parameter(Mandatory=$false)]
        [int]$UserLimit = 0,

        [Parameter(Mandatory=$false)]
        [string]$StartCursor = $null
    )

    $nodes = New-Object System.Collections.ArrayList
    $edges = New-Object System.Collections.ArrayList
    $cursor = $StartCursor
    $hasNextPage = $true
    $totalCollected = 0

    while ($hasNextPage) {
        $result = Invoke-GitHubGraphQL -Session $Session -Query $script:GraphQLQueries.OrganizationMembers -Variables @{
            login = $OrgLogin
            first = 100
            after = $cursor
        }

        $membersData = $result.data.organization.membersWithRole

        foreach ($memberEdge in $membersData.edges) {
            if ($UserLimit -gt 0 -and $totalCollected -ge $UserLimit) {
                $hasNextPage = $false
                break
            }

            $user = $memberEdge.node
            $role = $memberEdge.role

            $properties = [pscustomobject]@{
                id = Normalize-Null $user.databaseId
                node_id = Normalize-Null $user.id
                name = Normalize-Null $user.login
                login = Normalize-Null $user.login
                full_name = Normalize-Null $user.name
                email = Normalize-Null $user.email
                company = Normalize-Null $user.company
                bio = Normalize-Null $user.bio
                site_admin = Normalize-Null $user.isSiteAdmin
                created_at = Normalize-Null $user.createdAt
                organization_name = Normalize-Null $OrgLogin
                organization_id = Normalize-Null $OrgId
                org_role = Normalize-Null $role
            }

            $null = $nodes.Add((New-GitHoundNode -Id $user.id -Kind 'GHUser' -Properties $properties))
            $totalCollected++
        }

        $hasNextPage = $membersData.pageInfo.hasNextPage
        $cursor = $membersData.pageInfo.endCursor

        Write-Host "[*] users: Fetched $totalCollected members..."
    }

    [PSCustomObject]@{
        Nodes = $nodes
        Edges = $edges
    }
}

function Get-GraphQLTeams {
    Param(
        [Parameter(Mandatory=$true)]
        [PSTypeName('GitHound.Session')]$Session,

        [Parameter(Mandatory=$true)]
        [string]$OrgLogin,

        [Parameter(Mandatory=$true)]
        [string]$OrgId,

        [Parameter(Mandatory=$false)]
        [string]$StartCursor = $null
    )

    $nodes = New-Object System.Collections.ArrayList
    $edges = New-Object System.Collections.ArrayList
    $cursor = $StartCursor
    $hasNextPage = $true
    $totalCollected = 0

    while ($hasNextPage) {
        $result = Invoke-GitHubGraphQL -Session $Session -Query $script:GraphQLQueries.OrganizationTeams -Variables @{
            login = $OrgLogin
            first = 100
            after = $cursor
        }

        $teamsData = $result.data.organization.teams

        foreach ($team in $teamsData.nodes) {
            $properties = [pscustomobject]@{
                id = Normalize-Null $team.databaseId
                node_id = Normalize-Null $team.id
                name = Normalize-Null $team.name
                slug = Normalize-Null $team.slug
                description = Normalize-Null $team.description
                privacy = Normalize-Null $team.privacy
                created_at = Normalize-Null $team.createdAt
                updated_at = Normalize-Null $team.updatedAt
                organization_name = Normalize-Null $OrgLogin
                organization_id = Normalize-Null $OrgId
            }

            $null = $nodes.Add((New-GitHoundNode -Id $team.id -Kind 'GHTeam' -Properties $properties))

            # Parent team relationship
            if ($team.parentTeam) {
                $null = $edges.Add((New-GitHoundEdge -Kind 'GHMemberOf' -StartId $team.id -EndId $team.parentTeam.id -Properties @{ traversable = $true }))
            }

            # Team role nodes and member edges
            $memberId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($team.id)_members"))
            $maintainerId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($team.id)_maintainers"))

            $memberProps = [pscustomobject]@{
                id = $memberId
                name = "$OrgLogin/$($team.slug)/members"
                organization_name = $OrgLogin
                organization_id = $OrgId
                team_name = $team.name
                team_id = $team.id
                short_name = 'members'
                type = 'team'
            }
            $null = $nodes.Add((New-GitHoundNode -Id $memberId -Kind 'GHTeamRole','GHRole' -Properties $memberProps))
            $null = $edges.Add((New-GitHoundEdge -Kind 'GHMemberOf' -StartId $memberId -EndId $team.id -Properties @{traversable=$true}))

            $maintainerProps = [pscustomobject]@{
                id = $maintainerId
                name = "$OrgLogin/$($team.slug)/maintainers"
                organization_name = $OrgLogin
                organization_id = $OrgId
                team_name = $team.name
                team_id = $team.id
                short_name = 'maintainers'
                type = 'team'
            }
            $null = $nodes.Add((New-GitHoundNode -Id $maintainerId -Kind 'GHTeamRole','GHRole' -Properties $maintainerProps))
            $null = $edges.Add((New-GitHoundEdge -Kind 'GHMemberOf' -StartId $maintainerId -EndId $team.id -Properties @{traversable=$true}))
            $null = $edges.Add((New-GitHoundEdge -Kind 'GHAddMember' -StartId $maintainerId -EndId $team.id -Properties @{traversable=$true}))

            # Team member edges
            foreach ($memberEdge in $team.members.edges) {
                $targetId = if ($memberEdge.role -eq 'MAINTAINER') { $maintainerId } else { $memberId }
                $null = $edges.Add((New-GitHoundEdge -Kind 'GHHasRole' -StartId $memberEdge.node.id -EndId $targetId -Properties @{traversable=$true}))
            }

            $totalCollected++
        }

        $hasNextPage = $teamsData.pageInfo.hasNextPage
        $cursor = $teamsData.pageInfo.endCursor

        Write-Host "[*] teams: Fetched $totalCollected teams..."
    }

    [PSCustomObject]@{
        Nodes = $nodes
        Edges = $edges
    }
}

function Get-GraphQLRepositories {
    Param(
        [Parameter(Mandatory=$true)]
        [PSTypeName('GitHound.Session')]$Session,

        [Parameter(Mandatory=$true)]
        [string]$OrgLogin,

        [Parameter(Mandatory=$true)]
        [string]$OrgId,

        [Parameter(Mandatory=$false)]
        [string]$RepoFilter = '',

        [Parameter(Mandatory=$false)]
        [string]$RepoVisibility = 'all',

        [Parameter(Mandatory=$false)]
        [string]$StartCursor = $null
    )

    $nodes = New-Object System.Collections.ArrayList
    $edges = New-Object System.Collections.ArrayList
    $cursor = $StartCursor
    $hasNextPage = $true
    $totalCollected = 0

    while ($hasNextPage) {
        $result = Invoke-GitHubGraphQL -Session $Session -Query $script:GraphQLQueries.OrganizationRepositories -Variables @{
            login = $OrgLogin
            first = 100
            after = $cursor
        }

        $reposData = $result.data.organization.repositories

        foreach ($repo in $reposData.nodes) {
            # Apply filters
            if ($RepoFilter -ne '' -and $repo.name -notlike $RepoFilter) { continue }
            if ($RepoVisibility -ne 'all' -and $repo.visibility.ToLower() -ne $RepoVisibility.ToLower()) { continue }

            $properties = [pscustomobject]@{
                id = Normalize-Null $repo.databaseId
                node_id = Normalize-Null $repo.id
                name = Normalize-Null $repo.name
                full_name = Normalize-Null $repo.nameWithOwner
                description = Normalize-Null $repo.description
                html_url = Normalize-Null $repo.url
                homepage = Normalize-Null $repo.homepageUrl
                created_at = Normalize-Null $repo.createdAt
                updated_at = Normalize-Null $repo.updatedAt
                pushed_at = Normalize-Null $repo.pushedAt
                archived = Normalize-Null $repo.isArchived
                disabled = Normalize-Null $repo.isDisabled
                fork = Normalize-Null $repo.isFork
                private = Normalize-Null $repo.isPrivate
                visibility = Normalize-Null $repo.visibility
                forks = Normalize-Null $repo.forkCount
                stargazers_count = Normalize-Null $repo.stargazerCount
                default_branch = Normalize-Null $repo.defaultBranchRef.name
                organization_name = Normalize-Null $OrgLogin
                organization_id = Normalize-Null $OrgId
                owner_id = Normalize-Null $repo.owner.id
                owner_name = Normalize-Null $repo.owner.login
            }

            $null = $nodes.Add((New-GitHoundNode -Id $repo.id -Kind 'GHRepository' -Properties $properties))
            $null = $edges.Add((New-GitHoundEdge -Kind 'GHOwns' -StartId $OrgId -EndId $repo.id -Properties @{ traversable = $true }))

            $totalCollected++
        }

        $hasNextPage = $reposData.pageInfo.hasNextPage
        $cursor = $reposData.pageInfo.endCursor

        Write-Host "[*] repos: Fetched $totalCollected repositories..."
    }

    [PSCustomObject]@{
        Nodes = $nodes
        Edges = $edges
    }
}

function Get-GraphQLBranches {
    Param(
        [Parameter(Mandatory=$true)]
        [PSTypeName('GitHound.Session')]$Session,

        [Parameter(Mandatory=$true)]
        [string]$OrgLogin,

        [Parameter(Mandatory=$true)]
        [string]$OrgId,

        [Parameter(Mandatory=$true)]
        [array]$Repositories
    )

    $nodes = New-Object System.Collections.ArrayList
    $edges = New-Object System.Collections.ArrayList
    $totalRepos = $Repositories.Count
    $processedRepos = 0

    foreach ($repo in $Repositories) {
        $processedRepos++
        $repoName = $repo.properties.name
        $repoId = $repo.id
        $repoFullName = $repo.properties.full_name

        try {
            $result = Invoke-GitHubGraphQL -Session $Session -Query $script:GraphQLQueries.RepositoryBranches -Variables @{
                owner = $OrgLogin
                name = $repoName
                first = 100
                after = $null
            }

            $repoData = $result.data.repository
            if (-not $repoData) { continue }

            # Build protection rules map
            $protectionRules = @{}
            foreach ($rule in $repoData.branchProtectionRules.nodes) {
                $protectionRules[$rule.pattern] = $rule
            }

            # Process branches
            foreach ($branch in $repoData.refs.nodes) {
                $branchId = [System.BitConverter]::ToString([System.Security.Cryptography.MD5]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes("${OrgId}_${repoFullName}_$($branch.name)"))).Replace('-', '')

                # Find matching protection rule
                $protection = $null
                foreach ($pattern in $protectionRules.Keys) {
                    if ($branch.name -like $pattern -or $branch.name -eq $pattern) {
                        $protection = $protectionRules[$pattern]
                        break
                    }
                }

                $props = [pscustomobject]@{
                    name = "$repoName\$($branch.name)"
                    id = $branchId
                    short_name = $branch.name
                    commit_hash = Normalize-Null $branch.target.oid
                    commit_url = Normalize-Null $branch.target.url
                    protected = ($null -ne $protection)
                    organization = $OrgLogin
                    organization_id = $OrgId
                    repository_name = $repoFullName
                    repository_id = $repoId
                    protection_enforce_admins = $false
                    protection_lock_branch = $false
                    protection_required_pull_request_reviews = $false
                    protection_required_approving_review_count = 0
                    protection_require_code_owner_reviews = $false
                    protection_require_last_push_approval = $false
                    protection_push_restrictions = $false
                    query_branch_write = "MATCH p=(:GHUser)-[:GHCanWriteBranch|GHCanEditAndWriteBranch]->(:GHBranch {objectid:'$($branchId)'}) RETURN p"
                }

                if ($protection) {
                    $props.protection_enforce_admins = $protection.isAdminEnforced
                    $props.protection_lock_branch = $protection.lockBranch
                    $props.protection_required_pull_request_reviews = $protection.requiresApprovingReviews
                    $props.protection_required_approving_review_count = $protection.requiredApprovingReviewCount
                    $props.protection_require_code_owner_reviews = $protection.requiresCodeOwnerReviews
                    $props.protection_require_last_push_approval = $protection.requireLastPushApproval
                    $props.protection_push_restrictions = ($protection.pushAllowances.nodes.Count -gt 0)

                    # Bypass PR allowances
                    foreach ($allowance in $protection.bypassPullRequestAllowances.nodes) {
                        if ($allowance.actor.id) {
                            $null = $edges.Add((New-GitHoundEdge -Kind 'GHBypassRequiredPullRequest' -StartId $allowance.actor.id -EndId $branchId -Properties @{ traversable = $false }))
                        }
                    }

                    # Push allowances
                    foreach ($allowance in $protection.pushAllowances.nodes) {
                        if ($allowance.actor.id) {
                            $null = $edges.Add((New-GitHoundEdge -Kind 'GHRestrictionsCanPush' -StartId $allowance.actor.id -EndId $branchId -Properties @{ traversable = $false }))
                        }
                    }
                }

                $null = $nodes.Add((New-GitHoundNode -Id $branchId -Kind 'GHBranch' -Properties $props))
                $null = $edges.Add((New-GitHoundEdge -Kind 'GHHasBranch' -StartId $repoId -EndId $branchId -Properties @{ traversable = $true }))
            }
        }
        catch {
            Write-Warning "Failed to fetch branches for $repoFullName : $_"
        }

        if ($processedRepos % 10 -eq 0) {
            Write-Host "[*] branches: Processed $processedRepos/$totalRepos repositories..."
        }
    }

    Write-Host "[*] branches: Completed $totalRepos repositories"

    [PSCustomObject]@{
        Nodes = $nodes
        Edges = $edges
    }
}

function Get-GraphQLOrgRoles {
    Param(
        [Parameter(Mandatory=$true)]
        [PSTypeName('GitHound.Session')]$Session,

        [Parameter(Mandatory=$true)]
        [string]$OrgLogin,

        [Parameter(Mandatory=$true)]
        [string]$OrgId,

        [Parameter(Mandatory=$true)]
        [array]$Users
    )

    $nodes = New-Object System.Collections.ArrayList
    $edges = New-Object System.Collections.ArrayList

    # Create org-level role nodes
    $orgOwnersId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("${OrgId}_owners"))
    $orgMembersId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("${OrgId}_members"))

    # Base repo role IDs
    $orgAllRepoReadId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("${OrgId}_all_repo_read"))
    $orgAllRepoTriageId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("${OrgId}_all_repo_triage"))
    $orgAllRepoWriteId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("${OrgId}_all_repo_write"))
    $orgAllRepoMaintainId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("${OrgId}_all_repo_maintain"))
    $orgAllRepoAdminId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("${OrgId}_all_repo_admin"))

    # Owners role
    $ownersProps = [pscustomobject]@{
        id = $orgOwnersId
        name = "$OrgLogin/owners"
        organization_name = $OrgLogin
        organization_id = $OrgId
        short_name = 'owners'
        type = 'default'
    }
    $null = $nodes.Add((New-GitHoundNode -Id $orgOwnersId -Kind 'GHOrgRole', 'GHRole' -Properties $ownersProps))
    $null = $edges.Add((New-GitHoundEdge -Kind 'GHCreateRepository' -StartId $orgOwnersId -EndId $OrgId -Properties @{traversable=$false}))
    $null = $edges.Add((New-GitHoundEdge -Kind 'GHInviteMember' -StartId $orgOwnersId -EndId $OrgId -Properties @{traversable=$false}))
    $null = $edges.Add((New-GitHoundEdge -Kind 'GHCreateTeam' -StartId $orgOwnersId -EndId $OrgId -Properties @{traversable=$false}))
    $null = $edges.Add((New-GitHoundEdge -Kind 'GHHasBaseRole' -StartId $orgOwnersId -EndId $orgAllRepoAdminId -Properties @{traversable=$true}))

    # Members role
    $membersProps = [pscustomobject]@{
        id = $orgMembersId
        name = "$OrgLogin/members"
        organization_name = $OrgLogin
        organization_id = $OrgId
        short_name = 'members'
        type = 'default'
    }
    $null = $nodes.Add((New-GitHoundNode -Id $orgMembersId -Kind 'GHOrgRole', 'GHRole' -Properties $membersProps))
    $null = $edges.Add((New-GitHoundEdge -Kind 'GHCreateRepository' -StartId $orgMembersId -EndId $OrgId -Properties @{traversable=$false}))
    $null = $edges.Add((New-GitHoundEdge -Kind 'GHCreateTeam' -StartId $orgMembersId -EndId $OrgId -Properties @{traversable=$false}))

    # Assign users to roles based on their org_role property (from user collection)
    foreach ($user in $Users) {
        $userRole = $user.properties.org_role
        $destId = if ($userRole -eq 'ADMIN') { $orgOwnersId } else { $orgMembersId }
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHHasRole' -StartId $user.id -EndId $destId -Properties @{traversable=$true}))
    }

    [PSCustomObject]@{
        Nodes = $nodes
        Edges = $edges
    }
}

function Get-GraphQLRepoRoles {
    Param(
        [Parameter(Mandatory=$true)]
        [PSTypeName('GitHound.Session')]$Session,

        [Parameter(Mandatory=$true)]
        [string]$OrgLogin,

        [Parameter(Mandatory=$true)]
        [string]$OrgId,

        [Parameter(Mandatory=$true)]
        [array]$Repositories
    )

    $nodes = New-Object System.Collections.ArrayList
    $edges = New-Object System.Collections.ArrayList

    # Base org repo role IDs
    $orgAllRepoReadId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("${OrgId}_all_repo_read"))
    $orgAllRepoTriageId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("${OrgId}_all_repo_triage"))
    $orgAllRepoWriteId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("${OrgId}_all_repo_write"))
    $orgAllRepoMaintainId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("${OrgId}_all_repo_maintain"))
    $orgAllRepoAdminId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("${OrgId}_all_repo_admin"))

    $totalRepos = $Repositories.Count
    $processedRepos = 0

    foreach ($repo in $Repositories) {
        $processedRepos++
        $repoId = $repo.id
        $repoName = $repo.properties.name
        $repoFullName = $repo.properties.full_name

        # Create repo role nodes
        $repoReadId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("${repoId}_read"))
        $repoTriageId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("${repoId}_triage"))
        $repoWriteId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("${repoId}_write"))
        $repoMaintainId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("${repoId}_maintain"))
        $repoAdminId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("${repoId}_admin"))

        # Read role
        $readProps = [pscustomobject]@{
            id = $repoReadId
            name = "$repoFullName/read"
            organization_name = $OrgLogin
            organization_id = $OrgId
            repository_name = $repoName
            repository_id = $repoId
            short_name = 'read'
            type = 'default'
        }
        $null = $nodes.Add((New-GitHoundNode -Id $repoReadId -Kind 'GHRepoRole', 'GHRole' -Properties $readProps))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHReadRepoContents' -StartId $repoReadId -EndId $repoId -Properties @{traversable=$false}))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHHasBaseRole' -StartId $orgAllRepoReadId -EndId $repoReadId -Properties @{traversable=$true}))

        # Write role
        $writeProps = [pscustomobject]@{
            id = $repoWriteId
            name = "$repoFullName/write"
            organization_name = $OrgLogin
            organization_id = $OrgId
            repository_name = $repoName
            repository_id = $repoId
            short_name = 'write'
            type = 'default'
        }
        $null = $nodes.Add((New-GitHoundNode -Id $repoWriteId -Kind 'GHRepoRole', 'GHRole' -Properties $writeProps))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHReadRepoContents' -StartId $repoWriteId -EndId $repoId -Properties @{traversable=$false}))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHWriteRepoContents' -StartId $repoWriteId -EndId $repoId -Properties @{traversable=$false}))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHWriteRepoPullRequests' -StartId $repoWriteId -EndId $repoId -Properties @{traversable=$false}))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHHasBaseRole' -StartId $orgAllRepoWriteId -EndId $repoWriteId -Properties @{traversable=$true}))

        # Admin role
        $adminProps = [pscustomobject]@{
            id = $repoAdminId
            name = "$repoFullName/admin"
            organization_name = $OrgLogin
            organization_id = $OrgId
            repository_name = $repoName
            repository_id = $repoId
            short_name = 'admin'
            type = 'default'
        }
        $null = $nodes.Add((New-GitHoundNode -Id $repoAdminId -Kind 'GHRepoRole', 'GHRole' -Properties $adminProps))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHAdminTo' -StartId $repoAdminId -EndId $repoId -Properties @{traversable=$false}))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHReadRepoContents' -StartId $repoAdminId -EndId $repoId -Properties @{traversable=$false}))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHWriteRepoContents' -StartId $repoAdminId -EndId $repoId -Properties @{traversable=$false}))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHWriteRepoPullRequests' -StartId $repoAdminId -EndId $repoId -Properties @{traversable=$false}))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHManageWebhooks' -StartId $repoAdminId -EndId $repoId -Properties @{traversable=$false}))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHManageDeployKeys' -StartId $repoAdminId -EndId $repoId -Properties @{traversable=$false}))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHBypassBranchProtection' -StartId $repoAdminId -EndId $repoId -Properties @{traversable=$false}))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHEditRepoProtections' -StartId $repoAdminId -EndId $repoId -Properties @{traversable=$false}))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHHasBaseRole' -StartId $orgAllRepoAdminId -EndId $repoAdminId -Properties @{traversable=$true}))

        # Triage role
        $triageProps = [pscustomobject]@{
            id = $repoTriageId
            name = "$repoFullName/triage"
            organization_name = $OrgLogin
            organization_id = $OrgId
            repository_name = $repoName
            repository_id = $repoId
            short_name = 'triage'
            type = 'default'
        }
        $null = $nodes.Add((New-GitHoundNode -Id $repoTriageId -Kind 'GHRepoRole', 'GHRole' -Properties $triageProps))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHHasBaseRole' -StartId $repoTriageId -EndId $repoReadId -Properties @{traversable=$true}))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHHasBaseRole' -StartId $orgAllRepoTriageId -EndId $repoTriageId -Properties @{traversable=$true}))

        # Maintain role
        $maintainProps = [pscustomobject]@{
            id = $repoMaintainId
            name = "$repoFullName/maintain"
            organization_name = $OrgLogin
            organization_id = $OrgId
            repository_name = $repoName
            repository_id = $repoId
            short_name = 'maintain'
            type = 'default'
        }
        $null = $nodes.Add((New-GitHoundNode -Id $repoMaintainId -Kind 'GHRepoRole', 'GHRole' -Properties $maintainProps))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHPushProtectedBranch' -StartId $repoMaintainId -EndId $repoId -Properties @{traversable=$false}))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHHasBaseRole' -StartId $repoMaintainId -EndId $repoWriteId -Properties @{traversable=$true}))
        $null = $edges.Add((New-GitHoundEdge -Kind 'GHHasBaseRole' -StartId $orgAllRepoMaintainId -EndId $repoMaintainId -Properties @{traversable=$true}))

        if ($processedRepos % 50 -eq 0) {
            Write-Host "[*] reporoles: Processed $processedRepos/$totalRepos repositories..."
        }
    }

    Write-Host "[*] reporoles: Completed $totalRepos repositories"

    [PSCustomObject]@{
        Nodes = $nodes
        Edges = $edges
    }
}

function Get-GraphQLSAML {
    Param(
        [Parameter(Mandatory=$true)]
        [PSTypeName('GitHound.Session')]$Session,

        [Parameter(Mandatory=$true)]
        [string]$OrgLogin,

        [Parameter(Mandatory=$true)]
        [string]$OrgId
    )

    $nodes = New-Object System.Collections.ArrayList
    $edges = New-Object System.Collections.ArrayList
    $cursor = $null
    $hasNextPage = $true

    while ($hasNextPage) {
        $result = Invoke-GitHubGraphQL -Session $Session -Query $script:GraphQLQueries.SAMLIdentityProvider -Variables @{
            login = $OrgLogin
            count = 100
            after = $cursor
        }

        $samlProvider = $result.data.organization.samlIdentityProvider
        if (-not $samlProvider) {
            Write-Host "[*] No SAML Identity Provider configured for this organization"
            break
        }

        # Add SAML provider node (only on first iteration)
        if ($cursor -eq $null) {
            # Determine IdP type
            $ForeignUserNodeKind = 'ExternalUser'
            switch -Wildcard ($samlProvider.issuer) {
                'https://auth.pingone.com/*' { $ForeignUserNodeKind = 'PingOneUser' }
                'https://sts.windows.net/*' { $ForeignUserNodeKind = 'AZUser' }
                'http://www.okta.com/*' { $ForeignUserNodeKind = 'OktaUser' }
            }

            $providerProps = [pscustomobject]@{
                name = $samlProvider.id
                node_id = $samlProvider.id
                organization_name = $result.data.organization.name
                organization_id = $result.data.organization.id
                digest_method = Normalize-Null $samlProvider.digestMethod
                signature_method = Normalize-Null $samlProvider.signatureMethod
                sso_url = Normalize-Null $samlProvider.ssoUrl
                issuer = Normalize-Null $samlProvider.issuer
            }

            $null = $nodes.Add((New-GitHoundNode -Id $samlProvider.id -Kind 'GHSamlIdentityProvider' -Properties $providerProps))
            $null = $edges.Add((New-GitHoundEdge -Kind 'GHHasSamlIdentityProvider' -StartId $result.data.organization.id -EndId $samlProvider.id -Properties @{traversable=$false}))
        }

        # Process external identities
        foreach ($identity in $samlProvider.externalIdentities.nodes) {
            $identityProps = [pscustomobject]@{
                name = Normalize-Null $identity.id
                organization_id = $result.data.organization.id
                organization_name = $result.data.organization.name
                saml_identity_family_name = Normalize-Null $identity.samlIdentity.familyName
                saml_identity_given_name = Normalize-Null $identity.samlIdentity.givenName
                saml_identity_name_id = Normalize-Null $identity.samlIdentity.nameId
                saml_identity_username = Normalize-Null $identity.samlIdentity.username
                scim_identity_family_name = Normalize-Null $identity.scimIdentity.familyName
                scim_identity_given_name = Normalize-Null $identity.scimIdentity.givenName
                scim_identity_username = Normalize-Null $identity.scimIdentity.username
                github_username = Normalize-Null $identity.user.login
                github_user_id = Normalize-Null $identity.user.id
            }

            $null = $nodes.Add((New-GitHoundNode -Id $identity.id -Kind 'GHExternalIdentity' -Properties $identityProps))
            $null = $edges.Add((New-GitHoundEdge -Kind 'GHHasExternalIdentity' -StartId $samlProvider.id -EndId $identity.id -Properties @{traversable=$false}))

            $username = if ($identity.samlIdentity.username) { $identity.samlIdentity.username } else { $identity.scimIdentity.username }
            if ($username) {
                $null = $edges.Add((New-GitHoundEdge -Kind 'GHMapsToUser' -StartId $identity.id -EndId $username -EndKind $ForeignUserNodeKind -EndMatchBy 'name' -Properties @{traversable=$false}))
            }

            if ($identity.user.id) {
                $null = $edges.Add((New-GitHoundEdge -Kind 'GHMapsToUser' -StartId $identity.id -EndId $identity.user.id -Properties @{traversable=$false}))
                if ($username) {
                    $null = $edges.Add((New-GitHoundEdge -Kind 'SyncedToGHUser' -StartId $username -StartKind $ForeignUserNodeKind -StartMatchBy 'name' -EndId $identity.user.id -Properties @{traversable=$true}))
                }
            }
        }

        $hasNextPage = $samlProvider.externalIdentities.pageInfo.hasNextPage
        $cursor = $samlProvider.externalIdentities.pageInfo.endCursor

        Write-Host "[*] saml: Fetched $($samlProvider.externalIdentities.nodes.Count) external identities..."
    }

    [PSCustomObject]@{
        Nodes = $nodes
        Edges = $edges
    }
}

# ===========================================
# Main Entry Point
# ===========================================
function Invoke-GitHoundGraphQL {
    <#
    .SYNOPSIS
        GraphQL-based GitHound collector. More efficient than REST API version.

    .DESCRIPTION
        Collects GitHub organization data using GraphQL API and outputs per-phase JSON files for BloodHound ingestion.

    .PARAMETER Session
        A GitHound.Session object used for authentication and API requests.

    .PARAMETER Collect
        Array of collection phases to run. Defaults to 'All'.

    .PARAMETER UserLimit
        Limit number of users to enumerate. 0 means no limit (default).

    .PARAMETER RepoFilter
        Wildcard pattern to filter repositories by name.

    .PARAMETER RepoVisibility
        Filter repositories by visibility: all, public, private, internal.

    .PARAMETER OutputPath
        Base directory path for output.

    .PARAMETER Zip
        If specified, compresses output into a zip archive.

    .PARAMETER Resume
        Path to an existing output folder to resume collection.

    .PARAMETER Metrics
        If specified, enables performance metrics tracking.

    .PARAMETER BatchSize
        Number of repositories to fetch per batched GraphQL call. Default 10.

    .PARAMETER ThrottleLimit
        Maximum parallel threads for REST API fallback calls. Default 25.

    .PARAMETER CheckpointBatchSize
        Number of items to process before saving checkpoint. Default 100.

    .EXAMPLE
        $session = New-GithubSession -OrganizationName "my-org" -Token $token
        Invoke-GitHoundGraphQL -Session $session

    .EXAMPLE
        Invoke-GitHoundGraphQL -Session $session -Collect @('Users', 'Repos', 'Branches', 'Workflows') -Metrics

    .EXAMPLE
        Invoke-GitHoundGraphQL -Session $session -BatchSize 15 -ThrottleLimit 30 -Metrics
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [PSTypeName('GitHound.Session')]$Session,

        [Parameter(Mandatory = $false)]
        [ValidateSet('All', 'Users', 'Teams', 'Repos', 'Branches', 'Environments',
                     'Workflows', 'Secrets', 'TeamRoles', 'OrgRoles', 'RepoRoles',
                     'Collaborators', 'SecretScanning', 'AppInstallations', 'SAML')]
        [string[]]$Collect = @('Users', 'Teams', 'Repos', 'Branches',
                               'Workflows', 'TeamRoles', 'OrgRoles', 'RepoRoles',
                               'Collaborators', 'SecretScanning', 'SAML'),

        [Parameter(Mandatory = $false)]
        [int]$UserLimit = 0,

        [Parameter(Mandatory = $false)]
        [string]$RepoFilter = '',

        [Parameter(Mandatory = $false)]
        [ValidateSet('all', 'public', 'private', 'internal')]
        [string]$RepoVisibility = 'all',

        [Parameter(Mandatory = $false)]
        [string]$OutputPath = './',

        [Parameter(Mandatory = $false)]
        [switch]$Zip,

        [Parameter(Mandatory = $false)]
        [string]$Resume = '',

        [Parameter(Mandatory = $false)]
        [switch]$Metrics,

        [Parameter(Mandatory = $false)]
        [switch]$Paced,

        [Parameter(Mandatory = $false)]
        [int]$BatchSize = 10,

        [Parameter(Mandatory = $false)]
        [int]$ThrottleLimit = 25,

        [Parameter(Mandatory = $false)]
        [int]$CheckpointBatchSize = 100
    )

    # Initialize metrics if enabled
    if ($Metrics) {
        Initialize-GitHoundMetrics
        Write-Host "[*] Metrics tracking enabled" -ForegroundColor Cyan
    }

    $completedPhases = @()
    $phaseProgress = @{}

    # Handle resume
    if ($Resume -ne '') {
        if (-not (Test-Path $Resume)) {
            throw "Resume folder not found: $Resume"
        }

        $checkpoint = Get-GitHoundCheckpoint -OutputFolder $Resume
        if ($null -eq $checkpoint) {
            throw "No checkpoint file found in: $Resume"
        }

        Write-Host "[*] Resuming from checkpoint in: $Resume"
        Write-Host "[*] Previously completed phases: $($checkpoint.completedPhases -join ', ')"

        $timestamp = $checkpoint.timestamp
        $orgId = $checkpoint.orgId
        $outputFolder = $Resume
        $Collect = $checkpoint.collect
        $UserLimit = $checkpoint.userLimit
        $RepoFilter = $checkpoint.repoFilter
        $RepoVisibility = $checkpoint.repoVisibility
        $completedPhases = @($checkpoint.completedPhases)
        $phaseProgress = $checkpoint.phaseProgress
        # Restore batch settings from checkpoint if available
        if ($checkpoint.batchSize) { $BatchSize = $checkpoint.batchSize }
        if ($checkpoint.throttleLimit) { $ThrottleLimit = $checkpoint.throttleLimit }
        if ($checkpoint.paced) { $Paced = [switch]$true }
    } else {
        if ($Collect -contains 'All') {
            $Collect = @('Users', 'Teams', 'Repos', 'Branches', 'Environments',
                         'Workflows', 'Secrets', 'TeamRoles', 'OrgRoles', 'RepoRoles',
                         'Collaborators', 'SecretScanning', 'AppInstallations', 'SAML')
        }
    }

    # Auto-include Repos if dependent phases selected
    $repoDependentPhases = @('Branches', 'RepoRoles', 'Environments', 'Workflows', 'Secrets', 'TeamRoles', 'Collaborators')
    foreach ($phase in $repoDependentPhases) {
        if ($Collect -contains $phase -and $Collect -notcontains 'Repos') {
            Write-Host "[!] Auto-including Repos collection (required dependency for $phase)"
            $Collect = @('Repos') + $Collect
            break
        }
    }

    $writtenFiles = New-Object System.Collections.ArrayList
    $allNodes = New-Object System.Collections.ArrayList
    $allEdges = New-Object System.Collections.ArrayList

    # ===========================================
    # Organization Phase
    # ===========================================
    Start-GitHoundPhaseMetrics -PhaseName 'organization'
    Write-Host "[*] Starting GitHound GraphQL for $($Session.OrganizationName)"
    $org = Get-GraphQLOrganization -Session $Session
    $orgId = $org.OrgId
    $orgLogin = $org.OrgLogin
    Stop-GitHoundPhaseMetrics -PhaseName 'organization'

    # Setup output folder
    if ($Resume -eq '') {
        $timestamp = Get-Date -Format "yyyyMMddHHmmss"
        $folderName = "${timestamp}_${orgId}"
        $outputFolder = Join-Path -Path $OutputPath -ChildPath $folderName

        if (-not (Test-Path $OutputPath)) {
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        }
        New-Item -ItemType Directory -Path $outputFolder -Force | Out-Null
        Write-Host "[*] Output folder: $outputFolder"
    }

    # Helper to save checkpoint
    function Save-Checkpoint {
        $checkpointData = @{
            version = 3
            timestamp = $timestamp
            orgId = $orgId
            completedPhases = $completedPhases
            collect = $Collect
            userLimit = $UserLimit
            repoFilter = $RepoFilter
            repoVisibility = $RepoVisibility
            phaseProgress = $phaseProgress
            batchSize = $BatchSize
            throttleLimit = $ThrottleLimit
            paced = [bool]$Paced
        }
        Save-GitHoundCheckpoint -OutputFolder $outputFolder -Checkpoint $checkpointData
    }

    # Write organization phase
    if ($completedPhases -notcontains 'organization') {
        $orgFile = Write-GitHoundPayload -OutputPath $outputFolder -OrgName $orgId -PhaseName 'Organization' -Tier 1 -Nodes $org.Nodes -Edges $org.Edges
        $null = $writtenFiles.Add(@{ File = $orgFile; Tier = 1; Phase = 'organization' })
        $completedPhases += 'organization'
        Save-Checkpoint
    }
    $null = $allNodes.AddRange(@($org.Nodes))

    # Store users for OrgRoles phase
    $collectedUsers = @()
    $collectedRepos = @()

    # ===========================================
    # Users Phase
    # ===========================================
    if ($Collect -contains 'Users') {
        if ($completedPhases -notcontains 'users') {
            Start-GitHoundPhaseMetrics -PhaseName 'users'
            Write-Host "[*] Enumerating Organization Users (GraphQL)"

            $startCursor = if ($phaseProgress.users) { $phaseProgress.users.cursor } else { $null }
            $users = Get-GraphQLUsers -Session $Session -OrgLogin $orgLogin -OrgId $orgId -UserLimit $UserLimit -StartCursor $startCursor

            $userFile = Write-GitHoundPayload -OutputPath $outputFolder -OrgName $orgId -PhaseName 'User' -Tier 1 -Nodes $users.Nodes -Edges $users.Edges
            $null = $writtenFiles.Add(@{ File = $userFile; Tier = 1; Phase = 'users' })

            $null = $allNodes.AddRange(@($users.Nodes))
            $collectedUsers = @($users.Nodes)

            Stop-GitHoundPhaseMetrics -PhaseName 'users'
            $completedPhases += 'users'
            Save-Checkpoint
        } else {
            Write-Host "[*] Skipping users phase (already completed)"
            $userFile = Join-Path -Path $outputFolder -ChildPath "githound_User_${orgId}.json"
            $null = $writtenFiles.Add(@{ File = $userFile; Tier = 1; Phase = 'users' })
            $existingData = Read-GitHoundPhaseData -FilePath $userFile
            if ($existingData) {
                $null = $allNodes.AddRange(@($existingData.Nodes))
                $collectedUsers = @($existingData.Nodes)
            }
        }
    }

    # ===========================================
    # Teams Phase
    # ===========================================
    if ($Collect -contains 'Teams') {
        if ($completedPhases -notcontains 'teams') {
            Start-GitHoundPhaseMetrics -PhaseName 'teams'
            Write-Host "[*] Enumerating Organization Teams (GraphQL)"

            $teams = Get-GraphQLTeams -Session $Session -OrgLogin $orgLogin -OrgId $orgId

            $teamFile = Write-GitHoundPayload -OutputPath $outputFolder -OrgName $orgId -PhaseName 'Team' -Tier 1 -Nodes $teams.Nodes -Edges $teams.Edges
            $null = $writtenFiles.Add(@{ File = $teamFile; Tier = 1; Phase = 'teams' })

            $null = $allNodes.AddRange(@($teams.Nodes))
            $null = $allEdges.AddRange(@($teams.Edges))

            Stop-GitHoundPhaseMetrics -PhaseName 'teams'
            $completedPhases += 'teams'
            Save-Checkpoint
        } else {
            Write-Host "[*] Skipping teams phase (already completed)"
            $teamFile = Join-Path -Path $outputFolder -ChildPath "githound_Team_${orgId}.json"
            $null = $writtenFiles.Add(@{ File = $teamFile; Tier = 1; Phase = 'teams' })
            $existingData = Read-GitHoundPhaseData -FilePath $teamFile
            if ($existingData) {
                $null = $allNodes.AddRange(@($existingData.Nodes))
                $null = $allEdges.AddRange(@($existingData.Edges))
            }
        }
    }

    # ===========================================
    # Repos Phase
    # ===========================================
    if ($Collect -contains 'Repos') {
        if ($completedPhases -notcontains 'repos') {
            Start-GitHoundPhaseMetrics -PhaseName 'repos'
            Write-Host "[*] Enumerating Organization Repositories (GraphQL)"

            $repos = Get-GraphQLRepositories -Session $Session -OrgLogin $orgLogin -OrgId $orgId -RepoFilter $RepoFilter -RepoVisibility $RepoVisibility

            $repoFile = Write-GitHoundPayload -OutputPath $outputFolder -OrgName $orgId -PhaseName 'Repository' -Tier 1 -Nodes $repos.Nodes -Edges $repos.Edges
            $null = $writtenFiles.Add(@{ File = $repoFile; Tier = 1; Phase = 'repos' })

            $null = $allNodes.AddRange(@($repos.Nodes))
            $null = $allEdges.AddRange(@($repos.Edges))
            $collectedRepos = @($repos.Nodes)

            Stop-GitHoundPhaseMetrics -PhaseName 'repos'
            $completedPhases += 'repos'
            Save-Checkpoint
        } else {
            Write-Host "[*] Skipping repos phase (already completed)"
            $repoFile = Join-Path -Path $outputFolder -ChildPath "githound_Repository_${orgId}.json"
            $null = $writtenFiles.Add(@{ File = $repoFile; Tier = 1; Phase = 'repos' })
            $existingData = Read-GitHoundPhaseData -FilePath $repoFile
            if ($existingData) {
                $null = $allNodes.AddRange(@($existingData.Nodes))
                $null = $allEdges.AddRange(@($existingData.Edges))
                $collectedRepos = @($existingData.Nodes)
            }
        }
    }

    # ===========================================
    # Branches Phase (Batched GraphQL - 10-15 repos per request)
    # ===========================================
    if ($Collect -contains 'Branches' -and $collectedRepos.Count -gt 0) {
        if ($completedPhases -notcontains 'branches') {
            Start-GitHoundPhaseMetrics -PhaseName 'branches'
            Write-Host "[*] Enumerating Repository Branches (Batched GraphQL, $BatchSize repos/request)"

            # Use batched approach for efficiency (87% API reduction)
            $branches = Get-GraphQLBatchedRepoDetails -Session $Session -OrgLogin $orgLogin -OrgId $orgId -Repositories $collectedRepos -BatchSize $BatchSize

            $branchFile = Write-GitHoundPayload -OutputPath $outputFolder -OrgName $orgId -PhaseName 'Branch' -Tier 2 -Nodes $branches.Nodes -Edges $branches.Edges
            $null = $writtenFiles.Add(@{ File = $branchFile; Tier = 2; Phase = 'branches' })

            $null = $allNodes.AddRange(@($branches.Nodes))
            $null = $allEdges.AddRange(@($branches.Edges))

            Stop-GitHoundPhaseMetrics -PhaseName 'branches'
            $completedPhases += 'branches'
            Save-Checkpoint
        } else {
            Write-Host "[*] Skipping branches phase (already completed)"
            $branchFile = Join-Path -Path $outputFolder -ChildPath "githound_Branch_${orgId}.json"
            $null = $writtenFiles.Add(@{ File = $branchFile; Tier = 2; Phase = 'branches' })
            $existingData = Read-GitHoundPhaseData -FilePath $branchFile
            if ($existingData) {
                $null = $allNodes.AddRange(@($existingData.Nodes))
                $null = $allEdges.AddRange(@($existingData.Edges))
            }
        }
    }

    # ===========================================
    # Environments Phase (Batched GraphQL + REST for secrets)
    # ===========================================
    if ($Collect -contains 'Environments' -and $collectedRepos.Count -gt 0) {
        if ($completedPhases -notcontains 'environments') {
            Start-GitHoundPhaseMetrics -PhaseName 'environments'
            Wait-GitHubRateLimit -Session $Session -MinRemaining 500
            Write-Host "[*] Enumerating Repository Environments (REST API with parallel processing)"

            if ($Paced) {
                $envSecrets = Invoke-PacedRestPhase -Session $Session -Repositories $collectedRepos `
                    -CallsPerRepo 3 -ThrottleLimit $ThrottleLimit -PhaseName 'environments' `
                    -InvokePhase {
                        param($ChunkRepos, $DelayMs)
                        Get-RestEnvironmentsWithSecrets -Session $Session -OrgLogin $orgLogin -OrgId $orgId `
                            -Repositories $ChunkRepos -ThrottleLimit $ThrottleLimit -RequestDelayMs $DelayMs
                    }
            } else {
                $envSecrets = Get-RestEnvironmentsWithSecrets -Session $Session -OrgLogin $orgLogin -OrgId $orgId -Repositories $collectedRepos -ThrottleLimit $ThrottleLimit
            }

            $envFile = Write-GitHoundPayload -OutputPath $outputFolder -OrgName $orgId -PhaseName 'Environment' -Tier 2 -Nodes $envSecrets.Nodes -Edges $envSecrets.Edges
            $null = $writtenFiles.Add(@{ File = $envFile; Tier = 2; Phase = 'environments' })

            $null = $allNodes.AddRange(@($envSecrets.Nodes))
            $null = $allEdges.AddRange(@($envSecrets.Edges))

            Stop-GitHoundPhaseMetrics -PhaseName 'environments'
            $completedPhases += 'environments'
            Save-Checkpoint
        } else {
            Write-Host "[*] Skipping environments phase (already completed)"
            $envFile = Join-Path -Path $outputFolder -ChildPath "githound_Environment_${orgId}.json"
            $null = $writtenFiles.Add(@{ File = $envFile; Tier = 2; Phase = 'environments' })
            $existingData = Read-GitHoundPhaseData -FilePath $envFile
            if ($existingData) {
                $null = $allNodes.AddRange(@($existingData.Nodes))
                $null = $allEdges.AddRange(@($existingData.Edges))
            }
        }
    }

    # ===========================================
    # Workflows Phase (REST API - not in GraphQL)
    # ===========================================
    if ($Collect -contains 'Workflows' -and $collectedRepos.Count -gt 0) {
        if ($completedPhases -notcontains 'workflows') {
            Start-GitHoundPhaseMetrics -PhaseName 'workflows'
            Wait-GitHubRateLimit -Session $Session -MinRemaining 500
            Write-Host "[*] Enumerating Repository Workflows (REST API with parallel processing)"

            if ($Paced) {
                $workflows = Invoke-PacedRestPhase -Session $Session -Repositories $collectedRepos `
                    -CallsPerRepo 1 -ThrottleLimit $ThrottleLimit -PhaseName 'workflows' `
                    -InvokePhase {
                        param($ChunkRepos, $DelayMs)
                        Get-RestWorkflows -Session $Session -Repositories $ChunkRepos `
                            -ThrottleLimit $ThrottleLimit -RequestDelayMs $DelayMs
                    }
            } else {
                $workflows = Get-RestWorkflows -Session $Session -Repositories $collectedRepos -ThrottleLimit $ThrottleLimit
            }

            $wfFile = Write-GitHoundPayload -OutputPath $outputFolder -OrgName $orgId -PhaseName 'Workflow' -Tier 2 -Nodes $workflows.Nodes -Edges $workflows.Edges
            $null = $writtenFiles.Add(@{ File = $wfFile; Tier = 2; Phase = 'workflows' })

            $null = $allNodes.AddRange(@($workflows.Nodes))
            $null = $allEdges.AddRange(@($workflows.Edges))

            Stop-GitHoundPhaseMetrics -PhaseName 'workflows'
            $completedPhases += 'workflows'
            Save-Checkpoint
        } else {
            Write-Host "[*] Skipping workflows phase (already completed)"
            $wfFile = Join-Path -Path $outputFolder -ChildPath "githound_Workflow_${orgId}.json"
            $null = $writtenFiles.Add(@{ File = $wfFile; Tier = 2; Phase = 'workflows' })
            $existingData = Read-GitHoundPhaseData -FilePath $wfFile
            if ($existingData) {
                $null = $allNodes.AddRange(@($existingData.Nodes))
                $null = $allEdges.AddRange(@($existingData.Edges))
            }
        }
    }

    # ===========================================
    # Secrets Phase (REST API - not in GraphQL)
    # ===========================================
    if ($Collect -contains 'Secrets' -and $collectedRepos.Count -gt 0) {
        if ($completedPhases -notcontains 'secrets') {
            Start-GitHoundPhaseMetrics -PhaseName 'secrets'
            Wait-GitHubRateLimit -Session $Session -MinRemaining 500
            Write-Host "[*] Enumerating Organization and Repository Secrets (REST API)"

            if ($Paced) {
                $secrets = Invoke-PacedRestPhase -Session $Session -Repositories $collectedRepos `
                    -CallsPerRepo 2 -ThrottleLimit $ThrottleLimit -PhaseName 'secrets' `
                    -InvokePhase {
                        param($ChunkRepos, $DelayMs)
                        Get-RestSecrets -Session $Session -OrgLogin $orgLogin -OrgId $orgId `
                            -Repositories $ChunkRepos -ThrottleLimit $ThrottleLimit -RequestDelayMs $DelayMs
                    }
            } else {
                $secrets = Get-RestSecrets -Session $Session -OrgLogin $orgLogin -OrgId $orgId -Repositories $collectedRepos -ThrottleLimit $ThrottleLimit
            }

            $secretFile = Write-GitHoundPayload -OutputPath $outputFolder -OrgName $orgId -PhaseName 'Secret' -Tier 2 -Nodes $secrets.Nodes -Edges $secrets.Edges
            $null = $writtenFiles.Add(@{ File = $secretFile; Tier = 2; Phase = 'secrets' })

            $null = $allNodes.AddRange(@($secrets.Nodes))
            $null = $allEdges.AddRange(@($secrets.Edges))

            Stop-GitHoundPhaseMetrics -PhaseName 'secrets'
            $completedPhases += 'secrets'
            Save-Checkpoint
        } else {
            Write-Host "[*] Skipping secrets phase (already completed)"
            $secretFile = Join-Path -Path $outputFolder -ChildPath "githound_Secret_${orgId}.json"
            $null = $writtenFiles.Add(@{ File = $secretFile; Tier = 2; Phase = 'secrets' })
            $existingData = Read-GitHoundPhaseData -FilePath $secretFile
            if ($existingData) {
                $null = $allNodes.AddRange(@($existingData.Nodes))
                $null = $allEdges.AddRange(@($existingData.Edges))
            }
        }
    }

    # ===========================================
    # OrgRoles Phase
    # ===========================================
    if ($Collect -contains 'OrgRoles' -and $collectedUsers.Count -gt 0) {
        if ($completedPhases -notcontains 'orgroles') {
            Start-GitHoundPhaseMetrics -PhaseName 'orgroles'
            Write-Host "[*] Creating Organization Role Nodes"

            $orgRoles = Get-GraphQLOrgRoles -Session $Session -OrgLogin $orgLogin -OrgId $orgId -Users $collectedUsers

            $orFile = Write-GitHoundPayload -OutputPath $outputFolder -OrgName $orgId -PhaseName 'OrgRole' -Tier 3 -Nodes $orgRoles.Nodes -Edges $orgRoles.Edges
            $null = $writtenFiles.Add(@{ File = $orFile; Tier = 3; Phase = 'orgroles' })

            $null = $allNodes.AddRange(@($orgRoles.Nodes))
            $null = $allEdges.AddRange(@($orgRoles.Edges))

            Stop-GitHoundPhaseMetrics -PhaseName 'orgroles'
            $completedPhases += 'orgroles'
            Save-Checkpoint
        } else {
            Write-Host "[*] Skipping orgroles phase (already completed)"
            $orFile = Join-Path -Path $outputFolder -ChildPath "githound_OrgRole_${orgId}.json"
            $null = $writtenFiles.Add(@{ File = $orFile; Tier = 3; Phase = 'orgroles' })
            $existingData = Read-GitHoundPhaseData -FilePath $orFile
            if ($existingData) {
                $null = $allNodes.AddRange(@($existingData.Nodes))
                $null = $allEdges.AddRange(@($existingData.Edges))
            }
        }
    }

    # ===========================================
    # RepoRoles Phase
    # ===========================================
    if ($Collect -contains 'RepoRoles' -and $collectedRepos.Count -gt 0) {
        if ($completedPhases -notcontains 'reporoles') {
            Start-GitHoundPhaseMetrics -PhaseName 'reporoles'
            Write-Host "[*] Creating Repository Role Nodes"

            $repoRoles = Get-GraphQLRepoRoles -Session $Session -OrgLogin $orgLogin -OrgId $orgId -Repositories $collectedRepos

            $rrFile = Write-GitHoundPayload -OutputPath $outputFolder -OrgName $orgId -PhaseName 'RepoRole' -Tier 3 -Nodes $repoRoles.Nodes -Edges $repoRoles.Edges
            $null = $writtenFiles.Add(@{ File = $rrFile; Tier = 3; Phase = 'reporoles' })

            $null = $allNodes.AddRange(@($repoRoles.Nodes))
            $null = $allEdges.AddRange(@($repoRoles.Edges))

            Stop-GitHoundPhaseMetrics -PhaseName 'reporoles'
            $completedPhases += 'reporoles'
            Save-Checkpoint
        } else {
            Write-Host "[*] Skipping reporoles phase (already completed)"
            $rrFile = Join-Path -Path $outputFolder -ChildPath "githound_RepoRole_${orgId}.json"
            $null = $writtenFiles.Add(@{ File = $rrFile; Tier = 3; Phase = 'reporoles' })
            $existingData = Read-GitHoundPhaseData -FilePath $rrFile
            if ($existingData) {
                $null = $allNodes.AddRange(@($existingData.Nodes))
                $null = $allEdges.AddRange(@($existingData.Edges))
            }
        }
    }

    # ===========================================
    # TeamRoles Phase (Team to Repo permissions - REST API)
    # ===========================================
    if ($Collect -contains 'TeamRoles' -and $collectedRepos.Count -gt 0) {
        if ($completedPhases -notcontains 'teamroles') {
            Start-GitHoundPhaseMetrics -PhaseName 'teamroles'
            Wait-GitHubRateLimit -Session $Session -MinRemaining 500
            Write-Host "[*] Enumerating Team Repository Permissions (REST API with parallel processing)"

            if ($Paced) {
                $teamRoles = Invoke-PacedRestPhase -Session $Session -Repositories $collectedRepos `
                    -CallsPerRepo 1 -ThrottleLimit $ThrottleLimit -PhaseName 'teamroles' `
                    -InvokePhase {
                        param($ChunkRepos, $DelayMs)
                        Get-RestTeamRepoPermissions -Session $Session -OrgLogin $orgLogin `
                            -Repositories $ChunkRepos -ThrottleLimit $ThrottleLimit -RequestDelayMs $DelayMs
                    }
            } else {
                $teamRoles = Get-RestTeamRepoPermissions -Session $Session -OrgLogin $orgLogin -Repositories $collectedRepos -ThrottleLimit $ThrottleLimit
            }

            $trFile = Write-GitHoundPayload -OutputPath $outputFolder -OrgName $orgId -PhaseName 'TeamRoles' -Tier 3 -Nodes $teamRoles.Nodes -Edges $teamRoles.Edges
            $null = $writtenFiles.Add(@{ File = $trFile; Tier = 3; Phase = 'teamroles' })

            $null = $allEdges.AddRange(@($teamRoles.Edges))

            Stop-GitHoundPhaseMetrics -PhaseName 'teamroles'
            $completedPhases += 'teamroles'
            Save-Checkpoint
        } else {
            Write-Host "[*] Skipping teamroles phase (already completed)"
            $trFile = Join-Path -Path $outputFolder -ChildPath "githound_TeamRoles_${orgId}.json"
            $null = $writtenFiles.Add(@{ File = $trFile; Tier = 3; Phase = 'teamroles' })
            $existingData = Read-GitHoundPhaseData -FilePath $trFile
            if ($existingData) {
                $null = $allEdges.AddRange(@($existingData.Edges))
            }
        }
    }

    # ===========================================
    # Collaborators Phase (Direct repo collaborators - REST API)
    # ===========================================
    if ($Collect -contains 'Collaborators' -and $collectedRepos.Count -gt 0) {
        if ($completedPhases -notcontains 'collaborators') {
            Start-GitHoundPhaseMetrics -PhaseName 'collaborators'
            Wait-GitHubRateLimit -Session $Session -MinRemaining 500
            Write-Host "[*] Enumerating Repository Collaborators (REST API with parallel processing)"

            if ($Paced) {
                $collaborators = Invoke-PacedRestPhase -Session $Session -Repositories $collectedRepos `
                    -CallsPerRepo 1 -ThrottleLimit $ThrottleLimit -PhaseName 'collaborators' `
                    -InvokePhase {
                        param($ChunkRepos, $DelayMs)
                        Get-RestCollaborators -Session $Session -Repositories $ChunkRepos `
                            -ThrottleLimit $ThrottleLimit -RequestDelayMs $DelayMs
                    }
            } else {
                $collaborators = Get-RestCollaborators -Session $Session -Repositories $collectedRepos -ThrottleLimit $ThrottleLimit
            }

            $collabFile = Write-GitHoundPayload -OutputPath $outputFolder -OrgName $orgId -PhaseName 'Collaborator' -Tier 3 -Nodes $collaborators.Nodes -Edges $collaborators.Edges
            $null = $writtenFiles.Add(@{ File = $collabFile; Tier = 3; Phase = 'collaborators' })

            $null = $allEdges.AddRange(@($collaborators.Edges))

            Stop-GitHoundPhaseMetrics -PhaseName 'collaborators'
            $completedPhases += 'collaborators'
            Save-Checkpoint
        } else {
            Write-Host "[*] Skipping collaborators phase (already completed)"
            $collabFile = Join-Path -Path $outputFolder -ChildPath "githound_Collaborator_${orgId}.json"
            $null = $writtenFiles.Add(@{ File = $collabFile; Tier = 3; Phase = 'collaborators' })
            $existingData = Read-GitHoundPhaseData -FilePath $collabFile
            if ($existingData) {
                $null = $allEdges.AddRange(@($existingData.Edges))
            }
        }
    }

    # ===========================================
    # SecretScanning Phase (REST API)
    # ===========================================
    if ($Collect -contains 'SecretScanning') {
        if ($completedPhases -notcontains 'secretscanning') {
            Start-GitHoundPhaseMetrics -PhaseName 'secretscanning'
            Wait-GitHubRateLimit -Session $Session -MinRemaining 100
            Write-Host "[*] Enumerating Secret Scanning Alerts (REST API)"

            $secretAlerts = Get-RestSecretScanningAlerts -Session $Session -OrgLogin $orgLogin -OrgId $orgId

            $ssFile = Write-GitHoundPayload -OutputPath $outputFolder -OrgName $orgId -PhaseName 'SecretAlerts' -Tier 4 -Nodes $secretAlerts.Nodes -Edges $secretAlerts.Edges
            $null = $writtenFiles.Add(@{ File = $ssFile; Tier = 4; Phase = 'secretscanning' })

            $null = $allNodes.AddRange(@($secretAlerts.Nodes))
            $null = $allEdges.AddRange(@($secretAlerts.Edges))

            Stop-GitHoundPhaseMetrics -PhaseName 'secretscanning'
            $completedPhases += 'secretscanning'
            Save-Checkpoint
        } else {
            Write-Host "[*] Skipping secretscanning phase (already completed)"
            $ssFile = Join-Path -Path $outputFolder -ChildPath "githound_SecretAlerts_${orgId}.json"
            $null = $writtenFiles.Add(@{ File = $ssFile; Tier = 4; Phase = 'secretscanning' })
            $existingData = Read-GitHoundPhaseData -FilePath $ssFile
            if ($existingData) {
                $null = $allNodes.AddRange(@($existingData.Nodes))
                $null = $allEdges.AddRange(@($existingData.Edges))
            }
        }
    }

    # ===========================================
    # AppInstallations Phase (REST API)
    # ===========================================
    if ($Collect -contains 'AppInstallations') {
        if ($completedPhases -notcontains 'appinstallations') {
            Start-GitHoundPhaseMetrics -PhaseName 'appinstallations'
            Wait-GitHubRateLimit -Session $Session -MinRemaining 100
            Write-Host "[*] Enumerating GitHub App Installations (REST API)"

            $appInstalls = Get-RestAppInstallations -Session $Session -OrgLogin $orgLogin -OrgId $orgId

            $appFile = Write-GitHoundPayload -OutputPath $outputFolder -OrgName $orgId -PhaseName 'AppInstallation' -Tier 4 -Nodes $appInstalls.Nodes -Edges $appInstalls.Edges
            $null = $writtenFiles.Add(@{ File = $appFile; Tier = 4; Phase = 'appinstallations' })

            $null = $allNodes.AddRange(@($appInstalls.Nodes))
            $null = $allEdges.AddRange(@($appInstalls.Edges))

            Stop-GitHoundPhaseMetrics -PhaseName 'appinstallations'
            $completedPhases += 'appinstallations'
            Save-Checkpoint
        } else {
            Write-Host "[*] Skipping appinstallations phase (already completed)"
            $appFile = Join-Path -Path $outputFolder -ChildPath "githound_AppInstallation_${orgId}.json"
            $null = $writtenFiles.Add(@{ File = $appFile; Tier = 4; Phase = 'appinstallations' })
            $existingData = Read-GitHoundPhaseData -FilePath $appFile
            if ($existingData) {
                $null = $allNodes.AddRange(@($existingData.Nodes))
                $null = $allEdges.AddRange(@($existingData.Edges))
            }
        }
    }

    # ===========================================
    # SAML Phase
    # ===========================================
    if ($Collect -contains 'SAML') {
        if ($completedPhases -notcontains 'saml') {
            Start-GitHoundPhaseMetrics -PhaseName 'saml'
            Write-Host "[*] Enumerating SAML Identity Provider (GraphQL)"

            $saml = Get-GraphQLSAML -Session $Session -OrgLogin $orgLogin -OrgId $orgId

            $samlFile = Write-GitHoundPayload -OutputPath $outputFolder -OrgName $orgId -PhaseName 'saml' -Tier 4 -Nodes $saml.Nodes -Edges $saml.Edges
            $null = $writtenFiles.Add(@{ File = $samlFile; Tier = 4; Phase = 'saml' })

            # NOTE: SAML data is NOT added to combined output (kept in separate file)

            Stop-GitHoundPhaseMetrics -PhaseName 'saml'
            $completedPhases += 'saml'
            Save-Checkpoint
        } else {
            Write-Host "[*] Skipping saml phase (already completed)"
            $samlFile = Join-Path -Path $outputFolder -ChildPath "githound_saml_${orgId}.json"
            $null = $writtenFiles.Add(@{ File = $samlFile; Tier = 4; Phase = 'saml' })
        }
    }

    # ===========================================
    # Combined Output
    # ===========================================
    try {
        Write-Host "[*] Writing combined output"
        $combinedFile = Write-GitHoundPayload -OutputPath $outputFolder -OrgName $orgId -PhaseName 'combined' -Tier 0 -Nodes $allNodes -Edges $allEdges
    } catch {
        Write-Warning "[!] Failed to write combined output: $_"
    }

    # ===========================================
    # Ingestion Order Summary
    # ===========================================
    Write-Host ""
    Write-Host "=============================================" -ForegroundColor Green
    Write-Host "BLOODHOUND INGESTION ORDER" -ForegroundColor Green
    Write-Host "Upload files in this order:" -ForegroundColor Green
    Write-Host "=============================================" -ForegroundColor Green
    Write-Host ""

    $sortedFiles = $writtenFiles | Sort-Object { $_.Tier }
    $currentTier = -1
    foreach ($fileInfo in $sortedFiles) {
        if ($fileInfo.Tier -ne $currentTier) {
            $currentTier = $fileInfo.Tier
            if ($currentTier -eq 0) {
                Write-Host "Tier 0 (Combined - alternative to individual files):" -ForegroundColor Yellow
            } else {
                Write-Host "Tier $currentTier`:" -ForegroundColor Yellow
            }
        }
        Write-Host "  - $(Split-Path $fileInfo.File -Leaf)"
    }

    Write-Host ""
    Write-Host "=============================================" -ForegroundColor Green

    # Output metrics summary
    if ($Metrics) {
        Write-GitHoundMetricsSummary
    }

    # Zip if requested
    if ($Zip) {
        $zipPath = "$outputFolder.zip"
        Write-Host "[*] Creating zip archive: $zipPath"
        Compress-Archive -Path "$outputFolder\*" -DestinationPath $zipPath -Force
        Remove-Item -Path $outputFolder -Recurse -Force
        Write-Host "[+] Created $zipPath and removed output folder"
    }

    Write-Host ""
    Write-Host "[+] GitHound GraphQL collection complete!" -ForegroundColor Green
}

