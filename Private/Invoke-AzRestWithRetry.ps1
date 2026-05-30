function Invoke-AzRestWithRetry {
    <#
    .SYNOPSIS
        Wraps Invoke-RestMethod with retry logic for transient Azure API failures.
    .DESCRIPTION
        Retries on HTTP 429 (throttled, respects Retry-After header) and transient
        5xx server errors. Uses exponential backoff with a configurable maximum
        number of attempts. Non-retryable errors are re-thrown immediately.

        When -FollowAsync is supplied the request is issued via Invoke-WebRequest
        so headers and HTTP status are accessible. A 202 response triggers polling
        of the Azure-AsyncOperation URL (honoring Retry-After) until terminal
        status. Returns the final operation status object on async paths, or the
        parsed body for synchronous (200/201) responses.
    .OUTPUTS
        The response object from Invoke-RestMethod, or a final async-operation
        status object on async paths.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][hashtable]$Headers,
        [string]$Method = 'Get',
        [object]$Body,
        [int]$MaxRetries = 3,
        [int]$BaseDelaySeconds = 2,
        [switch]$FollowAsync,
        [int]$AsyncTimeoutSeconds = 300
    )

    $attempt = 0

    while ($true) {
        $attempt++
        try {
            $splat = @{
                Uri         = $Uri
                Headers     = $Headers
                Method      = $Method
                ErrorAction = 'Stop'
            }
            if ($null -ne $Body) { $splat['Body'] = $Body }

            if ($FollowAsync) {
                $resp = Invoke-WebRequest @splat -UseBasicParsing
                $statusCode = [int]$resp.StatusCode

                if ($statusCode -eq 202) {
                    $asyncUrl = $null
                    foreach ($key in 'Azure-AsyncOperation', 'Location') {
                        if ($resp.Headers.ContainsKey($key)) {
                            $val = $resp.Headers[$key]
                            if ($val -is [array]) { $val = $val[0] }
                            $asyncUrl = $val
                            break
                        }
                    }
                    if (-not $asyncUrl) {
                        return [PSCustomObject]@{ status = 'Succeeded'; properties = $null }
                    }
                    return Wait-AzAsyncOperation -Uri $asyncUrl -Headers $Headers -TimeoutSeconds $AsyncTimeoutSeconds
                }

                if ($resp.Content) {
                    try { return $resp.Content | ConvertFrom-Json -ErrorAction Stop } catch { return $resp.Content }
                }
                return $null
            }

            return Invoke-RestMethod @splat
        }
        catch {
            $statusCode = $null
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }

            $retryable = $statusCode -eq 429 -or ($statusCode -ge 500 -and $statusCode -le 599)

            if (-not $retryable -or $attempt -gt $MaxRetries) {
                throw
            }

            $waitSeconds = $BaseDelaySeconds * [math]::Pow(2, $attempt - 1)

            if ($statusCode -eq 429 -and $_.Exception.Response.Headers) {
                $retryAfter = $null
                try {
                    $retryAfter = $_.Exception.Response.Headers | Where-Object Key -eq 'Retry-After' | Select-Object -ExpandProperty Value -First 1
                } catch {
                    Write-Verbose "Could not parse Retry-After header: $_"
                }
                if ($retryAfter -and [int]::TryParse($retryAfter, [ref]$null)) {
                    $waitSeconds = [int]$retryAfter
                }
            }

            Write-Warning "Request to $Uri failed (HTTP $statusCode). Retry $attempt of $MaxRetries in ${waitSeconds}s."
            Start-Sleep -Seconds $waitSeconds
        }
    }
}

function Wait-AzAsyncOperation {
    <#
    .SYNOPSIS
        Polls an Azure-AsyncOperation URL until Succeeded, Failed, or Canceled.
        Honors Retry-After when present. Throws on Failed/Canceled so the caller's
        try/catch can branch into fallback logic.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][hashtable]$Headers,
        [int]$TimeoutSeconds = 300,
        [int]$DefaultPollSeconds = 5
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $waitSeconds = $DefaultPollSeconds

    while ($true) {
        if ((Get-Date) -gt $deadline) {
            throw "Async operation $Uri did not reach terminal status within ${TimeoutSeconds}s."
        }

        Start-Sleep -Seconds $waitSeconds

        try {
            $resp = Invoke-WebRequest -Uri $Uri -Headers $Headers -Method Get -UseBasicParsing -ErrorAction Stop
        }
        catch {
            $sc = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
            if ($sc -eq 429 -or ($sc -ge 500 -and $sc -le 599)) {
                $waitSeconds = [math]::Min(60, $waitSeconds * 2)
                continue
            }
            throw
        }

        $body = $null
        if ($resp.Content) {
            try { $body = $resp.Content | ConvertFrom-Json -ErrorAction Stop } catch { $body = $null }
        }

        $status = if ($body -and $body.status) { [string]$body.status } else { $null }

        if ($status -in 'Succeeded', 'Failed', 'Canceled') {
            if ($status -ne 'Succeeded') {
                $errMsg = if ($body.error -and $body.error.message) { $body.error.message } else { "Async operation $status" }
                throw $errMsg
            }
            return $body
        }

        if ($resp.Headers.ContainsKey('Retry-After')) {
            $ra = $resp.Headers['Retry-After']
            if ($ra -is [array]) { $ra = $ra[0] }
            $parsed = 0
            if ([int]::TryParse($ra, [ref]$parsed) -and $parsed -gt 0) {
                $waitSeconds = [int]$parsed
            }
        }
    }
}
