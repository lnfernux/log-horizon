function Invoke-AzRestWithRetry {
    <#
    .SYNOPSIS
        Wraps Invoke-RestMethod with retry logic for transient Azure API failures.
    .DESCRIPTION
        Retries on HTTP 429 (throttled, respects Retry-After header) and transient
        5xx server errors. Uses exponential backoff with a configurable maximum
        number of attempts. Non-retryable errors are re-thrown immediately.
    .OUTPUTS
        The response object from Invoke-RestMethod.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][hashtable]$Headers,
        [string]$Method = 'Get',
        [object]$Body,
        [int]$MaxRetries = 3,
        [int]$BaseDelaySeconds = 2
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

            # Determine wait time: use Retry-After header for 429, otherwise exponential backoff
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
