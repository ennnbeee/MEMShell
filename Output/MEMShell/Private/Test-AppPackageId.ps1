Function Test-AppPackageId() {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthTokenMSAL
    Authenticates you with the Graph API interface using MSAL.PS module
    .NOTES
    NAME: Get-AuthTokenMSAL
    #>

    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$packageId
    )

    $graphApiVersion = 'Beta'
    $Resource = "deviceAppManagement/mobileApps?`$filter=(isof('microsoft.graph.androidForWorkApp') or microsoft.graph.androidManagedStoreApp/supportsOemConfig eq false)"

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        $mobileApps = Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
    }
    catch {
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Output "Response content:`n$ex"
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        break
    }
    Write-Output $packageId | Out-Null
    $app = $mobileApps.value | Where-Object { $_.packageId -eq $packageId }

    If ($app) {
        return $app.id
    }
    Else {
        return [OutputType('System.Boolean')]$false
    }
}