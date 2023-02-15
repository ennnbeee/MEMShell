Function Remove-AppConfigPolicyApp() {

    <#
    .SYNOPSIS
    This function is used to remove Managed App policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and removes managed app policies
    .EXAMPLE
    Remove-AppConfigPolicyApp -id $id
    Removes a managed app policy configured in Intune
    .NOTES
    NAME: Remove-AppConfigPolicyApp
    #>

    [cmdletbinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        $id
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceAppManagement/targetedManagedAppConfigurations'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id"
        Invoke-MEMRestMethod -Uri $uri -Method Delete
    }
    catch {
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}