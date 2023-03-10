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

    [cmdletbinding(SupportsShouldProcess, ConfirmImpact='Medium')]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Id
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceAppManagement/targetedManagedAppConfigurations'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$Id"
        if ($PSCmdlet.ShouldProcess('ShouldProcess?')) {
            Invoke-MEMRestMethod -Uri $uri -Method Delete
        }
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}