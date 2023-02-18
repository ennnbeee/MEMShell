Function Invoke-AppAppleVPPAppSync() {

    <#
    .SYNOPSIS
    Sync Intune tenant to Apple DEP service
    .DESCRIPTION
    Intune automatically syncs with the Apple DEP service once every 24hrs. This function synchronises your Intune tenant with the Apple DEP service.
    .EXAMPLE
    Sync-AppleDEP
    .NOTES
    NAME: Sync-AppleDEP
    #>

    [cmdletbinding()]

    Param(
        [parameter(Mandatory = $true)]
        [string]$Id
    )

    $graphApiVersion = 'beta'
    $Resource = "deviceManagement/depOnboardingSettings/$id/syncWithAppleDeviceEnrollmentProgram"

    try {

        $Uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Post

    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}