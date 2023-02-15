Function Get-AppProtectionPolicy() {

    <#
    .SYNOPSIS
    This function is used to get Deivce Enrollment Configurations from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets Device Enrollment Configurations
    .EXAMPLE
    Get-DeviceEnrollmentConfigurations
    Returns Device Enrollment Configurations configured in Intune
    .NOTES
    NAME: Get-DeviceEnrollmentConfigurations
    #>

    [cmdletbinding()]

    $graphApiVersion = 'Beta'
    $Resource = 'deviceAppManagement/managedAppPolicies'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Get | Where-Object { ($_.'@odata.type').contains('ManagedAppProtection') -or ($_.'@odata.type').contains('InformationProtectionPolicy') }
    }
    catch {
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Output "Response content:`n$ex"
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        break
    }
}