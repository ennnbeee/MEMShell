Function Get-DeviceSettingsCatalogProfile() {

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

    param
    (
        [parameter(Mandatory = $false)]
        [ValidateSet('windows10', 'macOS')]
        [ValidateNotNullOrEmpty()]
        [string]$Platform
    )

    $graphApiVersion = 'beta'
    if ($Platform) {
        $Resource = "deviceManagement/configurationPolicies?`$filter=platforms has '$Platform' and technologies has 'mdm'"
    }
    else {
        $Resource = "deviceManagement/configurationPolicies?`$filter=technologies has 'mdm'"
    }

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Get
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