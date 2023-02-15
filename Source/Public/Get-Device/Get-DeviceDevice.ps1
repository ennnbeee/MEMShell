Function Get-DeviceDevice() {

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
        [switch]$IncludeEAS,
        [switch]$ExcludeMDM
    )

    $graphApiVersion = 'beta'
    $Resource = 'deviceManagement/managedDevices'

    try {
        $Count_Params = 0

        if ($IncludeEAS.IsPresent) { $Count_Params++ }
        if ($ExcludeMDM.IsPresent) { $Count_Params++ }
        if ($Count_Params -gt 1) {
            Write-Warning 'Multiple parameters set, specify a single parameter -IncludeEAS, -ExcludeMDM or no parameter against the function'
            break
        }
        elseif ($IncludeEAS) {
            $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        }
        elseif ($ExcludeMDM) {
            $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource`?`$filter=managementAgent eq 'eas'"
        }
        else {
            $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource`?`$filter=managementAgent eq 'mdm' and managementAgent eq 'easmdm'"
        }

        Invoke-MEMRestMethod -Uri $uri -Method Get
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}