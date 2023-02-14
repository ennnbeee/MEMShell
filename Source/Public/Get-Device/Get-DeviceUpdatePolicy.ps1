Function Get-DeviceUpdatePolicy() {
    
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
        [switch]$Windows10,
        [switch]$iOS,
        [switch]$macOS
    )

    $graphApiVersion = 'Beta'

    try {
        $Count_Params = 0
        if ($iOS.IsPresent) { $Count_Params++ }
        if ($Windows10.IsPresent) { $Count_Params++ }
        if ($macOS.IsPresent) { $Count_Params++ }
        if ($Count_Params -gt 1) {
            Write-Host 'Multiple parameters set, specify a single parameter -iOS or -Windows10 or -macOS against the function' -f Red
        }
        elseif ($Count_Params -eq 0) {
            Write-Host 'Parameter -iOS or -Windows10 or -macOS required against the function...' -ForegroundColor Red
            Write-Host
            break
        }
        elseif ($Windows10) {
            $Resource = "deviceManagement/deviceConfigurations?`$filter=isof('microsoft.graph.windowsUpdateForBusinessConfiguration')&`$expand=groupAssignments"
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).value
        }
        elseif ($iOS) {
            $Resource = "deviceManagement/deviceConfigurations?`$filter=isof('microsoft.graph.iosUpdateConfiguration')&`$expand=groupAssignments"
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
        }
        elseif ($macOS) {
            $Resource = "deviceManagement/deviceConfigurations?`$filter=isof('microsoft.graph.macOSSoftwareUpdateConfiguration')&`$expand=groupAssignments"
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
        }
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