Function Get-DeviceAutopilot() {

    <#
    .SYNOPSIS
    This function is used to get autopilot devices via the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any autopilot devices
    .EXAMPLE
    Get-AutopilotDevices
    Returns any autopilot devices
    .NOTES
    NAME: Get-AutopilotDevices
    #>
    [cmdletbinding()]

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/windowsAutopilotDeviceIdentities'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Get
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}