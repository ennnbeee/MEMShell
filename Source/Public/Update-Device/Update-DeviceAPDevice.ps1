Function Update-DeviceAP() {

    <#
    .SYNOPSIS
    This function is used to set autopilot devices properties via the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and sets autopilot device properties
    .EXAMPLE
    Set-AutopilotDevice
    Returns any autopilot devices
    .NOTES
    NAME: Set-AutopilotDevice
    #>

    [cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
    param(
        [Parameter(Mandatory = $true)]
        $Id,
        [Parameter(Mandatory = $true)]
        $GroupTag
    )

    $graphApiVersion = 'Beta'
    $Resource = "deviceManagement/windowsAutopilotDeviceIdentities/$Id/updateDeviceProperties"

    try {
        $Autopilot = New-Object -TypeName psobject
        $Autopilot | Add-Member -MemberType NoteProperty -Name 'groupTag' -Value $GroupTag
        $JSON = $Autopilot | ConvertTo-Json -Depth 3
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        if ($PSCmdlet.ShouldProcess('ShouldProcess?')) {
            Invoke-MEMRestMethod -Uri $uri -Method Post -Body $JSON
        }
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}