Function Update-DeviceManagedDeviceName() {

    <#
    .SYNOPSIS
    This function is used to update device compliance policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and updates device compliance policies
    .EXAMPLE
    Update-DeviceCompliancePolicy -id -JSON
    Updates a device compliance policies configured in Intune
    .NOTES
    NAME: Update-DeviceCompliancePolicy
    #>

    [cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    Param(
        [Parameter(Mandatory = $true)]
        $Id,
        [Parameter(Mandatory = $true)]
        $OS,
        [Parameter(Mandatory = $true)]
        $DeviceName
    )

    $graphApiVersion = 'Beta'
    $Resource = "deviceManagement/managedDevices('$Id')/setDeviceName"

    If ($OS -eq 'Windows') {
        $Length = '15'
    }
    Elseif ($OS -eq 'iOS') {
        $Length = '255'
    }
    Elseif ($OS -eq 'Android') {
        $Length = '50'
    }
    Elseif ($OS -eq 'macOS') {
        $Length = '250'
    }

    $DeviceName = $DeviceName.Replace(' ', '')
    if ($DeviceName.Length -ge $Length) {
        $DeviceName = $DeviceName.substring(0, $Length)
        Write-Information "Device name shortened to $DeviceName"
    }

    $Output = New-Object -TypeName psobject
    $Output | Add-Member -MemberType NoteProperty -Name 'deviceName' -Value $DeviceName
    $JSON = $Output | ConvertTo-Json -Depth 3

    try {
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