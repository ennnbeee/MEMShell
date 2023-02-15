Function Update-DeviceCompliancePolicy() {

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
    param
    (
        [Parameter(Mandatory = $true)]
        $Id,
        [Parameter(Mandatory = $true)]
        $JSON
    )

    $graphApiVersion = 'Beta'
    $Resource = "deviceManagement/deviceCompliancePolicies/$id"

    try {
        Test-Json -Json $JSON
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        if ($PSCmdlet.ShouldProcess('ShouldProcess?')) {
            Invoke-MEMRestMethod -Uri $uri -Method Patch -Body $JSON
        }

    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}