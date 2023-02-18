Function Remove-DeviceCompliancePolicy() {

    <#
        .SYNOPSIS
        This function is used to delete a device configuration policy from the Graph API REST interface
        .DESCRIPTION
        The function connects to the Graph API Interface and deletes a device compliance policy
        .EXAMPLE
        Remove-DeviceCompliancePolicy -id $id
        Returns any device configuration policies configured in Intune
        .NOTES
        NAME: Remove-DeviceCompliancePolicy
        #>

    [cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$id
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/deviceCompliancePolicies'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id"
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