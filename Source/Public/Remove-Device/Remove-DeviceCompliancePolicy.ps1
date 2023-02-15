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

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        $id
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/deviceCompliancePolicies'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id"
        Invoke-MEMRestMethod -Uri $uri -Method Delete
    }
    catch {
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Output "Response content:`n$ex"
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        break
    }
}