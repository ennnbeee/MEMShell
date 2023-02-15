Function Remove-DeviceSettingsCatalogProfile() {

    <#
    .SYNOPSIS
    This function is used to remove a device configuration policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and removes a device configuration policies
    .EXAMPLE
    Remove-DeviceSettingsCatalogProfile -id $id
    Removes a device configuration policies configured in Intune
    .NOTES
    NAME: Remove-DeviceSettingsCatalogProfile
    #>

    [cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(Mandatory = $true)]
        $id
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/configurationPolicies'

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