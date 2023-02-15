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

    [cmdletbinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        $id
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/configurationPolicies'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id"
        Invoke-MEMRestMethod -Uri $uri -Method Delete
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