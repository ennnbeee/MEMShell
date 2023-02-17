Function Get-MEMGroupMember() {

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
        [parameter(Mandatory = $true)]
        [string]$Id
    )

    # Defining Variables
    $graphApiVersion = 'beta'
    $Resource = 'groups'

    try {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$id/members"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}