Function Get-DeviceNotificationMessage() {
    
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
    param(
        [parameter(Mandatory = $true)]
        $Id
    )

    $graphApiVersion = 'Beta'
    $Resource = "deviceManagement/notificationMessageTemplates/$Id/localizedNotificationMessages"
    
    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
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