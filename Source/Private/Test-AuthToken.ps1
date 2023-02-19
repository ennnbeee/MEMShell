Function Test-AuthToken() {

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
    param (
    )

    if ($global:authToken) {

        # Setting DateTime to Universal time to work in all timezones
        $DateTime = (Get-Date).ToUniversalTime()

        # If the authToken exists checking when it expires
        $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes

        if ($TokenExpires -le 0) {

            Write-Output "Authentication Token expired $TokenExpires minutes ago"
            # Defining User Principal Name if not present
            if ($null -eq $global:User -or $global:User -eq '') {
                $global:User = Read-Host -Prompt 'Please specify your user principal name for Azure Authentication'
            }
            $global:authToken = Get-AuthTokenMSAL -User $global:User
        }
    }
    # Authentication doesn't exist, calling Get-AuthToken function
    else {
        if ($null -eq $global:User -or $global:User -eq '') {
            $global:User = Read-Host -Prompt 'Please specify your user principal name for Azure Authentication'
        }
        # Getting the authorization token
        $global:authToken = Get-AuthTokenMSAL -User $global:User
    }

    $global:authToken['ConsistencyLevel'] = 'eventual'

}