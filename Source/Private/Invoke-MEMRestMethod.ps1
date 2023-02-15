Function Invoke-MEMRestMethod() {

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
        [parameter(Mandatory = $true)]
        [uri]$Uri,
        [parameter(Mandatory = $true)]
        [ValidateSet('Delete', 'Get', 'Patch', 'Post', 'Put')]
        $Method,
        $Body,
        $ContentType = 'application/json'
    )

    if ($global:authToken) {

        # Setting DateTime to Universal time to work in all timezones
        $DateTime = (Get-Date).ToUniversalTime()

        # If the authToken exists checking when it expires
        $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes

        if ($TokenExpires -le 0) {

            Write-Output "Authentication Token expired $TokenExpires minutes ago"
            # Defining User Principal Name if not present
            if ($null -eq $User -or $User -eq '') {
                $User = Read-Host -Prompt 'Please specify your user principal name for Azure Authentication'
            }
            $global:authToken = Get-AuthTokenMSAL -User $User
        }
    }
    # Authentication doesn't exist, calling Get-AuthToken function
    else {
        if ($null -eq $User -or $User -eq '') {
            $User = Read-Host -Prompt 'Please specify your user principal name for Azure Authentication'
        }
        # Getting the authorization token
        $global:authToken = Get-AuthTokenMSAL -User $User
    }

    $global:authToken['ConsistencyLevel'] = 'eventual'
    $Headers = $global:authToken

    $Method = 'Get'
    if ($Method -eq 'Get') {
        $ValueOnly = 'True'
        $params = @{
            Uri     = $uri
            Method  = $Method
            Headers = $Headers
        }
    }
    elseif ($Method -eq 'Post') {
        $params = @{
            Uri         = $uri
            Method      = $Method
            Headers     = $Headers
            ContentType = $ContentType
            Body        = $Body
        }
    }
    elseif ($Method -eq 'Patch') {
        $params = @{
            Uri         = $uri
            Method      = $Method
            Headers     = $Headers
            ContentType = $ContentType
            Body        = $Body
        }
    }
    elseif ($Method -eq 'Delete') {
        $params = @{
            Uri     = $uri
            Method  = $Method
            Headers = $Headers
        }
    }
    Try {
        $Result = Invoke-RestMethod @params
        if ($ValueOnly) {
            return $Result.Value
        }
        else {
            return $Result
        }
    }
    Catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}