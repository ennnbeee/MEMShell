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
        [string]$Method,

        [string]$Body,

        [string]$ContentType = 'application/json'
    )

    Test-AuthToken

    $Headers = $global:authToken

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
