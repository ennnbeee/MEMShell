Function Get-EnrolmentESPAssignment() {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthTokenMSAL
    Authenticates you with the Graph API interface using MSAL.PS module
    .NOTES
    NAME: Get-AuthTokenMSAL
    #>

    [cmdletbinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        [string]$id
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/deviceEnrollmentConfigurations'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$Id/Assignments/"
        Invoke-MEMRestMethod -Uri $uri -Method Get
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}