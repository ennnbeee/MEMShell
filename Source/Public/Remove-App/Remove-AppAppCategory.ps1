Function Remove-AppAppCategory() {

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

    [cmdletbinding(SupportsShouldProcess, ConfirmImpact='Medium')]
    param
    (
        [Parameter(Mandatory = $true)]
        $Id,
        [Parameter(Mandatory = $true)]
        $CategoryId
    )

    $graphApiVersion = 'Beta'
    $Resource = "deviceAppManagement/mobileApps/$Id/categories/$CategoryId/`$ref"

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
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