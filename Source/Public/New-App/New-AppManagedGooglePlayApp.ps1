Function New-AppManagedGooglePlayApp() {

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
        $Id
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/androidManagedStoreAccountEnterpriseSettings/approveApps'

    try {
        $Id = 'app:' + $Id
        $Packages = New-Object -TypeName psobject
        $Packages | Add-Member -MemberType NoteProperty -Name 'approveAllPermissions' -Value 'true'
        $Packages | Add-Member -MemberType NoteProperty -Name 'packageIds' -Value @($Id)
        $JSON = $Packages | ConvertTo-Json -Depth 3

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        if ($PSCmdlet.ShouldProcess('ShouldProcess?')) {
            Invoke-MEMRestMethod -Uri $uri -Method Post -Body $JSON
        }
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
