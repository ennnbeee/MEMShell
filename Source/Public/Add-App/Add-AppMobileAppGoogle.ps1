Function Add-AppMobileAppGoogle() {

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
        $PackageID
    )

    $graphApiVersion = 'Beta'
    $App_resource = 'deviceManagement/androidManagedStoreAccountEnterpriseSettings/approveApps'

    try {
        $PackageID = 'app:' + $PackageID
        $Packages = New-Object -TypeName psobject
        $Packages | Add-Member -MemberType NoteProperty -Name 'approveAllPermissions' -Value 'true'
        $Packages | Add-Member -MemberType NoteProperty -Name 'packageIds' -Value @($PackageID)
        $JSON = $Packages | ConvertTo-Json -Depth 3
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($App_resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Post -Body $JSON

    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}