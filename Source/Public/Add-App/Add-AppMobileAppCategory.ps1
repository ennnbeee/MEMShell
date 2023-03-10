Function Add-AppMobileAppCategory() {

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
        [string]$Id,

        [Parameter(Mandatory = $true)]
        [string]$CategoryId
    )

    $graphApiVersion = 'Beta'
    $Resource = "deviceAppManagement/mobileApps/$Id/categories/`$ref"

    try {
        $value = "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/mobileAppCategories/$CategoryId"
        $Output = New-Object -TypeName psobject
        $Output | Add-Member -MemberType NoteProperty -Name '@odata.id' -Value $value
        $JSON = $Output | ConvertTo-Json -Depth 3
        Test-MEMJSON -Json $JSON
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Post -Body $JSON
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}