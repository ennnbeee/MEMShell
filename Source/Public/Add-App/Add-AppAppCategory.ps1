Function Add-AppAppCategory() {

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
        $Id,
        [Parameter(Mandatory = $true)]
        $CategoryId
    )

    $graphApiVersion = 'Beta'
    $Resource = "deviceAppManagement/mobileApps/$Id/categories/`$ref"

    try {
        $value = "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/mobileAppCategories/$CategoryId"
        $Output = New-Object -TypeName psobject
        $Output | Add-Member -MemberType NoteProperty -Name '@odata.id' -Value $value
        $JSON = $Output | ConvertTo-Json -Depth 3
        Test-Json -Json $JSON
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType 'application/json'
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