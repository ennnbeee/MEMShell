Function Add-AppCategory() {

    <#
    .SYNOPSIS
    This function is used to add new App Categories to Intune
    .DESCRIPTION
    Allows for the creation of new App Categories
    .EXAMPLE
    Add-AppCategory -Name 'User Apps'
    .NOTES
    NAME: Add-AppCategory
    #>

    [cmdletbinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceAppManagement/mobileAppCategories'

    try {
        $Output = New-Object -TypeName psobject
        $Output | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.mobileAppCategory'
        $Output | Add-Member -MemberType NoteProperty 'displayName' -Value $Name
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