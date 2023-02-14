Function Test-AppPackageId() {

    param (
        [Parameter(Mandatory = $true)]
        $packageId
    )
    
    $graphApiVersion = 'Beta'
    $Resource = "deviceAppManagement/mobileApps?`$filter=(isof('microsoft.graph.androidForWorkApp') or microsoft.graph.androidManagedStoreApp/supportsOemConfig eq false)"
    
    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        $mobileApps = Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
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
    
    $app = $mobileApps.value | Where-Object { $_.packageId -eq $packageId }
        
    If ($app) {
        return $app.id
    }
    Else {
        return $false
    }
}