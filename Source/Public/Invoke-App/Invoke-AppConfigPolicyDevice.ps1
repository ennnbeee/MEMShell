Function Invoke-AppConfigPolicyDevice {

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

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Path,

        [ValidateSet('Android', 'iOS')]
        [string[]]$OS,

        [ValidateSet('Corporate', 'Personal')]
        [string]$Enrolment,

        [ValidateSet('CE', 'NCSC', 'MS')]
        [string]$Engagement
    )

    $Files = Get-ChildItem -Path $Path -Filter *.json | Where-Object { ($_.name -like "*$OS*") -and ($_.name -like "*$Enrolment*") -and ($_.name -like "*_$($Engagement)_*") }

    foreach ($file in $files) {
        $ImportPath = $file.FullName
        $JSON_Data = Get-Content "$ImportPath"
        $JSON_Convert = $JSON_Data | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, version, isAssigned, roleScopeTagIds
        $DisplayName = $JSON_Convert.displayName
        if (Get-AppConfigPolicyDevice | Where-Object { ($_.displayName).equals($DisplayName) }) {
            Write-Information "App Config Profile '$DisplayName' already exists"
        }
        Else {
            If ($JSON_Convert.'@odata.type' -eq '#microsoft.graph.iosMobileAppConfiguration') {

                # Check if the client app is present
                $targetedMobileApp = Test-AppBundleId -bundleId $JSON_Convert.bundleId

                If ($targetedMobileApp) {
                    Write-Information "Targeted app $($JSON_Convert.bundleId) has already been added from the App Store"
                    Write-Information 'The App Configuration Policy will be created'

                    # Update the targetedMobileApps GUID if required
                    If (!($targetedMobileApp -eq $JSON_Convert.targetedMobileApps)) {
                        $JSON_Convert.targetedMobileApps.SetValue($targetedMobileApp, 0)
                    }

                    $JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 5
                    Write-Information "Adding App Configuration Policy '$DisplayName'"
                    New-AppConfigPolicyDevice -JSON $JSON_Output
                }
                Else {
                    Write-Error "Targeted app bundle id '$($JSON_Convert.bundleId)' has not been added from the App Store"
                    Write-Error "The App Configuration Policy can't be created"
                }
            }
            ElseIf ($JSON_Convert.'@odata.type' -eq '#microsoft.graph.androidManagedStoreAppConfiguration') {

                # Check if the client app is present
                $amendedpackageid = $($JSON_Convert.packageId) -replace 'app:', ''
                $targetedMobileApp = Test-AppPackageId -packageId $amendedpackageid

                If ($targetedMobileApp) {
                    Write-Information "Targeted app $($JSON_Convert.packageId) has already been added from Managed Google Play"
                    Write-Information 'The App Configuration Policy will be created'

                    # Update the targetedMobileApps GUID if required
                    If (!($targetedMobileApp -eq $JSON_Convert.targetedMobileApps)) {
                        $JSON_Convert.targetedMobileApps.SetValue($targetedMobileApp, 0)
                    }

                    $JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 5
                    Write-Information "Adding App Configuration Policy '$DisplayName'"
                    New-AppConfigPolicyDevice -JSON $JSON_Output
                }
                Else {
                    Write-Error "Targeted app package id '$($JSON_Convert.packageId)' has not been added from Managed Google Play"
                    Write-Error "The App Configuration Policy can't be created"
                }
            }
        }
    }
}