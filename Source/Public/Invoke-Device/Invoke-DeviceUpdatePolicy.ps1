Function Invoke-DeviceUpdatePolicy {

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
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string[]]$Path,
        [ValidateSet('Windows', 'Android', 'iOS', 'macOS')]
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
        $JSON_Convert = $JSON_Data | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, version, 'groupAssignments@odata.context', groupAssignments, supportsScopeTags
        $DisplayName = $JSON_Convert.displayName

        if ($DisplayName -like '*Windows*') {
            if (Get-DeviceUpdatePolicy -Windows10 | Where-Object { ($_.displayName).equals($DisplayName) }) {
                Write-Host "Windows Software Update Policy '$DisplayName' already exists..." -ForegroundColor Cyan

            }
            else {

                $JSON_Output = $JSON_Convert | ConvertTo-Json
                Write-Host "Adding Windows Software Update Policy '$DisplayName'" -ForegroundColor Cyan
                New-DeviceConfigProfile -JSON $JSON_Output
                Write-Host "Sucessfully Added Windows Software Update Profile '$DisplayName'" -ForegroundColor Green
            }
        }
        elseif ($DisplayName -like '*iOS*') {
            if (Get-DeviceUpdatePolicy -iOS | Where-Object { ($_.displayName).equals($DisplayName) }) {
                Write-Host "iOS Software Update Policy '$DisplayName' already exists..." -ForegroundColor Cyan

            }
            else {

                $JSON_Output = $JSON_Convert | ConvertTo-Json
                Write-Host "Adding iOS Software Update Policy '$DisplayName'" -ForegroundColor Cyan
                New-DeviceConfigProfile -JSON $JSON_Output
                Write-Host "Sucessfully Added iOS Software Update Profile '$DisplayName'" -ForegroundColor Green
            }
        }
        elseif ($DisplayName -like '*macOS*') {
            if (Get-DeviceUpdatePolicy -macOS | Where-Object { ($_.displayName).equals($DisplayName) }) {
                Write-Host "macOS Software Update Policy '$DisplayName' already exists..." -ForegroundColor Cyan

            }
            else {

                $JSON_Output = $JSON_Convert | ConvertTo-Json
                Write-Host "Adding macOS Software Update Policy '$DisplayName'" -ForegroundColor Cyan
                New-DeviceConfigProfile -JSON $JSON_Output
                Write-Host "Sucessfully Added macOS Software Update Profile '$DisplayName'" -ForegroundColor Green
            }
        }
    }


}