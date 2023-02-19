Function Invoke-DeviceConfigProfile {

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
        # Excluding entries that are not required - id,createdDateTime,lastModifiedDateTime,version
        $JSON_Convert = $JSON_Data | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, version, supportsScopeTags
        $DisplayName = $JSON_Convert.displayName

        if (Get-DeviceConfigProfile | Where-Object { ($_.displayName).equals($DisplayName) }) {
            Write-Host "Configuration Profile '$DisplayName' already exists..." -ForegroundColor Cyan

        }
        else {

            $JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 5
            Write-Host "Adding Device Configuration Policy '$DisplayName'" -ForegroundColor Cyan
            New-DeviceConfigProfile -JSON $JSON_Output
            Write-Host "Sucessfully Added Configuration Profile '$DisplayName'" -ForegroundColor Green
        }
    }
}