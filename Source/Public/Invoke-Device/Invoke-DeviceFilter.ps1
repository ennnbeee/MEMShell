Function Invoke-DeviceFilter {

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
        [string]$Enrolment
    )

    $Files = Get-ChildItem -Path $Path -Filter *.json | Where-Object { ($_.name -like "*$OS*") -and ($_.name -like "*$Enrolment*") }

    foreach ($file in $files) {
        $ImportPath = $file.FullName
        $JSON_Data = Get-Content "$ImportPath"
        $JSON_Convert = $JSON_Data | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, roleScopeTags
        $DisplayName = $JSON_Convert.displayName

        if (Get-DeviceFilter | Where-Object { ($_.displayName).equals($DisplayName) }) {
            Write-Host "Intune Filter '$DisplayName' already exists..." -ForegroundColor Cyan

        }
        else {
            $JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 5
            Write-Host "Adding Intune Filter '$DisplayName'" -ForegroundColor Cyan
            New-DeviceFilter -JSON $JSON_Output
            Write-Host "Sucessfully Added Intune Filter '$DisplayName'" -ForegroundColor Green
        }
    }
}