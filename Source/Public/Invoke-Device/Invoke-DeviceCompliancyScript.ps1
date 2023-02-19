Function Invoke-DeviceCompliancyScript {

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
        [ValidateSet('Windows')]
        [string[]]$OS,
        [ValidateSet('Corporate', 'Personal')]
        [string]$Enrolment,
        [ValidateSet('CE', 'NCSC', 'MS')]
        [string]$Engagement
    )

    $Files = Get-ChildItem -Path $Path -Filter *.json | Where-Object { ($_.name -like "*$OS*") -and ($_.name -like "*$Enrolment*") -and ($_.name -like "*_$($Engagement)_*") }

    foreach ($file in $files) {
        $ImportPath = $file.FullName
        $DisplayName = ($file.name).Split('.')[0]

        if (Get-DeviceComplianceScript | Where-Object { ($_.displayName).equals($DisplayName) }) {
            Write-Host "Device Script '$DisplayName' already exists" -ForegroundColor Cyan

        }
        else {

            Write-Host "Adding Compliance Script '$DisplayName'" -ForegroundColor Cyan
            New-DeviceComplianceScript -File $ImportPath
            Write-Host "Sucessfully Added Compliance Script '$DisplayName'" -ForegroundColor Green
        }
    }
}