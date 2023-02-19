Function Invoke-DeviceComplianceCustomPolicy {

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
        $JSON_Data = Get-Content "$ImportPath"
        # Excluding entries that are not required - id,createdDateTime,lastModifiedDateTime,version
        $JSON_Convert = $JSON_Data | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, version
        $DisplayName = $JSON_Convert.displayName
        $ComplianceScript = Get-DeviceCompliancePolicyScript | Where-Object { ($_.displayName).equals($DisplayName) }
        $JSON_Convert.deviceCompliancePolicyScript.deviceComplianceScriptId = $ComplianceScript.id

        if (Get-DeviceCompliancePolicy | Where-Object { ($_.displayName).equals($DisplayName) }) {
            Write-Host "Compliance Policy '$DisplayName' already exists..." -ForegroundColor Cyan

        }
        else {

            if (-not ($JSON_Convert.scheduledActionsForRule)) {
                $scheduledActionsForRule = @(
                    @{
                        ruleName                      = 'PasswordRequired'
                        scheduledActionConfigurations = @(
                            @{
                                actionType             = 'block'
                                gracePeriodHours       = 0
                                notificationTemplateId = ''
                            }
                        )
                    }
                )
                $JSON_Convert | Add-Member -NotePropertyName scheduledActionsForRule -NotePropertyValue $scheduledActionsForRule

            }
            $JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 5
            Write-Host "Adding Compliance Policy '$DisplayName'" -ForegroundColor Cyan
            New-DeviceCompliancePolicy -JSON $JSON_Output
            Write-Host "Sucessfully Added Compliance Policy '$DisplayName'" -ForegroundColor Green
        }
    }



}