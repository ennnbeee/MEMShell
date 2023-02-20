Function Invoke-DeviceCompliancePolicy {

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
        $JSON_Convert = $JSON_Data | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, version
        $DisplayName = $JSON_Convert.displayName

        if (Get-DeviceCompliancePolicy | Where-Object { ($_.displayName).equals($DisplayName) }) {
            Write-Information "Compliance Policy '$DisplayName' already exists..."

        }
        else {

            # Adding Scheduled Actions Rule to JSON
            #$scheduledActionsForRule = '"scheduledActionsForRule":[{"ruleName":"PasswordRequired","scheduledActionConfigurations":[{"actionType":"block","gracePeriodHours":0,"notificationTemplateId":"","notificationMessageCCList":[]}]}]'
            #$JSON_Output = $JSON_Output.trimend("}")
            #$JSON_Output = $JSON_Output.TrimEnd() + "," + "`r`n"
            # Joining the JSON together
            #$JSON_Output = $JSON_Output + $scheduledActionsForRule + "`r`n" + "}"

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
            Write-Information "Adding Compliance Policy '$DisplayName'"
            New-DeviceCompliancePolicy -JSON $JSON_Output
            Write-Information "Sucessfully Added Compliance Policy '$DisplayName'"
        }
    }
}