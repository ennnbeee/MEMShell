Function Invoke-DeviceNotificationMessage {

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
        $JSON_Convert = $JSON_Data | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, version, supportsScopeTags, roleScopeTagIds
        $Subject = $JSON_Convert.subject
        $filename = $file.Name.split('.')[0]

        $NotificationTemplate = (Get-DeviceNotificationTemplate | Where-Object { ($_.displayName).equals("$filename") })

        if (Get-DeviceNotificationMessage -Id $NotificationTemplate.id | Where-Object { ($_.subject).equals($Subject) }) {
            Write-Information "Notification Message with subject '$Subject' already exists on template '$($NotificationTemplate.displayName)'"
        }
        else {

            $JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 5
            Write-Information "Adding Notification Message '$Subject' to '$($NotificationTemplate.displayName)'"
            New-DeviceNotificationMessage -Id $NotificationTemplate.id -JSON $JSON_Output
            Write-Information "Sucessfully Added Notification Message with subject '$Subject' to template '$($NotificationTemplate.displayName)'"
        }
    }
}