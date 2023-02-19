Function Invoke-MEMGroups {

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
        [ValidateSet('Android', 'iOS', 'macOS', 'Windows')]
        [string[]]$OS,
        [ValidateSet('Corporate', 'Personal', 'Both', 'MAM', 'Autopilot')]
        [string]$Enrolment
    )

    If ($Enrolment -ne 'Both') {
        $Files = Get-ChildItem -Path $Path -Filter *.csv | Where-Object { ($_.name -like "*$OS*") -and ($_.name -like "*$Enrolment*") }
    }
    else {
        $Files = Get-ChildItem -Path $Path -Filter *.csv | Where-Object { ($_.name -like "*$OS*") }
    }

    foreach ($file in $files) {
        $Groups = Import-Csv -Path $file.FullName
        foreach ($Group in $Groups) {
            If (!(Get-MEMGroup -Name $Group.DisplayName)) {
                if (($null -eq $Group.MembershipRule) -or ($Group.MembershipRule -eq '')) {
                    New-MEMGroup -Name $Group.DisplayName -Description $Group.Description -Security $true -Mail $false -Type Assigned
                    Write-Host 'Successfully created the group '$Group.DisplayName'...' -ForegroundColor Green
                }
                else {
                    New-MEMGroup -Name $Group.DisplayName -Description $Group.Description -Security $true -Mail $false -type Dynamic -Rule $Group.MembershipRule
                    Write-Host 'Successfully created the group '$Group.DisplayName'...' -ForegroundColor Green
                }
            }
            Else {
                Write-Host 'The group '$Group.DisplayName' already exists......' -ForegroundColor Cyan
            }
        }
    }
}