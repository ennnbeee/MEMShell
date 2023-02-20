Function Invoke-AppProtectionPolicy {

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

        [ValidateSet('Corporate', 'Personal', 'Both')]
        [string]$Enrolment
    )

    $Files = Get-ChildItem -Path $Path -Filter *.json | Where-Object { ($_.name -like "*$OS*") }

    foreach ($file in $files) {
        $ImportPath = $file.FullName
        $JSON_Data = Get-Content "$ImportPath"
        $JSON_Convert = $JSON_Data | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, version, '@odata.context', apps@odata.context, deployedAppCount
        $JSON_Apps = $JSON_Convert.apps | Select-Object * -ExcludeProperty id, version
        $JSON_Convert | Add-Member -MemberType NoteProperty -Name 'apps' -Value @($JSON_Apps) -Force
        $DisplayName = $JSON_Convert.displayName

        if (Get-AppProtectionPolicy | Where-Object { ($_.displayName).equals($DisplayName) }) {
            Write-Information "App Protection Policy '$DisplayName' already exists"
        }
        else {

            $JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 5
            Write-Information "Adding App Protection Policy '$DisplayName'"
            New-AppProtectionPolicy -JSON $JSON_Output
            WWrite-Information "Sucessfully added App Protection Policy '$DisplayName'"
        }
    }



}