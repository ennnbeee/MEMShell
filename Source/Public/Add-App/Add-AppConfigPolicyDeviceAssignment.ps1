Function Add-AppConfigPolicyDeviceAssignment() {

    <#
    .SYNOPSIS
    This function is used to assign App Configuration Profiles
    .DESCRIPTION
    The function assigns App Configuration Profiles for Devices to Groups and Filters
    .EXAMPLE
    Assigns the policy to All Device as Include, with Device Filter
    Add-AppConfigPolicyDeviceAssignment -Id {id} -AssignmentType Include -All Devices -FilterId {Id} -FilterMode Include

    .NOTES
    NAME: Add-AppConfigPolicyDeviceAssignment
    #>

    [cmdletbinding()]

    param
    (
        [parameter(Mandatory = $true)]
        [string]$Id,

        [string]$TargetGroupId,

        [parameter(Mandatory = $true)]
        [ValidateSet('Include', 'Exclude')]
        [string]$AssignmentType,

        [string]$FilterID,

        [ValidateSet('Include', 'Exclude')]
        [string]$FilterMode,

        [ValidateSet('Users', 'Devices')]
        [string]$All
    )

    $graphApiVersion = 'beta'
    $Resource = "deviceAppManagement/mobileAppConfigurations/$Id/microsoft.graph.managedDeviceMobileAppConfiguration/assign"

    try {
        $TargetGroup = New-Object -TypeName psobject
        if ($TargetGroupId) {
            if ($AssignmentType -eq 'Exclude') {
                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.exclusionGroupAssignmentTarget'
            }
            elseif ($AssignmentType -eq 'Include') {
                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.groupAssignmentTarget'
            }

            $TargetGroup | Add-Member -MemberType NoteProperty -Name 'groupId' -Value $TargetGroupId
        }
        else {
            if ($All -eq 'Users') {
                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.allLicensedUsersAssignmentTarget'
            }
            ElseIf ($All -eq 'Devices') {
                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.allDevicesAssignmentTarget'
            }
        }

        if (($FilterMode -eq 'Include') -or ($FilterMode -eq 'Exclude')) {
            $TargetGroup | Add-Member -MemberType NoteProperty -Name 'deviceAndAppManagementAssignmentFilterId' -Value $FilterID
            $TargetGroup | Add-Member -MemberType NoteProperty -Name 'deviceAndAppManagementAssignmentFilterType' -Value $FilterMode
        }

        $Target = New-Object -TypeName psobject
        $Target | Add-Member -MemberType NoteProperty -Name 'target' -Value $TargetGroup

        $TargetGroups = $Target

        # Creating JSON object to pass to Graph
        $Output = New-Object -TypeName psobject
        $Output | Add-Member -MemberType NoteProperty -Name 'assignments' -Value @($TargetGroups)
        $JSON = $Output | ConvertTo-Json -Depth 3
        Test-MEMJSON -Json $JSON
        # POST to Graph Service
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Post -Body $JSON
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}