Function New-MEMGroup() {

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

    [cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]

    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Description,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Dynamic', 'Assigned')]
        [string]$Type,

        [Parameter(Mandatory = $true)]
        [boolean]$Security,

        [Parameter(Mandatory = $true)]
        [boolean]$Mail,

        [string]$Rule
    )


    $graphApiVersion = 'beta'
    $Resource = 'groups'

    $MailName = $Name -replace '\s', ''
    $Output = New-Object -TypeName psobject
    $Output | Add-Member -MemberType NoteProperty -Name 'description' -Value $Description
    $Output | Add-Member -MemberType NoteProperty -Name 'displayName' -Value $Name

    if ($Type -eq 'Dynamic') {
        $Output | Add-Member -MemberType NoteProperty -Name 'groupTypes' -Value @('DynamicMembership')
        if (!$Rule) {
            Write-Host 'No Dynamic Membership rule found' -ForegroundColor Red
            Break
        }
        else {
            $Output | Add-Member -MemberType NoteProperty -Name 'membershipRule' -Value $Rule
            $Output | Add-Member -MemberType NoteProperty -Name 'membershipRuleProcessingState' -Value 'On'
        }
    }
    elseif ($Type -eq 'Assigned') {
        $Output | Add-Member -MemberType NoteProperty -Name 'groupTypes' -Value @()
    }

    $Output | Add-Member -MemberType NoteProperty -Name 'mailEnabled' -Value $Mail
    $Output | Add-Member -MemberType NoteProperty -Name 'mailNickname' -Value $MailName
    $Output | Add-Member -MemberType NoteProperty -Name 'securityEnabled' -Value $Security

    $JSON = $Output | ConvertTo-Json -Depth 5

    try {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        if ($PSCmdlet.ShouldProcess('ShouldProcess?')) {
            Invoke-MEMRestMethod -Uri $uri -Method Post -Body $JSON
        }

    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}