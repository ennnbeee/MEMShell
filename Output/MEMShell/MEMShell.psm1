#Region '.\Private\Export-JSONData.ps1' 0
Function Export-JSONData() {

    <#
    .SYNOPSIS
    This function is used to export JSON data returned from Graph
    .DESCRIPTION
    This function is used to export JSON data returned from Graph
    .EXAMPLE
    Export-JSONData -JSON $JSON -ExportPath 'C:\Temp\Output'
    Export the JSON inputted on the function
    .NOTES
    NAME: Export-JSONData
    #>

    [cmdletbinding()]
    param (
        [parameter(Mandatory = $true)]
        $JSON,

        [parameter(Mandatory = $true)]
        [string]$ExportPath
    )

    try {
        if (!(Test-Path $ExportPath)) {
            Write-Error "$ExportPath doesn't exist, can't export JSON Data"
            Break
        }
        else {

            $JSON = ConvertTo-Json $JSON -Depth 5
            $JSON_Convert = $JSON | ConvertFrom-Json
            $displayName = $JSON_Convert.displayName
            If ($null -eq $displayName) {
                $displayName = $JSON_Convert.name
            }
            # Updating display name to follow file naming conventions - https://msdn.microsoft.com/en-us/library/windows/desktop/aa365247%28v=vs.85%29.aspx
            $DisplayName = $DisplayName -replace '\<|\>|:|"|/|\\|\||\?|\*', '_'

            $FileName_JSON = "$DisplayName" + '_' + $(Get-Date -f dd-MM-yyyy-H-mm-ss) + '.json'

            $JSON | Set-Content -LiteralPath "$ExportPath\$FileName_JSON"
            Write-Information "JSON created in $ExportPath\$FileName_JSON"
        }
    }
    catch {
        $_.Exception
    }
}
#EndRegion '.\Private\Export-JSONData.ps1' 49
#Region '.\Private\Get-AuthTokenMSAL.ps1' 0
Function Get-AuthTokenMSAL {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthTokenMSAL
    Authenticates you with the Graph API interface using MSAL.PS module
    .NOTES
    NAME: Get-AuthTokenMSAL
    #>

    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$User
    )

    $userUpn = New-Object 'System.Net.Mail.MailAddress' -ArgumentList $User

    if ($userUpn.Host -like '*onmicrosoft.com*') {
        $tenant = Read-Host -Prompt 'Please specify your Tenant name i.e. company.com'
    }
    else {
        $tenant = $userUpn.Host
    }

    Write-Information 'Checking for MSAL.PS module...'

    $MSALModule = Get-Module -Name 'MSAL.PS' -ListAvailable

    if ($null -eq $MSALModule) {
        Write-Information 'MSAL.PS Powershell module not installed...'
        Write-Information "Install by running 'Install-Module MSAL.PS -Scope CurrentUser' from an elevated PowerShell prompt"
        Write-Error "Script can't continue..."
        break
    }

    if ($MSALModule.count -gt 1) {
        $Latest_Version = ($MSALModule | Select-Object version | Sort-Object)[-1]
        $MSALModule = $MSALModule | Where-Object { $_.version -eq $Latest_Version.version }
        if ($MSALModule.count -gt 1) {
            $MSALModule = $MSALModule | Select-Object -Unique
        }
    }

    $ClientId = 'd1ddf0e4-d672-4dae-b554-9d5bdfd93547'
    $RedirectUri = 'urn:ietf:wg:oauth:2.0:oob'
    $Authority = "https://login.microsoftonline.com/$Tenant"

    try {
        Import-Module $MSALModule.Name

        if ($PSVersionTable.PSVersion.Major -ne 7) {
            $authResult = Get-MsalToken -ClientId $ClientId -Interactive -RedirectUri $RedirectUri -Authority $Authority
        }
        else {
            $authResult = Get-MsalToken -ClientId $ClientId -Interactive -RedirectUri $RedirectUri -Authority $Authority -DeviceCode
        }

        if ($authResult.AccessToken) {
            $authHeader = @{
                'Content-Type'  = 'application/json'
                'Authorization' = 'Bearer ' + $authResult.AccessToken
                'ExpiresOn'     = $authResult.ExpiresOn
            }
            return [OutputType('System.Collections.Hashtable')]$authHeader
        }
        else {
            Write-Information 'Authorization Access Token is null, please re-run authentication...'
            break
        }
    }
    catch {
        Write-Error $_.Exception.Message
        Write-Error $_.Exception.ItemName
        break
    }
}
#EndRegion '.\Private\Get-AuthTokenMSAL.ps1' 82
#Region '.\Private\Invoke-MEMRestMethod.ps1' 0
Function Invoke-MEMRestMethod() {

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

    [cmdletbinding()]
    param (
        [parameter(Mandatory = $true)]
        [uri]$Uri,

        [parameter(Mandatory = $true)]
        [ValidateSet('Delete', 'Get', 'Patch', 'Post', 'Put')]
        [string]$Method,

        [string]$Body,

        [string]$ContentType = 'application/json'
    )

    Test-AuthToken

    $Headers = $global:authToken

    $Method = 'Get'
    if ($Method -eq 'Get') {
        $ValueOnly = 'True'
        $params = @{
            Uri     = $uri
            Method  = $Method
            Headers = $Headers
        }
    }
    elseif ($Method -eq 'Post') {
        $params = @{
            Uri         = $uri
            Method      = $Method
            Headers     = $Headers
            ContentType = $ContentType
            Body        = $Body
        }
    }
    elseif ($Method -eq 'Patch') {
        $params = @{
            Uri         = $uri
            Method      = $Method
            Headers     = $Headers
            ContentType = $ContentType
            Body        = $Body
        }
    }
    elseif ($Method -eq 'Delete') {
        $params = @{
            Uri     = $uri
            Method  = $Method
            Headers = $Headers
        }
    }
    Try {
        $Result = Invoke-RestMethod @params
        if ($ValueOnly) {
            return $Result.Value
        }
        else {
            return $Result
        }
    }
    Catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Private\Invoke-MEMRestMethod.ps1' 82
#Region '.\Private\Test-AppBundleId.ps1' 0
Function Test-AppBundleId() {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthTokenMSAL
    Authenticates you with the Graph API interface using MSAL.PS module
    .NOTES
    NAME: Get-AuthTokenMSAL
    #>

    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$bundleId
    )

    $graphApiVersion = 'Beta'
    $Resource = "deviceAppManagement/mobileApps?`$filter=(microsoft.graph.managedApp/appAvailability eq null or microsoft.graph.managedApp/appAvailability eq 'lineOfBusiness' or isAssigned eq true) and (isof('microsoft.graph.iosLobApp') or isof('microsoft.graph.iosStoreApp') or isof('microsoft.graph.iosVppApp') or isof('microsoft.graph.managedIOSStoreApp') or isof('microsoft.graph.managedIOSLobApp'))"

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        $mobileApps = Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
    }
    catch {
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Output "Response content:`n$ex"
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        break
    }
    Write-Output $bundleId | Out-Null
    $app = $mobileApps.value | Where-Object { $_.bundleId -eq $bundleId }
    If ($app) {
        return $app.id
    }
    Else {
        return [OutputType('System.Boolean')]$false
    }
}
#EndRegion '.\Private\Test-AppBundleId.ps1' 43
#Region '.\Private\Test-AppPackageId.ps1' 0
Function Test-AppPackageId() {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthTokenMSAL
    Authenticates you with the Graph API interface using MSAL.PS module
    .NOTES
    NAME: Get-AuthTokenMSAL
    #>

    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$packageId
    )

    $graphApiVersion = 'Beta'
    $Resource = "deviceAppManagement/mobileApps?`$filter=(isof('microsoft.graph.androidForWorkApp') or microsoft.graph.androidManagedStoreApp/supportsOemConfig eq false)"

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        $mobileApps = Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
    }
    catch {
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Output "Response content:`n$ex"
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        break
    }
    Write-Output $packageId | Out-Null
    $app = $mobileApps.value | Where-Object { $_.packageId -eq $packageId }

    If ($app) {
        return $app.id
    }
    Else {
        return [OutputType('System.Boolean')]$false
    }
}
#EndRegion '.\Private\Test-AppPackageId.ps1' 44
#Region '.\Private\Test-MEMJSON.ps1' 0
Function Test-MEMJSON() {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthTokenMSAL
    Authenticates you with the Graph API interface using MSAL.PS module
    .NOTES
    NAME: Get-AuthTokenMSAL
    #>

    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $true)]
        $JSON
    )

    try {
        $TestJSON = ConvertFrom-Json $JSON -ErrorAction Stop
        $TestJSON | Out-Null
        $validJson = $true
    }
    catch {
        $validJson = $false
        $_.Exception
    }

    if (!$validJson) {
        Write-Output "Provided JSON isn't in valid JSON format"
        break
    }
}
#EndRegion '.\Private\Test-MEMJSON.ps1' 35
#Region '.\Private\Write-MEMLog.ps1' 0
Function Write-MEMLog {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthTokenMSAL
    Authenticates you with the Graph API interface using MSAL.PS module
    .NOTES
    NAME: Get-AuthTokenMSAL
    #>

    [cmdletbinding()]
    Param(
        [parameter(Mandatory = $true)]
        [String]$Path,

        [parameter(Mandatory = $true)]
        [String]$Message,

        [parameter(Mandatory = $true)]
        [String]$Component,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Info', 'Warning', 'Error')]
        [String]$Type
    )

    switch ($Type) {
        'Info' { [int]$Type = 1 }
        'Warning' { [int]$Type = 2 }
        'Error' { [int]$Type = 3 }
    }

    # Create a log entry
    $Content = "<![LOG[$Message]LOG]!>" + `
        "<time=`"$(Get-Date -Format 'HH:mm:ss.ffffff')`" " + `
        "date=`"$(Get-Date -Format 'M-d-yyyy')`" " + `
        "component=`"$Component`" " + `
        "context=`"$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " + `
        "type=`"$Type`" " + `
        "thread=`"$([Threading.Thread]::CurrentThread.ManagedThreadId)`" " + `
        "file=`"`">"

    # Write the line to the log file
    Add-Content -Path $Path -Value $Content
}
#EndRegion '.\Private\Write-MEMLog.ps1' 49
#Region '.\Public\Add-App\Add-AppCategory.ps1' 0
Function Add-AppCategory() {

    <#
    .SYNOPSIS
    This function is used to add new App Categories to Intune
    .DESCRIPTION
    Allows for the creation of new App Categories
    .EXAMPLE
    Add-AppCategory -Name 'User Apps'
    .NOTES
    NAME: Add-AppCategory
    #>

    [cmdletbinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceAppManagement/mobileAppCategories'

    try {
        $Output = New-Object -TypeName psobject
        $Output | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.mobileAppCategory'
        $Output | Add-Member -MemberType NoteProperty 'displayName' -Value $Name
        $JSON = $Output | ConvertTo-Json -Depth 3
        Test-MEMJSON -Json $JSON
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
#EndRegion '.\Public\Add-App\Add-AppCategory.ps1' 40
#Region '.\Public\Add-App\Add-AppConfigPolicyDeviceAssignment.ps1' 0
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
#EndRegion '.\Public\Add-App\Add-AppConfigPolicyDeviceAssignment.ps1' 87
#Region '.\Public\Add-App\Add-AppMobileAppAssignment.ps1' 0
Function Add-AppMobileAppAssignment() {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthTokenMSAL
    Authenticates you with the Graph API interface using MSAL.PS module
    .NOTES
    NAME: Get-AuthTokenMSAL
    #>

    [cmdletbinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Id,

        [parameter(Mandatory = $false)]
        [string]$TargetGroupId,

        [parameter(Mandatory = $true)]
        [ValidateSet('Available', 'Required')]
        [string]$InstallIntent,

        [string]$FilterID,

        [ValidateSet('Include', 'Exclude')]
        [string]$FilterMode,

        [parameter(Mandatory = $false)]
        [ValidateSet('Users', 'Devices')]
        [string]$All,

        [parameter(Mandatory = $true)]
        [ValidateSet('Replace', 'Add')]
        [string]$Action
    )

    $graphApiVersion = 'beta'
    $Resource = "deviceAppManagement/mobileApps/$Id/assign"

    try {
        $TargetGroups = @()

        If ($Action -eq 'Add') {
            # Checking if there are Assignments already configured
            $Assignments = (Get-ApplicationAssignment -Id $Id).assignments
            if (@($Assignments).count -ge 1) {
                foreach ($Assignment in $Assignments) {

                    If (($null -ne $TargetGroupId) -and ($TargetGroupId -eq $Assignment.target.groupId)) {
                        Write-Output 'The App is already assigned to the Group'
                    }
                    ElseIf (($All -eq 'Devices') -and ($Assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget')) {
                        Write-Output 'The App is already assigned to the All Devices Group'
                    }
                    ElseIf (($All -eq 'Users') -and ($Assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget')) {
                        Write-Output 'The App is already assigned to the All Users Group'
                    }
                    Else {
                        $TargetGroup = New-Object -TypeName psobject

                        if (($Assignment.target).'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                            $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.groupAssignmentTarget'
                            $TargetGroup | Add-Member -MemberType NoteProperty -Name 'groupId' -Value $Assignment.target.groupId
                        }

                        elseif (($Assignment.target).'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                            $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.allLicensedUsersAssignmentTarget'
                        }
                        elseif (($Assignment.target).'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                            $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.allDevicesAssignmentTarget'
                        }

                        if ($Assignment.target.deviceAndAppManagementAssignmentFilterType -ne 'none') {

                            $TargetGroup | Add-Member -MemberType NoteProperty -Name 'deviceAndAppManagementAssignmentFilterId' -Value $Assignment.target.deviceAndAppManagementAssignmentFilterId
                            $TargetGroup | Add-Member -MemberType NoteProperty -Name 'deviceAndAppManagementAssignmentFilterType' -Value $Assignment.target.deviceAndAppManagementAssignmentFilterType
                        }

                        $Target = New-Object -TypeName psobject
                        $Target | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.mobileAppAssignment'
                        $Target | Add-Member -MemberType NoteProperty -Name 'intent' -Value $Assignment.intent
                        $Target | Add-Member -MemberType NoteProperty -Name 'target' -Value $TargetGroup
                        $TargetGroups += $Target
                    }
                }
            }
        }

        $Target = New-Object -TypeName psobject
        $Target | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.mobileAppAssignment'
        $Target | Add-Member -MemberType NoteProperty -Name 'intent' -Value $InstallIntent

        $TargetGroup = New-Object -TypeName psobject
        if ($TargetGroupId) {
            $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.groupAssignmentTarget'
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

        if ($FilterMode) {
            $TargetGroup | Add-Member -MemberType NoteProperty -Name 'deviceAndAppManagementAssignmentFilterId' -Value $FilterID
            $TargetGroup | Add-Member -MemberType NoteProperty -Name 'deviceAndAppManagementAssignmentFilterType' -Value $FilterMode
        }

        $Target | Add-Member -MemberType NoteProperty -Name 'target' -Value $TargetGroup
        $TargetGroups += $Target
        $Output = New-Object -TypeName psobject
        $Output | Add-Member -MemberType NoteProperty -Name 'mobileAppAssignments' -Value @($TargetGroups)

        $JSON = $Output | ConvertTo-Json -Depth 3
        Test-MEMJSON -Json $JSON
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
#EndRegion '.\Public\Add-App\Add-AppMobileAppAssignment.ps1' 134
#Region '.\Public\Add-App\Add-AppMobileAppCategory.ps1' 0
Function Add-AppMobileAppCategory() {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthTokenMSAL
    Authenticates you with the Graph API interface using MSAL.PS module
    .NOTES
    NAME: Get-AuthTokenMSAL
    #>

    [cmdletbinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Id,

        [Parameter(Mandatory = $true)]
        [string]$CategoryId
    )

    $graphApiVersion = 'Beta'
    $Resource = "deviceAppManagement/mobileApps/$Id/categories/`$ref"

    try {
        $value = "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/mobileAppCategories/$CategoryId"
        $Output = New-Object -TypeName psobject
        $Output | Add-Member -MemberType NoteProperty -Name '@odata.id' -Value $value
        $JSON = $Output | ConvertTo-Json -Depth 3
        Test-MEMJSON -Json $JSON
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
#EndRegion '.\Public\Add-App\Add-AppMobileAppCategory.ps1' 44
#Region '.\Public\Add-App\Add-AppProtectionPolicyAssignment.ps1' 0
Function Add-AppProtectionPolicyAssignment() {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthTokenMSAL
    Authenticates you with the Graph API interface using MSAL.PS module
    .NOTES
    NAME: Get-AuthTokenMSAL
    #>

    [cmdletbinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Id,

        [string]$TargetGroupId,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Android', 'iOS')]
        [string]$OS,

        [ValidateSet('Include', 'Exclude')]
        [string]$AssignmentType
    )

    $graphApiVersion = 'Beta'

    try {
        $TargetGroup = New-Object -TypeName psobject

        if ($TargetGroupId) {
            if ($AssignmentType -eq 'Exclude') {
                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.exclusionGroupAssignmentTarget'
            }
            elseif ($AssignmentType -eq 'Include') {
                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.groupAssignmentTarget'
            }

            $TargetGroup | Add-Member -MemberType NoteProperty -Name 'groupId' -Value "$TargetGroupId"
        }

        else {
            $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.allLicensedUsersAssignmentTarget'
        }

        $Target = New-Object -TypeName psobject
        $Target | Add-Member -MemberType NoteProperty -Name 'target' -Value $TargetGroup

        $TargetGroups = $Target

        # Creating JSON object to pass to Graph
        $Output = New-Object -TypeName psobject
        $Output | Add-Member -MemberType NoteProperty -Name 'assignments' -Value @($TargetGroups)
        $JSON = $Output | ConvertTo-Json -Depth 3
        Test-MEMJSON -Json $JSON
        if ($OS -eq 'Android') {
            $uri = "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/androidManagedAppProtections('$ID')/assign"
        }

        elseif ($OS -eq 'iOS') {
            $uri = "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/iosManagedAppProtections('$ID')/assign"
        }

        Invoke-MEMRestMethod -Uri $uri -Method Post -Body $JSON
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Add-App\Add-AppProtectionPolicyAssignment.ps1' 78
#Region '.\Public\Add-Device\Add-DeviceCompliancePolicyAssignment.ps1' 0
Function Add-DeviceCompliancePolicyAssignment() {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthTokenMSAL
    Authenticates you with the Graph API interface using MSAL.PS module
    .NOTES
    NAME: Get-AuthTokenMSAL
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

        [string]$FilterMode,

        [ValidateSet('Users', 'Devices')]
        [string]$All
    )

    $graphApiVersion = 'v1.0'
    $Resource = "deviceManagement/deviceCompliancePolicies/$Id/assign"

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
#EndRegion '.\Public\Add-Device\Add-DeviceCompliancePolicyAssignment.ps1' 87
#Region '.\Public\Add-Device\Add-DeviceConfigProfileAssignment.ps1' 0
Function Add-DeviceConfigProfileAssignment() {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthTokenMSAL
    Authenticates you with the Graph API interface using MSAL.PS module
    .NOTES
    NAME: Get-AuthTokenMSAL
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

    $graphApiVersion = 'Beta'
    $Resource = "deviceManagement/deviceConfigurations/$Id/assign"

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

        $TargetGroups += $Target

        $Output = New-Object -TypeName psobject
        $Output | Add-Member -MemberType NoteProperty -Name 'assignments' -Value @($TargetGroups)
        $JSON = $Output | ConvertTo-Json -Depth 3

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
#EndRegion '.\Public\Add-Device\Add-DeviceConfigProfileAssignment.ps1' 87
#Region '.\Public\Add-Device\Add-DeviceEndpointSecProfileAssignment.ps1' 0
Function Add-DeviceEndpointSecurityAssignment() {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthTokenMSAL
    Authenticates you with the Graph API interface using MSAL.PS module
    .NOTES
    NAME: Get-AuthTokenMSAL
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

    $graphApiVersion = 'Beta'
    $Resource = "deviceManagement/intents/$Id/assign"

    try {
        $TargetGroup = New-Object -TypeName psobject

        if ($TargetGroupId) {
            if ($AssignmentType -eq 'Exclude') {
                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.exclusionGroupAssignmentTarget'
            }
            elseif ($AssignmentType -eq 'Include') {
                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.groupAssignmentTarget'
            }

            $TargetGroup | Add-Member -MemberType NoteProperty -Name 'groupId' -Value "$TargetGroupId"
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

        $Output = New-Object -TypeName psobject
        $Output | Add-Member -MemberType NoteProperty -Name 'assignments' -Value @($TargetGroups)
        $JSON = $Output | ConvertTo-Json -Depth 3

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
#EndRegion '.\Public\Add-Device\Add-DeviceEndpointSecProfileAssignment.ps1' 86
#Region '.\Public\Add-Device\Add-DeviceSettingsCatalogAssignment.ps1' 0
Function Add-DeviceSettingsCatalogAssignment() {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthTokenMSAL
    Authenticates you with the Graph API interface using MSAL.PS module
    .NOTES
    NAME: Get-AuthTokenMSAL
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

    $graphApiVersion = 'Beta'
    $Resource = "deviceManagement/configurationPolicies/$Id/assign"

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

        $Output = New-Object -TypeName psobject
        $Output | Add-Member -MemberType NoteProperty -Name 'assignments' -Value @($TargetGroups)
        $JSON = $Output | ConvertTo-Json -Depth 3

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
#EndRegion '.\Public\Add-Device\Add-DeviceSettingsCatalogAssignment.ps1' 86
#Region '.\Public\Add-Enrolment\Add-EnrolmentADEProfileAssignment.ps1' 0
Function Add-EnrolmentADEProfileAssignment() {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthTokenMSAL
    Authenticates you with the Graph API interface using MSAL.PS module
    .NOTES
    NAME: Get-AuthTokenMSAL
    #>

    [cmdletbinding()]

    Param(
        [Parameter(Mandatory = $true)]
        [string]$Id,

        [Parameter(Mandatory = $true)]
        [string]$ProfileID,

        [Parameter(Mandatory = $true)]
        [string]$DeviceSerials
    )

    $graphApiVersion = 'Beta'
    $Resource = "deviceManagement/depOnboardingSettings/$Id/enrollmentProfiles('$ProfileID')/updateDeviceProfileAssignment"

    $Output = New-Object -TypeName psobject
    $Output | Add-Member -MemberType NoteProperty -Name 'deviceIds' -Value $DeviceSerials
    $JSON = $Output | ConvertTo-Json -Depth 3

    try {
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
#EndRegion '.\Public\Add-Enrolment\Add-EnrolmentADEProfileAssignment.ps1' 45
#Region '.\Public\Add-Enrolment\Add-EnrolmentAutopilotProfileAssignment.ps1' 0
Function Add-EnrolmentAutopilotProfileAssignment() {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthTokenMSAL
    Authenticates you with the Graph API interface using MSAL.PS module
    .NOTES
    NAME: Get-AuthTokenMSAL
    #>

    [cmdletbinding()]

    param
    (
        [parameter(Mandatory = $true)]
        [string]$Id,

        [parameter(Mandatory = $true)]
        [string]$TargetGroupId,

        [parameter(Mandatory = $true)]
        [ValidateSet('Include', 'Exclude')]
        [string]$AssignmentType
    )

    $graphApiVersion = 'Beta'
    $Resource = "deviceManagement/windowsAutopilotDeploymentProfiles/$Id/assignments"

    try {
        $TargetGroup = New-Object -TypeName psobject

        if ($AssignmentType -eq 'Exclude') {
            $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.exclusionGroupAssignmentTarget'
        }
        elseif ($AssignmentType -eq 'Include') {
            $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.groupAssignmentTarget'
        }

        $TargetGroup | Add-Member -MemberType NoteProperty -Name 'groupId' -Value $TargetGroupId

        $Target = New-Object -TypeName psobject
        $Target | Add-Member -MemberType NoteProperty -Name 'target' -Value $TargetGroup

        $JSON = $Target | ConvertTo-Json -Depth 3

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
#EndRegion '.\Public\Add-Enrolment\Add-EnrolmentAutopilotProfileAssignment.ps1' 59
#Region '.\Public\Add-Enrolment\Add-EnrolmentESPAssignment.ps1' 0
Function Add-EnrolmentESPAssignment() {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthTokenMSAL
    Authenticates you with the Graph API interface using MSAL.PS module
    .NOTES
    NAME: Get-AuthTokenMSAL
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

    $graphApiVersion = 'Beta'
    $Resource = "deviceManagement/deviceEnrollmentConfigurations/$Id/assign"

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

        $Output = New-Object -TypeName psobject
        $Output | Add-Member -MemberType NoteProperty -Name 'enrollmentConfigurationAssignments' -Value @($Target)
        $JSON = $Output | ConvertTo-Json -Depth 3

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
#EndRegion '.\Public\Add-Enrolment\Add-EnrolmentESPAssignment.ps1' 85
#Region '.\Public\Add-Enrolment\Add-EnrolmentRestrictionAssignment.ps1' 0
Function Add-EnrolmentRestrictionAssignment() {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthTokenMSAL
    Authenticates you with the Graph API interface using MSAL.PS module
    .NOTES
    NAME: Get-AuthTokenMSAL
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

    $graphApiVersion = 'Beta'
    $Resource = "deviceManagement/deviceEnrollmentConfigurations/$Id/assign"

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

        # Creating JSON object to pass to Graph
        $Output = New-Object -TypeName psobject
        $Output | Add-Member -MemberType NoteProperty -Name 'enrollmentConfigurationAssignments' -Value @($Target)
        $JSON = $Output | ConvertTo-Json -Depth 3

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
#EndRegion '.\Public\Add-Enrolment\Add-EnrolmentRestrictionAssignment.ps1' 85
#Region '.\Public\Export-JSON\Export-JSONIntune.ps1' 0
Function Export-JSONIntune() {

    <#
    .SYNOPSIS
    This function is used to get export JSON data from Intune
    .DESCRIPTION
    The function connects allows data collected from another Intune Function to be exported to JSON files
    .EXAMPLE
    $Compliance = Get-DeviceComplicyPolicy
    Export-JSONSettings -Path 'C:\Temp\Output' -Settings $Compliance
    Returns any autopilot devices
    .NOTES
    NAME: Export-JSONIntune
    #>
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [string]$Path,

        [parameter(Mandatory = $true)]
        $Settings
    )

    try {
        $Path = $Path.replace('"','')
        if (!(Test-Path "$Path")) {
            $Confirm = Read-Host "Path '$Path' doesn't exist, do you want to create this directory? Y or N?"
            if ($Confirm -eq 'y' -or $Confirm -eq 'Y') {
                New-Item -ItemType Directory -Path "$Path" | Out-Null
            }
            else {
                Write-Error 'Creation of directory path was cancelled...'
                break
            }
        }

        foreach ($Setting in $Settings) {
            Export-JSONData -JSON $Setting -ExportPath $Path
        }

    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }

}
#EndRegion '.\Public\Export-JSON\Export-JSONIntune.ps1' 50
#Region '.\Public\Get-App\Get-AppCategory.ps1' 0
Function Get-AppCategory() {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthTokenMSAL
    Authenticates you with the Graph API interface using MSAL.PS module
    .NOTES
    NAME: Get-AuthTokenMSAL
    #>

    [cmdletbinding()]

    $graphApiVersion = 'Beta'
    $Resource = 'deviceAppManagement/mobileAppCategories'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Get
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Get-App\Get-AppCategory.ps1' 30
#Region '.\Public\Get-App\Get-AppConfigPolicyApp.ps1' 0
Function Get-AppConfigPolicyApp() {

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

    [cmdletbinding()]

    $graphApiVersion = 'Beta'
    $Resource = "deviceAppManagement/targetedManagedAppConfigurations?`$expand=apps"

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Get
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Get-App\Get-AppConfigPolicyApp.ps1' 30
#Region '.\Public\Get-App\Get-AppConfigPolicyDevice.ps1' 0
Function Get-AppConfigPolicyDevice() {

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

    [cmdletbinding()]

    $graphApiVersion = 'Beta'
    $Resource = 'deviceAppManagement/mobileAppConfigurations'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Get
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Get-App\Get-AppConfigPolicyDevice.ps1' 30
#Region '.\Public\Get-App\Get-AppMobileApp.ps1' 0
Function Get-AppMobileApp() {

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

    [cmdletbinding()]

    $graphApiVersion = 'Beta'
    $Resource = 'deviceAppManagement/mobileApps'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Get
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Get-App\Get-AppMobileApp.ps1' 30
#Region '.\Public\Get-App\Get-AppMobileAppAssignment.ps1' 0
Function Get-AppMobileAppAssignment() {

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

    [cmdletbinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        $Id
    )

    $graphApiVersion = 'Beta'
    $Resource = "deviceAppManagement/mobileApps/$Id/?`$expand=categories,assignments"

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Get
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Get-App\Get-AppMobileAppAssignment.ps1' 36
#Region '.\Public\Get-App\Get-AppMobileAppCategory.ps1' 0
Function Get-AppMobileAppCategory() {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthTokenMSAL
    Authenticates you with the Graph API interface using MSAL.PS module
    .NOTES
    NAME: Get-AuthTokenMSAL
    #>

    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        $Id
    )

    $graphApiVersion = 'Beta'
    $Resource = "deviceAppManagement/mobileApps/$Id/categories"

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Get
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Get-App\Get-AppMobileAppCategory.ps1' 35
#Region '.\Public\Get-App\Get-AppProtectionPolicy.ps1' 0
Function Get-AppProtectionPolicy() {

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

    [cmdletbinding()]

    $graphApiVersion = 'Beta'
    $Resource = 'deviceAppManagement/managedAppPolicies'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Get | Where-Object { ($_.'@odata.type').contains('ManagedAppProtection') -or ($_.'@odata.type').contains('InformationProtectionPolicy') }
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Get-App\Get-AppProtectionPolicy.ps1' 30
#Region '.\Public\Get-Device\Get-DeviceAutopilot.ps1' 0
Function Get-DeviceAutopilot() {

    <#
    .SYNOPSIS
    This function is used to get autopilot devices via the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any autopilot devices
    .EXAMPLE
    Get-AutopilotDevices
    Returns any autopilot devices
    .NOTES
    NAME: Get-AutopilotDevices
    #>
    [cmdletbinding()]

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/windowsAutopilotDeviceIdentities'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Get
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Get-Device\Get-DeviceAutopilot.ps1' 29
#Region '.\Public\Get-Device\Get-DeviceCompliancePolicy.ps1' 0
Function Get-DeviceCompliancePolicy() {

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

    [cmdletbinding()]

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/deviceCompliancePolicies'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Get
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Get-Device\Get-DeviceCompliancePolicy.ps1' 30
#Region '.\Public\Get-Device\Get-DeviceComplianceScript.ps1' 0
Function Get-DeviceComplianceScript() {

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

    [cmdletbinding()]

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/deviceComplianceScripts'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Get
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Get-Device\Get-DeviceComplianceScript.ps1' 30
#Region '.\Public\Get-Device\Get-DeviceConfigProfile.ps1' 0
Function Get-DeviceConfigProfile() {

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

    [cmdletbinding()]

    $graphApiVersion = 'beta'
    $Resource = 'deviceManagement/deviceConfigurations'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Get
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Get-Device\Get-DeviceConfigProfile.ps1' 30
#Region '.\Public\Get-Device\Get-DeviceConfigProfileAssignment.ps1' 0
Function Get-DeviceConfigProfileAssignment() {

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

    [cmdletbinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        $Id
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/deviceConfigurations'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$Id/Assignments/"
        Invoke-MEMRestMethod -Uri $uri -Method Get
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Get-Device\Get-DeviceConfigProfileAssignment.ps1' 36
#Region '.\Public\Get-Device\Get-DeviceEndpointSecProfile.ps1' 0
Function Get-DeviceEndpointSecProfile() {

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

    [cmdletbinding()]

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/intents'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Get

    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Get-Device\Get-DeviceEndpointSecProfile.ps1' 31
#Region '.\Public\Get-Device\Get-DeviceEndpointSecTemplate.ps1' 0
Function Get-DeviceEndpointSecTemplate() {

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

    [cmdletbinding()]

    $graphApiVersion = 'Beta'
    $Resource = "deviceManagement/templates?`$filter=(isof(%27microsoft.graph.securityBaselineTemplate%27))"

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Get
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Get-Device\Get-DeviceEndpointSecTemplate.ps1' 30
#Region '.\Public\Get-Device\Get-DeviceFilter.ps1' 0
Function Get-DeviceFilter() {

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

    [cmdletbinding()]

    $graphApiVersion = 'beta'
    $Resource = 'deviceManagement/assignmentFilters'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Get
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Get-Device\Get-DeviceFilter.ps1' 30
#Region '.\Public\Get-Device\Get-DeviceManagedDevice.ps1' 0
Function Get-DeviceManagedDevice() {

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

    [cmdletbinding()]
    param
    (
        [switch]$IncludeEAS,
        [switch]$ExcludeMDM
    )

    $graphApiVersion = 'beta'
    $Resource = 'deviceManagement/managedDevices'

    try {
        $Count_Params = 0

        if ($IncludeEAS.IsPresent) { $Count_Params++ }
        if ($ExcludeMDM.IsPresent) { $Count_Params++ }
        if ($Count_Params -gt 1) {
            Write-Warning 'Multiple parameters set, specify a single parameter -IncludeEAS, -ExcludeMDM or no parameter against the function'
            break
        }
        elseif ($IncludeEAS) {
            $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        }
        elseif ($ExcludeMDM) {
            $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource`?`$filter=managementAgent eq 'eas'"
        }
        else {
            $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource`?`$filter=managementAgent eq 'mdm' and managementAgent eq 'easmdm'"
        }

        Invoke-MEMRestMethod -Uri $uri -Method Get
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Get-Device\Get-DeviceManagedDevice.ps1' 52
#Region '.\Public\Get-Device\Get-DeviceNotificationMessage.ps1' 0
Function Get-DeviceNotificationMessage() {

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

    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true)]
        $Id
    )

    $graphApiVersion = 'Beta'
    $Resource = "deviceManagement/notificationMessageTemplates/$Id/localizedNotificationMessages"

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Get
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Get-Device\Get-DeviceNotificationMessage.ps1' 34
#Region '.\Public\Get-Device\Get-DeviceNotificationTemplate.ps1' 0
Function Get-DeviceNotificationTemplate() {

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

    [cmdletbinding()]

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/notificationMessageTemplates'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Get
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Get-Device\Get-DeviceNotificationTemplate.ps1' 30
#Region '.\Public\Get-Device\Get-DeviceScript.ps1' 0
Function Get-DeviceScript() {

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

    [cmdletbinding()]

    param (

        [Parameter(Mandatory = $true)]
        $Id

    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/deviceManagementScripts'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$Id"
        Invoke-MEMRestMethod -Uri $uri -Method Get
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Get-Device\Get-DeviceScript.ps1' 37
#Region '.\Public\Get-Device\Get-DeviceScriptAssignment.ps1' 0
Function Get-DeviceScriptAssignment() {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthTokenMSAL
    Authenticates you with the Graph API interface using MSAL.PS module
    .NOTES
    NAME: Get-AuthTokenMSAL
    #>

    [cmdletbinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        $Id
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/deviceManagementScripts'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$Id/Assignments/"
        Invoke-MEMRestMethod -Uri $uri -Method Get
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Get-Device\Get-DeviceScriptAssignment.ps1' 36
#Region '.\Public\Get-Device\Get-DeviceSettingsCatalog.ps1' 0
Function Get-DeviceSettingsCatalog() {

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

    [cmdletbinding()]

    param
    (
        [parameter(Mandatory = $false)]
        [ValidateSet('windows10', 'macOS')]
        [ValidateNotNullOrEmpty()]
        [string]$Platform
    )

    $graphApiVersion = 'beta'
    if ($Platform) {
        $Resource = "deviceManagement/configurationPolicies?`$filter=platforms has '$Platform' and technologies has 'mdm'"
    }
    else {
        $Resource = "deviceManagement/configurationPolicies?`$filter=technologies has 'mdm'"
    }

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Get
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Get-Device\Get-DeviceSettingsCatalog.ps1' 43
#Region '.\Public\Get-Device\Get-DeviceUpdatePolicy.ps1' 0
Function Get-DeviceUpdatePolicy() {

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

    [cmdletbinding()]

    param
    (
        [switch]$Windows10,
        [switch]$iOS,
        [switch]$macOS
    )

    $graphApiVersion = 'Beta'

    try {
        $Count_Params = 0
        if ($iOS.IsPresent) { $Count_Params++ }
        if ($Windows10.IsPresent) { $Count_Params++ }
        if ($macOS.IsPresent) { $Count_Params++ }
        if ($Count_Params -gt 1) {
            Write-Error 'Multiple parameters set, specify a single parameter -iOS or -Windows10 or -macOS against the function'
            break
        }
        elseif ($Count_Params -eq 0) {
            Write-Error 'Parameter -iOS or -Windows10 or -macOS required against the function...'
            break
        }
        elseif ($Windows10) {
            $Resource = "deviceManagement/deviceConfigurations?`$filter=isof('microsoft.graph.windowsUpdateForBusinessConfiguration')&`$expand=groupAssignments"
        }
        elseif ($iOS) {
            $Resource = "deviceManagement/deviceConfigurations?`$filter=isof('microsoft.graph.iosUpdateConfiguration')&`$expand=groupAssignments"
        }
        elseif ($macOS) {
            $Resource = "deviceManagement/deviceConfigurations?`$filter=isof('microsoft.graph.macOSSoftwareUpdateConfiguration')&`$expand=groupAssignments"
        }

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Get
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Get-Device\Get-DeviceUpdatePolicy.ps1' 58
#Region '.\Public\Get-Enrolment\Get-EnrolmentADEProfile.ps1' 0
Function Get-EnrolmentADEProfile() {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthTokenMSAL
    Authenticates you with the Graph API interface using MSAL.PS module
    .NOTES
    NAME: Get-AuthTokenMSAL
    #>

    [cmdletbinding()]

    Param(
        [Parameter(Mandatory = $true)]
        [string]$Id
    )

    $graphApiVersion = 'Beta'
    $Resource = "deviceManagement/depOnboardingSettings/$Id/enrollmentProfiles"

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Get
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Get-Enrolment\Get-EnrolmentADEProfile.ps1' 35
#Region '.\Public\Get-Enrolment\Get-EnrolmentADEToken.ps1' 0
Function Get-EnrolmentADEToken() {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthTokenMSAL
    Authenticates you with the Graph API interface using MSAL.PS module
    .NOTES
    NAME: Get-AuthTokenMSAL
    #>

    [cmdletbinding()]
    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/depOnboardingSettings'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Get
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Get-Enrolment\Get-EnrolmentADEToken.ps1' 29
#Region '.\Public\Get-Enrolment\Get-EnrolmentAPProfile.ps1' 0
Function Get-EnrolmentAPProfile() {

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

    [cmdletbinding()]

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/windowsAutopilotDeploymentProfiles'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Get
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Get-Enrolment\Get-EnrolmentAPProfile.ps1' 30
#Region '.\Public\Get-Enrolment\Get-EnrolmentAPProfileAssignment.ps1' 0
Function Get-EnrolmentAPProfileAssignment() {

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

    [cmdletbinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Id
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/windowsAutopilotDeploymentProfiles'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$Id/Assignments/"
        Invoke-MEMRestMethod -Uri $uri -Method Get
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Get-Enrolment\Get-EnrolmentAPProfileAssignment.ps1' 36
#Region '.\Public\Get-Enrolment\Get-EnrolmentESP.ps1' 0
Function Get-EnrolmentESP() {

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

    [cmdletbinding()]

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/deviceEnrollmentConfigurations'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Get
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Get-Enrolment\Get-EnrolmentESP.ps1' 30
#Region '.\Public\Get-Enrolment\Get-EnrolmentESPAssignment.ps1' 0
Function Get-EnrolmentESPAssignment() {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthTokenMSAL
    Authenticates you with the Graph API interface using MSAL.PS module
    .NOTES
    NAME: Get-AuthTokenMSAL
    #>

    [cmdletbinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        [string]$id
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/deviceEnrollmentConfigurations'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$Id/Assignments/"
        Invoke-MEMRestMethod -Uri $uri -Method Get
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Get-Enrolment\Get-EnrolmentESPAssignment.ps1' 36
#Region '.\Public\Get-Enrolment\Get-EnrolmentRestriction.ps1' 0
Function Get-EnrolmentRestriction() {

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

    [cmdletbinding()]

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/deviceEnrollmentConfigurations'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Get
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Get-Enrolment\Get-EnrolmentRestriction.ps1' 30
#Region '.\Public\Get-Group\Get-MEMGroup.ps1' 0
Function Get-MEMGroup() {

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

    [cmdletbinding()]

    param
    (
        [parameter(Mandatory = $true)]
        [string]$Name
    )

    $graphApiVersion = 'beta'
    $Resource = 'groups'

    try {
        $authToken['ConsistencyLevel'] = 'eventual'
        $searchterm = 'search="displayName:' + $Name + '"'
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource`?$searchterm"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Get-Group\Get-MEMGroup.ps1' 38
#Region '.\Public\Get-Group\Get-MEMGroupMember.ps1' 0
Function Get-MEMGroupMember() {

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

    [cmdletbinding()]

    param
    (
        [parameter(Mandatory = $true)]
        [string]$Id
    )

    # Defining Variables
    $graphApiVersion = 'beta'
    $Resource = 'groups'

    try {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$id/members"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Get-Group\Get-MEMGroupMember.ps1' 38
#Region '.\Public\Invoke-App\Invoke-AppAppleVPPAppSync.ps1' 0
Function Invoke-AppAppleVPPAppSync() {

    <#
    .SYNOPSIS
    Sync Intune tenant to Apple DEP service
    .DESCRIPTION
    Intune automatically syncs with the Apple DEP service once every 24hrs. This function synchronises your Intune tenant with the Apple DEP service.
    .EXAMPLE
    Sync-AppleDEP
    .NOTES
    NAME: Sync-AppleDEP
    #>

    [cmdletbinding()]

    Param(
        [parameter(Mandatory = $true)]
        [string]$Id
    )

    $graphApiVersion = 'beta'
    $Resource = "deviceManagement/depOnboardingSettings/$id/syncWithAppleDeviceEnrollmentProgram"

    try {

        $Uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Post

    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Invoke-App\Invoke-AppAppleVPPAppSync.ps1' 36
#Region '.\Public\Invoke-App\Invoke-AppConfigPolicyDevice.ps1' 0
Function Invoke-AppConfigPolicyDevice {

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

        [ValidateSet('Corporate', 'Personal')]
        [string]$Enrolment,

        [ValidateSet('CE', 'NCSC', 'MS')]
        [string]$Engagement
    )

    $Files = Get-ChildItem -Path $Path -Filter *.json | Where-Object { ($_.name -like "*$OS*") -and ($_.name -like "*$Enrolment*") -and ($_.name -like "*_$($Engagement)_*") }

    foreach ($file in $files) {
        $ImportPath = $file.FullName
        $JSON_Data = Get-Content "$ImportPath"
        $JSON_Convert = $JSON_Data | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, version, isAssigned, roleScopeTagIds
        $DisplayName = $JSON_Convert.displayName
        if (Get-AppConfigPolicyDevice | Where-Object { ($_.displayName).equals($DisplayName) }) {
            Write-Information "App Config Profile '$DisplayName' already exists"
        }
        Else {
            If ($JSON_Convert.'@odata.type' -eq '#microsoft.graph.iosMobileAppConfiguration') {

                # Check if the client app is present
                $targetedMobileApp = Test-AppBundleId -bundleId $JSON_Convert.bundleId

                If ($targetedMobileApp) {
                    Write-Information "Targeted app $($JSON_Convert.bundleId) has already been added from the App Store"
                    Write-Information 'The App Configuration Policy will be created'

                    # Update the targetedMobileApps GUID if required
                    If (!($targetedMobileApp -eq $JSON_Convert.targetedMobileApps)) {
                        $JSON_Convert.targetedMobileApps.SetValue($targetedMobileApp, 0)
                    }

                    $JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 5
                    Write-Information "Adding App Configuration Policy '$DisplayName'"
                    New-AppConfigPolicyDevice -JSON $JSON_Output
                }
                Else {
                    Write-Error "Targeted app bundle id '$($JSON_Convert.bundleId)' has not been added from the App Store"
                    Write-Error "The App Configuration Policy can't be created"
                }
            }
            ElseIf ($JSON_Convert.'@odata.type' -eq '#microsoft.graph.androidManagedStoreAppConfiguration') {

                # Check if the client app is present
                $amendedpackageid = $($JSON_Convert.packageId) -replace 'app:', ''
                $targetedMobileApp = Test-AppPackageId -packageId $amendedpackageid

                If ($targetedMobileApp) {
                    Write-Information "Targeted app $($JSON_Convert.packageId) has already been added from Managed Google Play"
                    Write-Information 'The App Configuration Policy will be created'

                    # Update the targetedMobileApps GUID if required
                    If (!($targetedMobileApp -eq $JSON_Convert.targetedMobileApps)) {
                        $JSON_Convert.targetedMobileApps.SetValue($targetedMobileApp, 0)
                    }

                    $JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 5
                    Write-Information "Adding App Configuration Policy '$DisplayName'"
                    New-AppConfigPolicyDevice -JSON $JSON_Output
                }
                Else {
                    Write-Error "Targeted app package id '$($JSON_Convert.packageId)' has not been added from Managed Google Play"
                    Write-Error "The App Configuration Policy can't be created"
                }
            }
        }
    }
}
#EndRegion '.\Public\Invoke-App\Invoke-AppConfigPolicyDevice.ps1' 90
#Region '.\Public\Invoke-App\Invoke-AppGooglePlayAppSync.ps1' 0
Function Invoke-AppGooglePlayAppSync() {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthTokenMSAL
    Authenticates you with the Graph API interface using MSAL.PS module
    .NOTES
    NAME: Get-AuthTokenMSAL
    #>

    [cmdletbinding()]

    $graphApiVersion = 'Beta'
    $Resource = '/deviceManagement/androidManagedStoreAccountEnterpriseSettings/syncApps'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Post

    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Invoke-App\Invoke-AppGooglePlayAppSync.ps1' 31
#Region '.\Public\Invoke-App\Invoke-AppProtectionPolicy.ps1' 0
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
#EndRegion '.\Public\Invoke-App\Invoke-AppProtectionPolicy.ps1' 51
#Region '.\Public\Invoke-Device\Invoke-DeviceComplianceCustomPolicy.ps1' 0
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
        [Parameter(Mandatory = $true)]
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
            Write-Information "Compliance Policy '$DisplayName' already exists..."
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
            Write-Information "Adding Compliance Policy '$DisplayName'"
            New-DeviceCompliancePolicy -JSON $JSON_Output
            Write-Information "Sucessfully Added Compliance Policy '$DisplayName'"
        }
    }



}
#EndRegion '.\Public\Invoke-Device\Invoke-DeviceComplianceCustomPolicy.ps1' 71
#Region '.\Public\Invoke-Device\Invoke-DeviceCompliancePolicy.ps1' 0
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
#EndRegion '.\Public\Invoke-Device\Invoke-DeviceCompliancePolicy.ps1' 75
#Region '.\Public\Invoke-Device\Invoke-DeviceCompliancyScript.ps1' 0
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
        [Parameter(Mandatory = $true)]
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
            Write-Information "Device Script '$DisplayName' already exists"

        }
        else {

            Write-Information "Adding Compliance Script '$DisplayName'"
            New-DeviceComplianceScript -File $ImportPath
            Write-Information "Sucessfully Added Compliance Script '$DisplayName'"
        }
    }
}
#EndRegion '.\Public\Invoke-Device\Invoke-DeviceCompliancyScript.ps1' 47
#Region '.\Public\Invoke-Device\Invoke-DeviceConfigProfile.ps1' 0
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
        $JSON_Convert = $JSON_Data | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, version, supportsScopeTags
        $DisplayName = $JSON_Convert.displayName

        if (Get-DeviceConfigProfile | Where-Object { ($_.displayName).equals($DisplayName) }) {
            Write-Information "Configuration Profile '$DisplayName' already exists..."

        }
        else {

            $JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 5
            Write-Information "Adding Device Configuration Policy '$DisplayName'"
            New-DeviceConfigProfile -JSON $JSON_Output
            Write-Information "Sucessfully Added Configuration Profile '$DisplayName'"
        }
    }
}
#EndRegion '.\Public\Invoke-Device\Invoke-DeviceConfigProfile.ps1' 49
#Region '.\Public\Invoke-Device\Invoke-DeviceEndpointSecProfile.ps1' 0
Function Invoke-DeviceEndpointSecProfile {

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
        $JSON_Convert = $JSON_Data | ConvertFrom-Json
        $JSON_DN = $JSON_Convert.displayName
        $JSON_TemplateDisplayName = $JSON_Convert.TemplateDisplayName
        $JSON_TemplateId = $JSON_Convert.templateId

        Write-Information "Endpoint Security Policy '$JSON_DN' found"
        Write-Information "Template Display Name: $JSON_TemplateDisplayName"
        Write-Information "Template ID: $JSON_TemplateId"
        $Templates = Get-DeviceEndpointSecTemplate
        $ES_Template = $Templates | Where-Object { $_.id -eq $JSON_TemplateId }

        # If template is a baseline Edge, MDATP or Windows, use templateId specified
        if (($ES_Template.templateType -eq 'microsoftEdgeSecurityBaseline') -or ($ES_Template.templateType -eq 'securityBaseline') -or ($ES_Template.templateType -eq 'advancedThreatProtectionSecurityBaseline')) {
            $TemplateId = $JSON_Convert.templateId
        }

        # Else If not a baseline, check if template is deprecated
        elseif ($ES_Template) {
            # if template isn't deprecated use templateId
            if ($ES_Template.isDeprecated -eq $false) {
                $TemplateId = $JSON_Convert.templateId
            }
            # If template deprecated, look for lastest version
            elseif ($ES_Template.isDeprecated -eq $true) {
                $Template = $Templates | Where-Object { $_.displayName -eq "$JSON_TemplateDisplayName" }
                $Template = $Template | Where-Object { $_.isDeprecated -eq $false }
                $TemplateId = $Template.id
            }
        }
        # Else If Imported JSON template ID can't be found check if Template Display Name can be used
        elseif ($null -eq $ES_Template) {
            Write-Information "Didn't find Template with ID $JSON_TemplateId, checking if Template DisplayName '$JSON_TemplateDisplayName' can be used."
            $ES_Template = $Templates | Where-Object { $_.displayName -eq "$JSON_TemplateDisplayName" }

            If ($ES_Template) {
                if (($ES_Template.templateType -eq 'securityBaseline') -or ($ES_Template.templateType -eq 'advancedThreatProtectionSecurityBaseline')) {
                    Write-Error "TemplateID '$JSON_TemplateId' with template Name '$JSON_TemplateDisplayName' doesn't exist"
                    Write-Error 'Importing using the updated template could fail as settings specified may not be included in the latest template'
                    break
                }
                else {
                    $Template = $ES_Template | Where-Object { $_.isDeprecated -eq $false }
                    $TemplateId = $Template.id
                }
            }
            else {
                Write-Error "TemplateID '$JSON_TemplateId' with template Name '$JSON_TemplateDisplayName' doesn't exist..." -
                Write-Error 'Importing using the updated template could fail as settings specified may not be included in the latest template...'
            }
        }

        # Excluding certain properties from JSON that aren't required for import
        $JSON_Convert = $JSON_Convert | Select-Object -Property * -ExcludeProperty TemplateDisplayName, TemplateId, versionInfo
        $DisplayName = $JSON_Convert.displayName

        if (Get-DeviceEndpointSecProfile | Where-Object { ($_.displayName).equals($DisplayName) }) {
            Write-Information "Endpoint Security Profile '$DisplayName' already exists..."
            else {
                $JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 5
                Write-Information "Adding Endpoint Security Policy '$DisplayName'"
                New-DeviceEndpointSecProfile -TemplateId $TemplateId -JSON $JSON_Output
                Write-Information "Sucessfully Added Endpoint Security Profile '$DisplayName'"
            }
        }
    }
}
#EndRegion '.\Public\Invoke-Device\Invoke-DeviceEndpointSecProfile.ps1' 100
#Region '.\Public\Invoke-Device\Invoke-DeviceFilter.ps1' 0
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
        [Parameter(Mandatory = $true)]
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
            Write-Information "Intune Filter '$DisplayName' already exists..." -ForegroundColor Cyan

        }
        else {
            $JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 5
            Write-Information "Adding Intune Filter '$DisplayName'"
            New-DeviceFilter -JSON $JSON_Output
            Write-Information "Sucessfully Added Intune Filter '$DisplayName'"
        }
    }
}
#EndRegion '.\Public\Invoke-Device\Invoke-DeviceFilter.ps1' 46
#Region '.\Public\Invoke-Device\Invoke-DeviceNotificationMessage.ps1' 0
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
#EndRegion '.\Public\Invoke-Device\Invoke-DeviceNotificationMessage.ps1' 53
#Region '.\Public\Invoke-Device\Invoke-DeviceNotificationTemplate.ps1' 0
Function Invoke-DeviceNotificationTemplate {

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
        $DisplayName = $JSON_Convert.displayName

        if (Get-DeviceNotificationTemplate | Where-Object { ($_.displayName).equals($DisplayName) }) {
            Write-Information "Notification Template '$DisplayName' already exists"
        }
        else {

            $JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 5
            Write-Information "Adding Notification Template '$DisplayName'"
            New-DeviceNotificationTemplate -JSON $JSON_Output
            Write-Information "Sucessfully Added Notification Template '$DisplayName'"
        }
    }
}
#EndRegion '.\Public\Invoke-Device\Invoke-DeviceNotificationTemplate.ps1' 50
#Region '.\Public\Invoke-Device\Invoke-DeviceSettingsCatalog.ps1' 0
Function Invoke-DeviceSettingsCatalog {

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
        $JSON_Convert = $JSON_Data | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, version, supportsScopeTags
        $DisplayName = $JSON_Convert.name

        if (Get-DeviceSettingsCatalog | Where-Object { ($_.name).contains($DisplayName) }) {
            Write-Information "Settings Catalog Profile '$DisplayName' already exists"

        }
        else {

            $JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 20
            Write-Information "Adding Device Settings Catalog Policy '$DisplayName'"
            New-DeviceSettingCatalog -JSON $JSON_Output
            Write-Information "Sucessfully Added Settings Catalog Profile '$DisplayName'"
        }
    }
}
#EndRegion '.\Public\Invoke-Device\Invoke-DeviceSettingsCatalog.ps1' 51
#Region '.\Public\Invoke-Device\Invoke-DeviceUpdatePolicy.ps1' 0
Function Invoke-DeviceUpdatePolicy {

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
        $JSON_Convert = $JSON_Data | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, version, 'groupAssignments@odata.context', groupAssignments, supportsScopeTags
        $DisplayName = $JSON_Convert.displayName

        if ($DisplayName -like '*Windows*') {
            if (Get-DeviceUpdatePolicy -Windows10 | Where-Object { ($_.displayName).equals($DisplayName) }) {
                Write-Information "Windows Software Update Policy $DisplayName"

            }
            else {

                $JSON_Output = $JSON_Convert | ConvertTo-Json
                Write-Information "Adding Windows Software Update Policy $DisplayName"
                New-DeviceConfigProfile -JSON $JSON_Output
                Write-Information "Sucessfully Added Windows Software Update Profile $DisplayName"
            }
        }
        elseif ($DisplayName -like '*iOS*') {
            if (Get-DeviceUpdatePolicy -iOS | Where-Object { ($_.displayName).equals($DisplayName) }) {
                Write-Information "iOS Software Update Policy $DisplayName already exists"
            }
            else {

                $JSON_Output = $JSON_Convert | ConvertTo-Json
                Write-Information "Adding iOS Software Update Policy $DisplayName"
                New-DeviceConfigProfile -JSON $JSON_Output
                Write-Information "Sucessfully Added iOS Software Update Profile $DisplayName"
            }
            elseif ($DisplayName -like '*macOS*') {
                if (Get-DeviceUpdatePolicy -macOS | Where-Object { ($_.displayName).equals($DisplayName) }) {
                    Write-Information "macOS Software Update Policy $DisplayName already exists"

                }
                else {

                    $JSON_Output = $JSON_Convert | ConvertTo-Json
                    Write-Information "Adding macOS Software Update Policy $DisplayName"
                    New-DeviceConfigProfile -JSON $JSON_Output
                    Write-Information "Sucessfully Added macOS Software Update Profile $DisplayName"
                }
            }
        }

    }
}
#EndRegion '.\Public\Invoke-Device\Invoke-DeviceUpdatePolicy.ps1' 79
#Region '.\Public\Invoke-Enrolment\Invoke-EnrolmentRestriction.ps1' 0
Function Invoke-EnrolmentRestriction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Path,

        [ValidateSet('Windows', 'Android', 'iOS', 'macOS')]
        [string[]]$OS,

        [ValidateSet('Corporate', 'Personal', 'Both')]
        [string]$Enrolment,

        [ValidateSet('CE', 'NCSC', 'MS')]
        [string]$Engagement
    )

    $Files = Get-ChildItem -Path $Path -Filter *.json | Where-Object { ($_.name -like "*$OS*") -and ($_.name -like "*$Enrolment*") -and ($_.name -like "*_$($Engagement)_*") }

    foreach ($file in $files) {
        $ImportPath = $file.FullName
        $JSON_Data = Get-Content "$ImportPath"
        # Excluding entries that are not required - id,createdDateTime,lastModifiedDateTime,version
        $JSON_Convert = $JSON_Data | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, version, roleScopeTagIds
        $DisplayName = $JSON_Convert.displayName

        if (($OS -eq 'Android') -or ($DisplayName -like '*Android*')) {

            if (Get-EnrolmentRestriction | Where-Object { ($_.platformType -eq $JSON_Convert.platformType ) } ) {
                Write-Information "Enrolment Restriction $DisplayName already exists."
            }
            Else {
                $JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 5
                Write-Information "Adding Enrolment Restriction $DisplayName"
                New-EnrolmentRestriction -JSON $JSON_Output
                Write-Information "Sucessfully Added Enrolment Restriction $DisplayName"
            }

        }
        else {
            if (Get-EnrolmentRestriction | Where-Object { ($_.displayName).equals($DisplayName) }) {

                Write-Information "Enrolment Restriction $DisplayName already exists"
            }

            else {

                $JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 5
                Write-Information "Adding Enrolment Restriction '$DisplayName'" -ForegroundColor Cyan
                New-EnrolmentRestriction -JSON $JSON_Output
                Write-Information "Sucessfully Added Enrolment Restriction $DisplayName"
            }
        }
    }
}
#EndRegion '.\Public\Invoke-Enrolment\Invoke-EnrolmentRestriction.ps1' 54
#Region '.\Public\Invoke-Groups\Invoke-MEMGroup.ps1' 0
Function Invoke-MEMGroup {

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
                    Write-Information "Successfully created the group $Group.DisplayName"
                }
                else {
                    New-MEMGroup -Name $Group.DisplayName -Description $Group.Description -Security $true -Mail $false -type Dynamic -Rule $Group.MembershipRule
                    Write-Information "Successfully created the group $Group.DisplayName"
                }
                Else {
                    Write-Information "The group $Group.DisplayName already exists"
                }
            }
        }
    }
}
#EndRegion '.\Public\Invoke-Groups\Invoke-MEMGroup.ps1' 52
#Region '.\Public\New-App\New-AppConfigPolicyApp.ps1' 0
Function New-AppConfigPolicyApp() {

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

    [cmdletbinding(SupportsShouldProcess, ConfirmImpact='Medium')]
    param
    (
        [parameter(Mandatory = $true)]
        $JSON
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceAppManagement/targetedManagedAppConfigurations'

    try {
        Test-MEMJSON -Json $JSON
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
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
#EndRegion '.\Public\New-App\New-AppConfigPolicyApp.ps1' 38
#Region '.\Public\New-App\New-AppConfigPolicyDevice.ps1' 0
Function New-AppConfigPolicyDevice() {

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

    [cmdletbinding(SupportsShouldProcess, ConfirmImpact='Medium')]
    param
    (
        [parameter(Mandatory = $true)]
        $JSON
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceAppManagement/mobileAppConfigurations'

    try {
        Test-MEMJSON -Json $JSON
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
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
#EndRegion '.\Public\New-App\New-AppConfigPolicyDevice.ps1' 38
#Region '.\Public\New-App\New-AppManagedGooglePlayApp.ps1' 0
Function New-AppManagedGooglePlayApp() {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthTokenMSAL
    Authenticates you with the Graph API interface using MSAL.PS module
    .NOTES
    NAME: Get-AuthTokenMSAL
    #>

    [cmdletbinding(SupportsShouldProcess, ConfirmImpact='Medium')]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Id
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/androidManagedStoreAccountEnterpriseSettings/approveApps'

    try {
        $Id = 'app:' + $Id
        $Packages = New-Object -TypeName psobject
        $Packages | Add-Member -MemberType NoteProperty -Name 'approveAllPermissions' -Value 'true'
        $Packages | Add-Member -MemberType NoteProperty -Name 'packageIds' -Value @($Id)
        $JSON = $Packages | ConvertTo-Json -Depth 3

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
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
#EndRegion '.\Public\New-App\New-AppManagedGooglePlayApp.ps1' 43
#Region '.\Public\New-App\New-AppProtectionPolicy.ps1' 0
Function New-AppProtectionPolicy() {

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

    [cmdletbinding(SupportsShouldProcess, ConfirmImpact='Medium')]
    param
    (
        [parameter(Mandatory = $true)]
        $JSON
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceAppManagement/managedAppPolicies'

    try {
        Test-MEMJSON -Json $JSON
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
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
#EndRegion '.\Public\New-App\New-AppProtectionPolicy.ps1' 38
#Region '.\Public\New-Device\New-DeviceCompliancePolicy.ps1' 0
Function New-DeviceCompliancePolicy() {

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

    [cmdletbinding(SupportsShouldProcess, ConfirmImpact='Medium')]
    param
    (
        [parameter(Mandatory = $true)]
        $JSON
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/deviceCompliancePolicies'

    try {
        Test-MEMJSON -Json $JSON
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
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
#EndRegion '.\Public\New-Device\New-DeviceCompliancePolicy.ps1' 38
#Region '.\Public\New-Device\New-DeviceComplianceScript.ps1' 0
Function New-DeviceComplianceScript() {

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
    Param (
        # Path or URL to Compliance Script to add to Intune
        [Parameter(Mandatory = $true)]
        [string]$File,

        [string]$Publisher

    )

    if (!(Test-Path $File)) {
        Write-Error "$File could not be located."
        break
    }
    $FileName = Get-Item $File | Select-Object -ExpandProperty Name
    $DisplayName = $FileName.Split('.')[0]
    $B64File = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes("$File"));

    $JSON = @"
{
    "id": "",
    "displayName": "$DisplayName",
    "description": "",
    "publisher": "$Publisher",
    "detectionScriptContent": "$B64File",
    "runAsAccount": "system",
    "enforceSignatureCheck": false,
    "runAs32Bit": true
}
"@

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/deviceComplianceScripts'

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
#EndRegion '.\Public\New-Device\New-DeviceComplianceScript.ps1' 62
#Region '.\Public\New-Device\New-DeviceConfigProfile.ps1' 0
Function New-DeviceConfigProfile() {

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

    [cmdletbinding(SupportsShouldProcess, ConfirmImpact='Medium')]
    param
    (
        [parameter(Mandatory = $true)]
        $JSON
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/deviceConfigurations'

    try {
        Test-MEMJSON -Json $JSON
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
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
#EndRegion '.\Public\New-Device\New-DeviceConfigProfile.ps1' 38
#Region '.\Public\New-Device\New-DeviceEndpointSecProfile.ps1' 0
Function New-DeviceEndpointSecProfile() {

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

    [cmdletbinding(SupportsShouldProcess, ConfirmImpact='Medium')]
    param
    (
        [parameter(Mandatory = $true)]
        [string]$Id,
        [parameter(Mandatory = $true)]
        $JSON
    )

    $graphApiVersion = 'Beta'
    $Resource = "deviceManagement/templates/$Id/createInstance"

    try {
        Test-MEMJSON -Json $JSON
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
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
#EndRegion '.\Public\New-Device\New-DeviceEndpointSecProfile.ps1' 40
#Region '.\Public\New-Device\New-DeviceFilter.ps1' 0
Function New-DeviceFilter() {

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

    [cmdletbinding(SupportsShouldProcess, ConfirmImpact='Medium')]
    param
    (
        [parameter(Mandatory = $true)]
        $JSON
    )

    $graphApiVersion = 'beta'
    $Resource = 'deviceManagement/assignmentFilters'

    try {
        Test-MEMJSON -Json $JSON
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
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
#EndRegion '.\Public\New-Device\New-DeviceFilter.ps1' 38
#Region '.\Public\New-Device\New-DeviceNotificationMessage.ps1' 0
Function New-DeviceNotificationMessage() {

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

    [cmdletbinding(SupportsShouldProcess, ConfirmImpact='Medium')]
    param
    (
        [parameter(Mandatory = $true)]
        [string]$Id,
        [parameter(Mandatory = $true)]
        $JSON
    )

    $graphApiVersion = 'Beta'
    $Resource = "deviceManagement/notificationMessageTemplates/$Id/localizedNotificationMessages"

    try {
        Test-MEMJSON -Json $JSON
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
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
#EndRegion '.\Public\New-Device\New-DeviceNotificationMessage.ps1' 40
#Region '.\Public\New-Device\New-DeviceNotificationTemplate.ps1' 0
Function New-DeviceNotificationTemplate() {

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

    [cmdletbinding(SupportsShouldProcess, ConfirmImpact='Medium')]
    param
    (
        [parameter(Mandatory = $true)]
        $JSON
    )

    $graphApiVersion = 'v1.0'
    $Resource = 'deviceManagement/notificationMessageTemplates'

    try {
        Test-MEMJSON -Json $JSON
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
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
#EndRegion '.\Public\New-Device\New-DeviceNotificationTemplate.ps1' 38
#Region '.\Public\New-Device\New-DeviceScript.ps1' 0
Function New-DeviceManagementScript() {

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

    [cmdletbinding(SupportsShouldProcess, ConfirmImpact='Medium')]
    Param (
        # Path or URL to Powershell-script to add to Intune
        [Parameter(Mandatory = $true)]
        [string]$File,

        # PowerShell description in Intune
        [Parameter(Mandatory = $false)]
        [string]$Description
    )

    if (!(Test-Path $File)) {
        Write-Output "$File could not be located."
        break
    }
    $FileName = Get-Item $File | Select-Object -ExpandProperty Name
    $DisplayName = $FileName.Split('.')[0]
    $B64File = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes("$File"));

    $JSON = @"
{
    "@odata.type": "#microsoft.graph.deviceManagementScript",
    "displayName": "$DisplayName",
    "description": "$Description",
    "runSchedule": {
    "@odata.type": "microsoft.graph.runSchedule"
},
    "scriptContent": "$B64File",
    "runAsAccount": "system",
    "enforceSignatureCheck": "false",
    "fileName": "$FileName"
}
"@

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/deviceManagementScripts'

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
#EndRegion '.\Public\New-Device\New-DeviceScript.ps1' 65
#Region '.\Public\New-Device\New-DeviceSettingCatalog.ps1' 0
Function New-DeviceSettingCatalog() {

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

    [cmdletbinding(SupportsShouldProcess, ConfirmImpact='Medium')]
    param
    (
        [parameter(Mandatory = $true)]
        $JSON
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/configurationPolicies'

    try {
        Test-MEMJSON -Json $JSON
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
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
#EndRegion '.\Public\New-Device\New-DeviceSettingCatalog.ps1' 38
#Region '.\Public\New-Enrolment\New-EnrolmentAPProfile.ps1' 0
Function New-EnrolmentAPProfile() {

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

    [cmdletbinding(SupportsShouldProcess, ConfirmImpact='Medium')]
    param
    (
        [parameter(Mandatory = $true)]
        $JSON
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/windowsAutopilotDeploymentProfiles'

    try {
        Test-MEMJSON -Json $JSON
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
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
#EndRegion '.\Public\New-Enrolment\New-EnrolmentAPProfile.ps1' 38
#Region '.\Public\New-Enrolment\New-EnrolmentESP.ps1' 0
Function New-EnrolmentESP() {

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

    [cmdletbinding(SupportsShouldProcess, ConfirmImpact='Medium')]
    param
    (
        [parameter(Mandatory = $true)]
        $JSON
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/deviceEnrollmentConfigurations'

    try {
        Test-MEMJSON -Json $JSON
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
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
#EndRegion '.\Public\New-Enrolment\New-EnrolmentESP.ps1' 38
#Region '.\Public\New-Enrolment\New-EnrolmentRestriction.ps1' 0
Function New-EnrolmentRestriction() {

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
        [parameter(Mandatory = $true)]
        $JSON
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/deviceEnrollmentConfigurations'

    try {
        Test-Json -Json $JSON
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
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
#EndRegion '.\Public\New-Enrolment\New-EnrolmentRestriction.ps1' 38
#Region '.\Public\New-Group\New-MEMGroup.ps1' 0
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
            Write-Error 'No Dynamic Membership rule found'
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
#EndRegion '.\Public\New-Group\New-MEMGroup.ps1' 82
#Region '.\Public\Remove-App\Remove-AppConfigPolicyApp.ps1' 0
Function Remove-AppConfigPolicyApp() {

    <#
    .SYNOPSIS
    This function is used to remove Managed App policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and removes managed app policies
    .EXAMPLE
    Remove-AppConfigPolicyApp -id $id
    Removes a managed app policy configured in Intune
    .NOTES
    NAME: Remove-AppConfigPolicyApp
    #>

    [cmdletbinding(SupportsShouldProcess, ConfirmImpact='Medium')]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Id
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceAppManagement/targetedManagedAppConfigurations'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$Id"
        if ($PSCmdlet.ShouldProcess('ShouldProcess?')) {
            Invoke-MEMRestMethod -Uri $uri -Method Delete
        }
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Remove-App\Remove-AppConfigPolicyApp.ps1' 37
#Region '.\Public\Remove-App\Remove-AppConfigPolicyDevice.ps1' 0
Function Remove-AppConfigPolicyDevice() {

    <#
    .SYNOPSIS
    This function is used to remove Managed App policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and removes managed app policies
    .EXAMPLE
    Remove-AppConfigPolicyDevice -id $id
    Removes a managed app policy configured in Intune
    .NOTES
    NAME: Remove-AppConfigPolicyDevice
    #>

    [cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Id
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceAppManagement/mobileAppConfigurations'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$Id"
        if ($PSCmdlet.ShouldProcess('ShouldProcess?')) {
            Invoke-MEMRestMethod -Uri $uri -Method Delete
        }
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Remove-App\Remove-AppConfigPolicyDevice.ps1' 37
#Region '.\Public\Remove-App\Remove-AppMobileAppAssignment.ps1' 0
Function Remove-AppMobileAppAssignment() {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthTokenMSAL
    Authenticates you with the Graph API interface using MSAL.PS module
    .NOTES
    NAME: Get-AuthTokenMSAL
    #>

    [cmdletbinding(SupportsShouldProcess, ConfirmImpact='Medium')]
    param
    (
        [parameter(Mandatory = $true)]
        [string]$Id,
        [parameter(Mandatory = $true)]
        [string]$AssignmentId
    )

    $graphApiVersion = 'Beta'
    $Resource = "deviceAppManagement/mobileApps/$Id/assignments/$AssignmentId"

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        if ($PSCmdlet.ShouldProcess('ShouldProcess?')) {
            Invoke-MEMRestMethod -Uri $uri -Method Delete
        }
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Remove-App\Remove-AppMobileAppAssignment.ps1' 39
#Region '.\Public\Remove-App\Remove-AppMobileAppCategory.ps1' 0
Function Remove-AppMobileAppCategory() {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthTokenMSAL
    Authenticates you with the Graph API interface using MSAL.PS module
    .NOTES
    NAME: Get-AuthTokenMSAL
    #>

    [cmdletbinding(SupportsShouldProcess, ConfirmImpact='Medium')]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Id,
        [Parameter(Mandatory = $true)]
        [string]$CategoryId
    )

    $graphApiVersion = 'Beta'
    $Resource = "deviceAppManagement/mobileApps/$Id/categories/$CategoryId/`$ref"

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        if ($PSCmdlet.ShouldProcess('ShouldProcess?')) {
            Invoke-MEMRestMethod -Uri $uri -Method Delete
        }
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Remove-App\Remove-AppMobileAppCategory.ps1' 39
#Region '.\Public\Remove-App\Remove-AppProtectionPolicy.ps1' 0
Function Remove-AppProtectionPolicy() {

    <#
    .SYNOPSIS
    This function is used to remove Managed App policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and removes managed app policies
    .EXAMPLE
    Remove-ManagedAppPolicy -id $id
    Removes a managed app policy configured in Intune
    .NOTES
    NAME: Remove-ManagedAppPolicy
    #>

    [cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$id
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceAppManagement/managedAppPolicies'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id"
        if ($PSCmdlet.ShouldProcess('ShouldProcess?')) {
            Invoke-MEMRestMethod -Uri $uri -Method Delete
        }
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Remove-App\Remove-AppProtectionPolicy.ps1' 37
#Region '.\Public\Remove-Device\Remove-DeviceCompliancePolicy.ps1' 0
Function Remove-DeviceCompliancePolicy() {

    <#
        .SYNOPSIS
        This function is used to delete a device configuration policy from the Graph API REST interface
        .DESCRIPTION
        The function connects to the Graph API Interface and deletes a device compliance policy
        .EXAMPLE
        Remove-DeviceCompliancePolicy -id $id
        Returns any device configuration policies configured in Intune
        .NOTES
        NAME: Remove-DeviceCompliancePolicy
        #>

    [cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$id
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/deviceCompliancePolicies'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id"
        if ($PSCmdlet.ShouldProcess('ShouldProcess?')) {
            Invoke-MEMRestMethod -Uri $uri -Method Delete
        }
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Remove-Device\Remove-DeviceCompliancePolicy.ps1' 37
#Region '.\Public\Remove-Device\Remove-DeviceConfigProfile.ps1' 0
Function Remove-DeviceConfigProfile() {

    <#
    .SYNOPSIS
    This function is used to remove a device configuration policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and removes a device configuration policies
    .EXAMPLE
    Remove-DeviceConfigProfile -id $id
    Removes a device configuration policies configured in Intune
    .NOTES
    NAME: Remove-DeviceConfigProfile
    #>

    [cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$id
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/deviceConfigurations'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id"
        if ($PSCmdlet.ShouldProcess('ShouldProcess?')) {
            Invoke-MEMRestMethod -Uri $uri -Method Delete
        }
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Remove-Device\Remove-DeviceConfigProfile.ps1' 37
#Region '.\Public\Remove-Device\Remove-DeviceFilter.ps1' 0
Function Remove-DeviceFilter() {

    <#
    .SYNOPSIS
    This function is used to remove a device configuration policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and removes a device configuration policies
    .EXAMPLE
    Remove-DeviceFilter -id $id
    Removes a device configuration policies configured in Intune
    .NOTES
    NAME: Remove-DeviceFilter
    #>

    [cmdletbinding(SupportsShouldProcess, ConfirmImpact='Medium')]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$id
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/assignmentFilters'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id"
        if ($PSCmdlet.ShouldProcess("ShouldProcess?")) {
            Invoke-MEMRestMethod -Uri $uri -Method Delete
        }
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Remove-Device\Remove-DeviceFilter.ps1' 37
#Region '.\Public\Remove-Device\Remove-DeviceScript.ps1' 0
Function Remove-DeviceManagement() {

    <#
    .SYNOPSIS
    This function is used to remove a device configuration policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and removes a device configuration policies
    .EXAMPLE
    Remove-DeviceManagementScript -id $id
    Removes a device configuration policies configured in Intune
    .NOTES
    NAME: Remove-DeviceManagementScript
    #>

    [cmdletbinding(SupportsShouldProcess, ConfirmImpact='Medium')]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$id
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/deviceManagementScripts'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id"
        if ($PSCmdlet.ShouldProcess("ShouldProcess?")) {
            Invoke-MEMRestMethod -Uri $uri -Method Delete
        }
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Remove-Device\Remove-DeviceScript.ps1' 37
#Region '.\Public\Remove-Device\Remove-DeviceSettingsCatalog.ps1' 0
Function Remove-DeviceSettingsCatalog() {

    <#
    .SYNOPSIS
    This function is used to remove a device configuration policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and removes a device configuration policies
    .EXAMPLE
    Remove-DeviceSettingsCatalogProfile -id $id
    Removes a device configuration policies configured in Intune
    .NOTES
    NAME: Remove-DeviceSettingsCatalogProfile
    #>

    [cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$id
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/configurationPolicies'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id"
        if ($PSCmdlet.ShouldProcess('ShouldProcess?')) {
            Invoke-MEMRestMethod -Uri $uri -Method Delete
        }
    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Remove-Device\Remove-DeviceSettingsCatalog.ps1' 37
#Region '.\Public\Test-Auth\Test-AuthToken.ps1' 0
Function Test-AuthToken() {

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

    [cmdletbinding()]
    param (
    )

    if ($global:authToken) {

        # Setting DateTime to Universal time to work in all timezones
        $DateTime = (Get-Date).ToUniversalTime()

        # If the authToken exists checking when it expires
        $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes

        if ($TokenExpires -le 0) {

            Write-Output "Authentication Token expired $TokenExpires minutes ago"
            # Defining User Principal Name if not present
            if ($null -eq $global:User -or $global:User -eq '') {
                $global:User = Read-Host -Prompt 'Please specify your user principal name for Azure Authentication'
            }
            $global:authToken = Get-AuthTokenMSAL -User $global:User
        }
    }
    # Authentication doesn't exist, calling Get-AuthToken function
    else {
        if ($null -eq $global:User -or $global:User -eq '') {
            $global:User = Read-Host -Prompt 'Please specify your user principal name for Azure Authentication'
        }
        # Getting the authorization token
        $global:authToken = Get-AuthTokenMSAL -User $global:User
    }

    $global:authToken['ConsistencyLevel'] = 'eventual'

}
#EndRegion '.\Public\Test-Auth\Test-AuthToken.ps1' 48
#Region '.\Public\Update-Device\Update-DeviceAPDevice.ps1' 0
Function Update-DeviceAP() {

    <#
    .SYNOPSIS
    This function is used to set autopilot devices properties via the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and sets autopilot device properties
    .EXAMPLE
    Set-AutopilotDevice
    Returns any autopilot devices
    .NOTES
    NAME: Set-AutopilotDevice
    #>

    [cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Id,

        [Parameter(Mandatory = $true)]
        [string]$GroupTag
    )

    $graphApiVersion = 'Beta'
    $Resource = "deviceManagement/windowsAutopilotDeviceIdentities/$Id/updateDeviceProperties"

    try {
        $Autopilot = New-Object -TypeName psobject
        $Autopilot | Add-Member -MemberType NoteProperty -Name 'groupTag' -Value $GroupTag
        $JSON = $Autopilot | ConvertTo-Json -Depth 3
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
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
#EndRegion '.\Public\Update-Device\Update-DeviceAPDevice.ps1' 42
#Region '.\Public\Update-Device\Update-DeviceCompliancePolicy.ps1' 0
Function Update-DeviceCompliancePolicy() {

    <#
    .SYNOPSIS
    This function is used to update device compliance policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and updates device compliance policies
    .EXAMPLE
    Update-DeviceCompliancePolicy -id -JSON
    Updates a device compliance policies configured in Intune
    .NOTES
    NAME: Update-DeviceCompliancePolicy
    #>

    [cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Id,

        [Parameter(Mandatory = $true)]
        $JSON
    )

    $graphApiVersion = 'Beta'
    $Resource = "deviceManagement/deviceCompliancePolicies/$id"

    try {
        Test-Json -Json $JSON
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        if ($PSCmdlet.ShouldProcess('ShouldProcess?')) {
            Invoke-MEMRestMethod -Uri $uri -Method Patch -Body $JSON
        }

    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Update-Device\Update-DeviceCompliancePolicy.ps1' 42
#Region '.\Public\Update-Device\Update-DeviceManagedDeviceName.ps1' 0
Function Update-DeviceManagedDeviceName() {

    <#
    .SYNOPSIS
    This function is used to update device compliance policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and updates device compliance policies
    .EXAMPLE
    Update-DeviceCompliancePolicy -id -JSON
    Updates a device compliance policies configured in Intune
    .NOTES
    NAME: Update-DeviceCompliancePolicy
    #>

    [cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Id,

        [Parameter(Mandatory = $true)]
        [string]$OS,

        [Parameter(Mandatory = $true)]
        [string]$DeviceName
    )

    $graphApiVersion = 'Beta'
    $Resource = "deviceManagement/managedDevices('$Id')/setDeviceName"

    If ($OS -eq 'Windows') {
        $Length = '15'
    }
    Elseif ($OS -eq 'iOS') {
        $Length = '255'
    }
    Elseif ($OS -eq 'Android') {
        $Length = '50'
    }
    Elseif ($OS -eq 'macOS') {
        $Length = '250'
    }

    $DeviceName = $DeviceName.Replace(' ', '')
    if ($DeviceName.Length -ge $Length) {
        $DeviceName = $DeviceName.substring(0, $Length)
        Write-Information "Device name shortened to $DeviceName"
    }

    $Output = New-Object -TypeName psobject
    $Output | Add-Member -MemberType NoteProperty -Name 'deviceName' -Value $DeviceName
    $JSON = $Output | ConvertTo-Json -Depth 3

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
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
#EndRegion '.\Public\Update-Device\Update-DeviceManagedDeviceName.ps1' 65
#Region '.\Public\Update-Device\Update-DeviceOwnership.ps1' 0
Function Update-DeviceOwnership() {

    <#
    .SYNOPSIS
    This function is used to update device compliance policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and updates device compliance policies
    .EXAMPLE
    Update-DeviceCompliancePolicy -id -JSON
    Updates a device compliance policies configured in Intune
    .NOTES
    NAME: Update-DeviceCompliancePolicy
    #>

    [cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Id,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Company', 'Personal')]
        [string]$Ownership
    )
    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/managedDevices'

    try {
        $Output = New-Object -TypeName psobject
        $Output | Add-Member -MemberType NoteProperty -Name 'ownerType' -Value $Ownership
        $JSON = $Output | ConvertTo-Json -Depth 3
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$Id"
        if ($PSCmdlet.ShouldProcess('ShouldProcess?')) {
            Invoke-MEMRestMethod -Uri $uri -Method Patch -Body $JSON
        }

    }
    catch {
        $exs = $Error
        $ex = $exs[0]
        Write-Error "`n$ex"
        break
    }
}
#EndRegion '.\Public\Update-Device\Update-DeviceOwnership.ps1' 44
