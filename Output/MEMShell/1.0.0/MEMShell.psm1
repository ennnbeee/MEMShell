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
        $User
    )

    $userUpn = New-Object 'System.Net.Mail.MailAddress' -ArgumentList $User
    if ($userUpn.Host -like '*onmicrosoft.com*') {
        $tenant = Read-Host -Prompt 'Please specify your Tenant name i.e. company.com'
        Write-Host
    }
    else {
        $tenant = $userUpn.Host
    }

    Write-Host 'Checking for MSAL.PS module...'
    $MSALModule = Get-Module -Name 'MSAL.PS' -ListAvailable
    if ($null -eq $MSALModule) {
        Write-Host
        Write-Host 'MSAL.PS Powershell module not installed...' -f Red
        Write-Host "Install by running 'Install-Module MSAL.PS -Scope CurrentUser' from an elevated PowerShell prompt" -f Yellow
        Write-Host "Script can't continue..." -f Red
        Write-Host
        exit
    }
    if ($MSALModule.count -gt 1) {
        $Latest_Version = ($MSALModule | Select-Object version | Sort-Object)[-1]
        $MSALModule = $MSALModule | Where-Object { $_.version -eq $Latest_Version.version }
        # Checking if there are multiple versions of the same module found
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
        # If the accesstoken is valid then create the authentication header
        if ($authResult.AccessToken) {
            # Creating header for Authorization token
            $authHeader = @{
                'Content-Type'  = 'application/json'
                'Authorization' = 'Bearer ' + $authResult.AccessToken
                'ExpiresOn'     = $authResult.ExpiresOn
            }
            return $authHeader
        }
        else {
            Write-Host
            Write-Host 'Authorization Access Token is null, please re-run authentication...' -ForegroundColor Red
            Write-Host
            break
        }
    }
    catch {
        Write-Host $_.Exception.Message -f Red
        Write-Host $_.Exception.ItemName -f Red
        Write-Host
        break
    }
}
#EndRegion '.\Private\Get-AuthTokenMSAL.ps1' 85
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
        $Method,
        $Body,
        $ContentType = 'application/json'
    )

    if ($global:authToken) {

        # Setting DateTime to Universal time to work in all timezones
        $DateTime = (Get-Date).ToUniversalTime()

        # If the authToken exists checking when it expires
        $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes

        if ($TokenExpires -le 0) {

            Write-Host 'Authentication Token expired' $TokenExpires 'minutes ago' -ForegroundColor Yellow
            Write-Host
            # Defining User Principal Name if not present
            if ($null -eq $User -or $User -eq '') {
                $User = Read-Host -Prompt 'Please specify your user principal name for Azure Authentication'
                Write-Host
            }
            $global:authToken = Get-AuthTokenMSAL -User $User
        }
    }
    # Authentication doesn't exist, calling Get-AuthToken function
    else {
        if ($null -eq $User -or $User -eq '') {
            $User = Read-Host -Prompt 'Please specify your user principal name for Azure Authentication'
            Write-Host
        }
        # Getting the authorization token
        $global:authToken = Get-AuthTokenMSAL -User $User
    }

    $authToken['ConsistencyLevel'] = 'eventual'
    $Headers = $global:authToken

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
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
    }
}
#EndRegion '.\Private\Invoke-MEMRestMethod.ps1' 109
#Region '.\Private\Test-AppBundleId.ps1' 0
Function Test-AppBundleId() {
    param (
        [Parameter(Mandatory = $true)]
        $bundleId
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
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
    
    $app = $mobileApps.value | Where-Object { $_.bundleId -eq $bundleId }
    If ($app) {
        return $app.id
    }
    Else {
        return $false
    }
}
#EndRegion '.\Private\Test-AppBundleId.ps1' 31
#Region '.\Private\Test-AppPackageId.ps1' 0
Function Test-AppPackageId() {

    param (
        [Parameter(Mandatory = $true)]
        $packageId
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
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
    
    $app = $mobileApps.value | Where-Object { $_.packageId -eq $packageId }
        
    If ($app) {
        return $app.id
    }
    Else {
        return $false
    }
}
#EndRegion '.\Private\Test-AppPackageId.ps1' 33
#Region '.\Private\Test-JSON.ps1' 0
Function Test-JSON() {

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
        Write-Host "Provided JSON isn't in valid JSON format" -f Red
        break
    }
}
#EndRegion '.\Private\Test-JSON.ps1' 22
#Region '.\Public\Add-App\Add-AppAppAssignment.ps1' 0
Function Add-ApplicationAssignment() {

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
        $Id,
        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        $TargetGroupId,
        [parameter(Mandatory = $true)]
        [ValidateSet('Available', 'Required')]
        [ValidateNotNullOrEmpty()]
        $InstallIntent,
        $FilterID,
        [ValidateSet('Include', 'Exclude')]
        $FilterMode,
        [parameter(Mandatory = $false)]
        [ValidateSet('Users', 'Devices')]
        [ValidateNotNullOrEmpty()]
        $All,
        [parameter(Mandatory = $true)]
        [ValidateSet('Replace', 'Add')]
        $Action
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
                        Write-Host 'The App is already assigned to the Group' -ForegroundColor Yellow
                    }
                    ElseIf (($All -eq 'Devices') -and ($Assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget')) {
                        Write-Host 'The App is already assigned to the All Devices Group' -ForegroundColor Yellow
                    }
                    ElseIf (($All -eq 'Users') -and ($Assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget')) {
                        Write-Host 'The App is already assigned to the All Users Group' -ForegroundColor Yellow
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

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType 'application/json'
    }
    catch {
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Add-App\Add-AppAppAssignment.ps1' 134
#Region '.\Public\Add-App\Add-AppAppCategory.ps1' 0
Function Add-AppAppCategory() {

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
        $Id,
        [Parameter(Mandatory = $true)]
        $CategoryId
    )

    $graphApiVersion = 'Beta'
    $Resource = "deviceAppManagement/mobileApps/$Id/categories/`$ref"

    try {
        $value = "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/mobileAppCategories/$CategoryId"
        $Output = New-Object -TypeName psobject
        $Output | Add-Member -MemberType NoteProperty -Name '@odata.id' -Value $value
        $JSON = $Output | ConvertTo-Json -Depth 3
        Test-Json -Json $JSON
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType 'application/json'
    }
    catch {
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Add-App\Add-AppAppCategory.ps1' 46
#Region '.\Public\Add-App\Add-AppCategory.ps1' 0
Function Add-AppCategory() {

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
        $Name
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceAppManagement/mobileAppCategories'

    try {
        $Output = New-Object -TypeName psobject
        $Output | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.mobileAppCategory'
        $Output | Add-Member -MemberType NoteProperty 'displayName' -Value $Name
        $JSON = $Output | ConvertTo-Json -Depth 3
        Test-Json -Json $JSON
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType 'application/json'
    }
    catch {
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Add-App\Add-AppCategory.ps1' 44
#Region '.\Public\Add-App\Add-AppConfigPolicyDeviceAssignment.ps1' 0
Function Add-AppConfigPolicyDeviceAssignment() {

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
        $Id,
        $TargetGroupId,
        [parameter(Mandatory = $true)]
        [ValidateSet('Include', 'Exclude')]
        $AssignmentType,
        $FilterID,
        [ValidateSet('Include', 'Exclude')]
        $FilterMode,
        [ValidateSet('Users', 'Devices')]
        $All
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

        # POST to Graph Service
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType 'application/json'
    }
    catch {
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Add-App\Add-AppConfigPolicyDeviceAssignment.ps1' 84
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
        $Id,
        $TargetGroupId,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Android', 'iOS')]
        [string]$OS,
        [ValidateSet('Include', 'Exclude')]
        [ValidateNotNullOrEmpty()]
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

        if ($OS -eq 'Android') {
            $uri = "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/androidManagedAppProtections('$ID')/assign"
        }

        elseif ($OS -eq 'iOS') {
            $uri = "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/iosManagedAppProtections('$ID')/assign"
        }

        Invoke-RestMethod -Uri $uri -Method Post -ContentType 'application/json' -Body $JSON -Headers $authToken
    }
    catch {
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Add-App\Add-AppProtectionPolicyAssignment.ps1' 79
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
        $Id,
        $TargetGroupId,
        [parameter(Mandatory = $true)]
        [ValidateSet('Include', 'Exclude')]
        $AssignmentType,
        $FilterID,
        $FilterMode,
        [ValidateSet('Users', 'Devices')]
        $All
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
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Add-Device\Add-DeviceCompliancePolicyAssignment.ps1' 85
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
        $Id,
        $TargetGroupId,
        [parameter(Mandatory = $true)]
        [ValidateSet('Include', 'Exclude')]
        $AssignmentType,
        $FilterID,
        [ValidateSet('Include', 'Exclude')]
        $FilterMode,
        [ValidateSet('Users', 'Devices')]
        $All
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
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Add-Device\Add-DeviceConfigProfileAssignment.ps1' 85
#Region '.\Public\Add-Device\Add-DeviceEndpointSecProfileAssignment.ps1' 0
Function Add-DeviceEndpointSecProfileAssignment() {

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
        $Id,
        $TargetGroupId,
        [parameter(Mandatory = $true)]
        [ValidateSet('Include', 'Exclude')]
        $AssignmentType,
        $FilterID,
        $FilterMode,
        [ValidateSet('Users', 'Devices')]
        $All
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
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Add-Device\Add-DeviceEndpointSecProfileAssignment.ps1' 83
#Region '.\Public\Add-Device\Add-DeviceSettingsCatalogProfileAssignment.ps1' 0
Function Add-DeviceSettingsCatalogProfileAssignment() {

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
        $Id,
        $TargetGroupId,
        [parameter(Mandatory = $true)]
        [ValidateSet('Include', 'Exclude')]
        $AssignmentType,
        $FilterID,
        $FilterMode,
        [ValidateSet('Users', 'Devices')]
        $All
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
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Add-Device\Add-DeviceSettingsCatalogProfileAssignment.ps1' 83
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
        $Id,
        [Parameter(Mandatory = $true)]
        $ProfileID,
        [Parameter(Mandatory = $true)]
        $DeviceSerials
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
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Add-Enrolment\Add-EnrolmentADEProfileAssignment.ps1' 46
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
        $Id,
        [parameter(Mandatory = $true)]
        $TargetGroupId,
        [parameter(Mandatory = $true)]
        [ValidateSet('Include', 'Exclude')]
        $AssignmentType
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
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Add-Enrolment\Add-EnrolmentAutopilotProfileAssignment.ps1' 60
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
        $Id,
        $TargetGroupId,
        [parameter(Mandatory = $true)]
        [ValidateSet('Include', 'Exclude')]
        $AssignmentType,
        $FilterID,
        $FilterMode,
        [ValidateSet('Users', 'Devices')]
        $All
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
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Add-Enrolment\Add-EnrolmentESPAssignment.ps1' 82
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
        $Id,
        $TargetGroupId,
        [parameter(Mandatory = $true)]
        [ValidateSet('Include', 'Exclude')]
        $AssignmentType,
        $FilterID,
        $FilterMode,
        [ValidateSet('Users', 'Devices')]
        $All
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
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Add-Enrolment\Add-EnrolmentRestrictionAssignment.ps1' 82
#Region '.\Public\Get-App\Get-AppApp.ps1' 0
Function Get-AppApps() {

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
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Get-App\Get-AppApp.ps1' 33
#Region '.\Public\Get-App\Get-AppAppAssignment.ps1' 0
Function Get-AppAppAssignment() {

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
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Get-App\Get-AppAppAssignment.ps1' 39
#Region '.\Public\Get-App\Get-AppAppCategory.ps1' 0
Function Get-AppAppCategory() {

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
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Get-App\Get-AppAppCategory.ps1' 38
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
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Get-App\Get-AppCategory.ps1' 33
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
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Get-App\Get-AppConfigPolicyApp.ps1' 33
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
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Get-App\Get-AppConfigPolicyDevice.ps1' 33
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
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Get-App\Get-AppProtectionPolicy.ps1' 33
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
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Get-Device\Get-DeviceCompliancePolicy.ps1' 33
#Region '.\Public\Get-Device\Get-DeviceCompliancePolicyScript.ps1' 0
Function Get-DeviceCompliancePolicyScript() {

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
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Get-Device\Get-DeviceCompliancePolicyScript.ps1' 33
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
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Get-Device\Get-DeviceConfigProfile.ps1' 33
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
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Get-Device\Get-DeviceConfigProfileAssignment.ps1' 39
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
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Get-Device\Get-DeviceEndpointSecProfile.ps1' 34
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
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Get-Device\Get-DeviceEndpointSecTemplate.ps1' 33
#Region '.\Public\Get-Device\Get-DeviceEnrolmentRestriction.ps1' 0
Function Get-DeviceEnrollRestriction() {

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
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Get-Device\Get-DeviceEnrolmentRestriction.ps1' 33
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
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Get-Device\Get-DeviceFilter.ps1' 33
#Region '.\Public\Get-Device\Get-DeviceManagementScript.ps1' 0
Function Get-DeviceManagementScript() {

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
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Get-Device\Get-DeviceManagementScript.ps1' 40
#Region '.\Public\Get-Device\Get-DeviceManagementScriptAssignment.ps1' 0
Function Get-DeviceManagementScriptAssignment() {

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
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Get-Device\Get-DeviceManagementScriptAssignment.ps1' 39
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
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Get-Device\Get-DeviceNotificationMessage.ps1' 37
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
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Get-Device\Get-DeviceNotificationTemplate.ps1' 33
#Region '.\Public\Get-Device\Get-DeviceSettingsCatalogProfile.ps1' 0
Function Get-DeviceSettingsCatalogProfile() {

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
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Get-Device\Get-DeviceSettingsCatalogProfile.ps1' 46
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
            Write-Host 'Multiple parameters set, specify a single parameter -iOS or -Windows10 or -macOS against the function' -f Red
        }
        elseif ($Count_Params -eq 0) {
            Write-Host 'Parameter -iOS or -Windows10 or -macOS required against the function...' -ForegroundColor Red
            Write-Host
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
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Get-Device\Get-DeviceUpdatePolicy.ps1' 61
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
        $Id
    )

    $graphApiVersion = 'Beta'
    $Resource = "deviceManagement/depOnboardingSettings/$Id/enrollmentProfiles"

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Get
    }
    catch {
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Get-Enrolment\Get-EnrolmentADEProfile.ps1' 38
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
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Get-Enrolment\Get-EnrolmentADEToken.ps1' 32
#Region '.\Public\Get-Enrolment\Get-EnrolmentAutopilotProfile.ps1' 0
Function Get-EnrolmentAutopilotProfile() {

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
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Get-Enrolment\Get-EnrolmentAutopilotProfile.ps1' 33
#Region '.\Public\Get-Enrolment\Get-EnrolmentAutopilotProfileAssignment.ps1' 0
Function Get-EnrolmentAutopilotProfileAssignment() {

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
    $Resource = 'deviceManagement/windowsAutopilotDeploymentProfiles'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$Id/Assignments/"
        Invoke-MEMRestMethod -Uri $uri -Method Get
    }
    catch {
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Get-Enrolment\Get-EnrolmentAutopilotProfileAssignment.ps1' 39
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
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Get-Enrolment\Get-EnrolmentESP.ps1' 33
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
        $id
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/deviceEnrollmentConfigurations'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$Id/Assignments/"
        Invoke-MEMRestMethod -Uri $uri -Method Get
    }
    catch {
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Get-Enrolment\Get-EnrolmentESPAssignment.ps1' 39
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
        [string]$GroupName
    )

    $graphApiVersion = 'beta'
    $Resource = 'groups'

    try {
        $authToken['ConsistencyLevel'] = 'eventual'
        $searchterm = 'search="displayName:' + $GroupName + '"'
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource`?$searchterm"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
    }
    catch {
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Get-Group\Get-MEMGroup.ps1' 41
#Region '.\Public\Invoke-App\Invoke-AppManagedGooglePlayAppSync.ps1' 0
Function Invoke-AppManagedGooglePlayAppSync() {

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
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Invoke-App\Invoke-AppManagedGooglePlayAppSync.ps1' 34
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

    [cmdletbinding()]

    param
    (
        [parameter(Mandatory = $true)]
        $JSON
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceAppManagement/targetedManagedAppConfigurations'

    try {
        Test-Json -Json $JSON
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Post -Body $JSON
    }
    catch {
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\New-App\New-AppConfigPolicyApp.ps1' 40
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

    [cmdletbinding()]

    param
    (
        [parameter(Mandatory = $true)]
        $JSON
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceAppManagement/mobileAppConfigurations'

    try {
        Test-Json -Json $JSON
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Post -Body $JSON
    }
    catch {
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\New-App\New-AppConfigPolicyDevice.ps1' 40
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

    [cmdletbinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        $Id
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
        Invoke-MEMRestMethod -Uri $uri -Method Post -Body $JSON
    }
    catch {
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\New-App\New-AppManagedGooglePlayApp.ps1' 45
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

    [cmdletbinding()]

    param
    (
        [parameter(Mandatory = $true)]
        $JSON
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceAppManagement/managedAppPolicies'

    try {
        Test-Json -Json $JSON
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Post -Body $JSON
    }
    catch {
        Write-Host
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\New-App\New-AppProtectionPolicy.ps1' 41
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

    [cmdletbinding()]

    param
    (
        [parameter(Mandatory = $true)]
        $JSON
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/deviceCompliancePolicies'

    try {
        Test-Json -Json $JSON
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Post -Body $JSON
    }
    catch {
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\New-Device\New-DeviceCompliancePolicy.ps1' 40
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

    [cmdletbinding()]

    param
    (
        [parameter(Mandatory = $true)]
        $JSON
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/deviceConfigurations'

    try {
        Test-Json -Json $JSON
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Post -Body $JSON
    }
    catch {
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\New-Device\New-DeviceConfigProfile.ps1' 40
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

    [cmdletbinding()]

    param
    (
        [parameter(Mandatory = $true)]
        $TemplateId,
        [parameter(Mandatory = $true)]
        $JSON
    )

    $graphApiVersion = 'Beta'
    $Resource = "deviceManagement/templates/$TemplateId/createInstance"

    try {
        Test-Json -Json $JSON
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Post -Body $JSON
    }
    catch {
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\New-Device\New-DeviceEndpointSecProfile.ps1' 42
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

    [cmdletbinding()]

    param
    (
        [parameter(Mandatory = $true)]
        $JSON
    )

    $graphApiVersion = 'beta'
    $Resource = 'deviceManagement/assignmentFilters'

    try {
        Test-Json -Json $JSON
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Post -Body $JSON
    }
    catch {
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\New-Device\New-DeviceFilter.ps1' 40
#Region '.\Public\New-Device\New-DeviceManagementScript.ps1' 0
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

    [cmdletbinding()]

    Param (
        # Path or URL to Powershell-script to add to Intune
        [Parameter(Mandatory = $true)]
        [string]$File,
        # PowerShell description in Intune
        [Parameter(Mandatory = $false)]
        [string]$Description,
        # Set to true if it is a URL
        [Parameter(Mandatory = $false)]
        [switch][bool]$URL = $false
    )
    if ($URL -eq $true) {
        $FileName = $File -split '/'
        $FileName = $FileName[-1]
        $OutFile = "$env:TEMP\$FileName"
        try {
            Invoke-WebRequest -Uri $File -UseBasicParsing -OutFile $OutFile
        }
        catch {
            Write-Host "Could not download file from URL: $File" -ForegroundColor Red
            break
        }
        $File = $OutFile
        if (!(Test-Path $File)) {
            Write-Host "$File could not be located." -ForegroundColor Red
            break
        }
    }
    elseif ($URL -eq $false) {
        if (!(Test-Path $File)) {
            Write-Host "$File could not be located." -ForegroundColor Red
            break
        }
        $FileName = Get-Item $File | Select-Object -ExpandProperty Name
        $DisplayName = $FileName.Split('.')[0]
        $B64File = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes("$File"));

        if ($URL -eq $true) {
            Remove-Item $File -Force
        }

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
        $DMS_resource = 'deviceManagement/deviceManagementScripts'
        Write-Verbose "Resource: $DMS_resource"

        try {
            $uri = "https://graph.microsoft.com/$graphApiVersion/$DMS_resource"
            Invoke-MEMRestMethod -Uri $uri -Method Post -Body $JSON
        }

        catch {
            $exs = $Error.ErrorDetails
            $ex = $exs[0]
            Write-Host "Response content:`n$ex" -f Red
            Write-Host
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
            Write-Host
        }
    }
}
#EndRegion '.\Public\New-Device\New-DeviceManagementScript.ps1' 91
#Region '.\Public\New-Device\New-DeviceNotificationMessage.ps1' 0
Function New-DeviceNotificationMessageNew-DeviceNotificationMessage() {

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
        $Id,
        [parameter(Mandatory = $true)]
        $JSON
    )

    $graphApiVersion = 'Beta'
    $Resource = "deviceManagement/notificationMessageTemplates/$Id/localizedNotificationMessages"

    try {
        Test-Json -Json $JSON
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Post -Body $JSON
    }
    catch {
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\New-Device\New-DeviceNotificationMessage.ps1' 42
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

    [cmdletbinding()]

    param
    (
        [parameter(Mandatory = $true)]
        $JSON
    )

    $graphApiVersion = 'v1.0'
    $Resource = 'deviceManagement/notificationMessageTemplates'

    try {
        Test-Json -Json $JSON
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Post -Body $JSON
    }
    catch {
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\New-Device\New-DeviceNotificationTemplate.ps1' 40
#Region '.\Public\New-Device\New-DeviceSettingCatalogProfile.ps1' 0
Function New-DeviceSettingCatalogProfile() {

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
        $JSON
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/configurationPolicies'

    try {
        Test-Json -Json $JSON
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Post -Body $JSON
    }
    catch {
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\New-Device\New-DeviceSettingCatalogProfile.ps1' 40
#Region '.\Public\New-Enrolment\New-EnrolmentAutopilotProfile.ps1' 0
Function New-EnrolmentAutopilotProfile() {

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
        $JSON
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/windowsAutopilotDeploymentProfiles'

    try {
        Test-Json -Json $JSON
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Post -Body $JSON
    }
    catch {
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\New-Enrolment\New-EnrolmentAutopilotProfile.ps1' 40
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

    [cmdletbinding()]

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
        Invoke-MEMRestMethod -Uri $uri -Method Post -Body $JSON
    }
    catch {
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\New-Enrolment\New-EnrolmentESP.ps1' 40
#Region '.\Public\Remove-App\Remove-AppAppAssignment.ps1' 0
Function Remove-AppAppAssignment() {

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
        $Id,
        [parameter(Mandatory = $true)]
        $AssignmentId
    )

    $graphApiVersion = 'Beta'
    $Resource = "deviceAppManagement/mobileApps/$Id/assignments/$AssignmentId"

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Delete
    }
    catch {
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Remove-App\Remove-AppAppAssignment.ps1' 41
#Region '.\Public\Remove-App\Remove-AppAppCategory.ps1' 0
Function Remove-AppAppCategory() {

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
        $Id,
        [Parameter(Mandatory = $true)]
        $CategoryId
    )

    $graphApiVersion = 'Beta'
    $Resource = "deviceAppManagement/mobileApps/$Id/categories/$CategoryId/`$ref"

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Delete
    }
    catch {
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Remove-App\Remove-AppAppCategory.ps1' 41
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

    [cmdletbinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        $id
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceAppManagement/targetedManagedAppConfigurations'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id"
        Invoke-MEMRestMethod -Uri $uri -Method Delete
    }
    catch {
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Remove-App\Remove-AppConfigPolicyApp.ps1' 39
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

    [cmdletbinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        $id
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceAppManagement/mobileAppConfigurations'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id"
        Invoke-MEMRestMethod -Uri $uri -Method Delete
    }
    catch {
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Remove-App\Remove-AppConfigPolicyDevice.ps1' 39
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

    [cmdletbinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        $id
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceAppManagement/managedAppPolicies'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id"
        Invoke-MEMRestMethod -Uri $uri -Method Delete
    }
    catch {
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Remove-App\Remove-AppProtectionPolicy.ps1' 39
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

    [cmdletbinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        $id
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/deviceCompliancePolicies'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id"
        Invoke-MEMRestMethod -Uri $uri -Method Delete
    }
    catch {
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Remove-Device\Remove-DeviceCompliancePolicy.ps1' 39
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

    [cmdletbinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        $id
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/deviceConfigurations'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id"
        Invoke-MEMRestMethod -Uri $uri -Method Delete
    }
    catch {
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Remove-Device\Remove-DeviceConfigProfile.ps1' 39
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

    [cmdletbinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        $id
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/assignmentFilters'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id"
        Invoke-MEMRestMethod -Uri $uri -Method Delete
    }
    catch {
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Remove-Device\Remove-DeviceFilter.ps1' 39
#Region '.\Public\Remove-Device\Remove-DeviceManagementScript.ps1' 0
Function Remove-DeviceManagementScript() {

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

    [cmdletbinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        $id
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/deviceManagementScripts'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id"
        Invoke-MEMRestMethod -Uri $uri -Method Delete
    }
    catch {
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Remove-Device\Remove-DeviceManagementScript.ps1' 39
#Region '.\Public\Remove-Device\Remove-DeviceSettingsCatalogProfile.ps1' 0
Function Remove-DeviceSettingsCatalogProfile() {

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

    [cmdletbinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        $id
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/configurationPolicies'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id"
        Invoke-MEMRestMethod -Uri $uri -Method Delete
    }
    catch {
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Remove-Device\Remove-DeviceSettingsCatalogProfile.ps1' 39
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

    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        $Id,
        [Parameter(Mandatory = $true)]
        $JSON
    )

    $graphApiVersion = 'Beta'
    $Resource = "deviceManagement/deviceCompliancePolicies/$id"

    try {
        Test-Json -Json $JSON
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MEMRestMethod -Uri $uri -Method Patch -Body $JSON

    }
    catch {
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}
#EndRegion '.\Public\Update-Device\Update-DeviceCompliancePolicy.ps1' 42
