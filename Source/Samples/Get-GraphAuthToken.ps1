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
    Write-Host 'Connected to Graph API' -ForegroundColor Green
    Write-Host
}
