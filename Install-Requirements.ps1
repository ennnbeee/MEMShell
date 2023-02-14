$Modules = @("ModuleBuilder")

foreach ($Module in $Modules) {
    Try {
        Get-InstalledModule -Name $Module -ErrorAction Stop
    }
    Catch {
        Write-Host "Installing $Module" -ForegroundColor Cyan
        Install-Module -Name $Module -Force
    }
}