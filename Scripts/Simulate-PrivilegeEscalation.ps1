# Privilege Escalation Simulation Script
# Assigns a user to a privileged role, waits, then removes them
# Used to validate the Privileged Role Assignment Detection rule in Microsoft Sentinel
# MITRE ATT&CK: T1078.004 - Valid Accounts: Cloud Accounts

param(
    [string]$TargetUser = "socadmin@NavaSecurityInc.onmicrosoft.com",
    [string]$RoleName = "User Administrator",
    [int]$WaitSeconds = 120
)

# Connect with all required scopes
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory","User.Read.All" -UseDeviceAuthentication

# Get the role definition
Write-Host "Looking up role: $RoleName" -ForegroundColor Cyan
$role = Get-MgDirectoryRole | Where-Object { $_.DisplayName -eq $RoleName }

if (-not $role) {
    Write-Host "Activating role from template..." -ForegroundColor Yellow
    $roleTemplate = Get-MgDirectoryRoleTemplate | Where-Object { $_.DisplayName -eq $RoleName }
    $role = New-MgDirectoryRole -RoleTemplateId $roleTemplate.Id
}

Write-Host "Role ID: $($role.Id)" -ForegroundColor Gray

# Get the target user
Write-Host "Looking up user: $TargetUser" -ForegroundColor Cyan
$user = Get-MgUser -UserId $TargetUser
Write-Host "User ID: $($user.Id)" -ForegroundColor Gray

# Assign the role using Invoke-MgGraphRequest
Write-Host "Assigning $RoleName to $TargetUser..." -ForegroundColor Yellow
Invoke-MgGraphRequest -Method POST `
    -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$($role.Id)/members/`$ref" `
    -Body @{
        "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($user.Id)"
    } `
    -ContentType "application/json"

Write-Host "Role assigned successfully. Waiting $WaitSeconds seconds for audit log ingestion..." -ForegroundColor Green
Start-Sleep -Seconds $WaitSeconds

# Remove the role assignment
Write-Host "Removing role assignment..." -ForegroundColor Yellow
Remove-MgDirectoryRoleMemberByRef -DirectoryRoleId $role.Id -DirectoryObjectId $user.Id

Write-Host "Done. Check Microsoft Sentinel Incidents for Privileged Role Assignment Detection." -ForegroundColor Green
