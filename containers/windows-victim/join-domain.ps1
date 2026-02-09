# Join the TechVault AD domain
# Run as Administrator
param(
    [string]$DomainName = "techvault.local",
    [string]$DNSIP = "172.20.2.10",
    [string]$AdminUser = "TECHVAULT\Administrator",
    [string]$AdminPassword = "Admin123!"
)

Write-Host "=== Joining TechVault domain ==="

# Set DNS to the AD DC
$adapter = Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select-Object -First 1
Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $DNSIP

# Verify DNS resolution
Write-Host "Testing DNS resolution..."
Resolve-DnsName $DomainName -ErrorAction Stop

# Join domain
$securePassword = ConvertTo-SecureString $AdminPassword -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($AdminUser, $securePassword)

Write-Host "Joining domain $DomainName..."
Add-Computer -DomainName $DomainName -Credential $credential -Restart -Force

Write-Host "=== Domain join initiated. System will restart. ==="
