param(
    [string]$RuleName
)

Start-Sleep -Seconds 300

Remove-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue

Write-Output "Firewall rule removed: $RuleName"