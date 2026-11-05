
$AlertFile = "C:\Snort\log\alert.ids"
$Threshold = 5
$WindowSeconds = 60
$BlockDurationSeconds = 300
$AllowedAttackerIP = "192.168.56.101"

$Attempts = @{}
$Blocked = @{}

Write-Host "Snort Automatic Blocking System Started"
Write-Host "Monitoring: $AlertFile"
Write-Host "Threshold: $Threshold attempts in $WindowSeconds seconds"

Get-Content $AlertFile -Tail 0 -Wait | ForEach-Object {

    $Line = $_

    if ($Line -match '\[1:1000003:' -and
        $Line -match '\{TCP\}\s+(\d{1,3}(?:\.\d{1,3}){3}):\d+\s+->') {

        $AttackerIP = $Matches[1]

        if ($AttackerIP -ne $AllowedAttackerIP) {
            return
        }

        $Now = Get-Date

if ($Blocked.ContainsKey($AttackerIP)) {
    if ($Now -lt $Blocked[$AttackerIP]) {
        return
    }

    $Blocked.Remove($AttackerIP)
}


      if (-not $Attempts.ContainsKey($AttackerIP)) {
    $Attempts[$AttackerIP] = @()
}

$Attempts[$AttackerIP] = @(
    $Attempts[$AttackerIP] | Where-Object {
        ($Now - $_).TotalSeconds -le $WindowSeconds
    }
) + @($Now)

$Count = $Attempts[$AttackerIP].Count

        Write-Host "SSH attempts from $AttackerIP : $Count"

        if ($Count -ge $Threshold) {

            $RuleName = "Snort-AutoBlock-$AttackerIP"

            New-NetFirewallRule `
                -DisplayName $RuleName `
                -Direction Inbound `
                -RemoteAddress $AttackerIP `
                -Action Block `
                -Profile Any

            $Blocked[$AttackerIP] = (Get-Date).AddSeconds($BlockDurationSeconds)
            Start-Process powershell.exe -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "C:\Snort\auto-unblock.ps1", "-RuleName", $RuleName -WindowStyle Hidden
            Write-Host "BLOCKED: $AttackerIP" -ForegroundColor Red
        }
    }
}
