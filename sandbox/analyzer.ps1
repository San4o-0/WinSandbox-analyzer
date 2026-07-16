$ErrorActionPreference = "SilentlyContinue"

$shared = "C:\Users\WDAGUtilityAccount\Desktop\shared"
$reportPath = Join-Path $shared "report.json"
$configPath = Join-Path $shared "run.json"

$runCfg = Get-Content $configPath -Raw | ConvertFrom-Json
$targetName = $runCfg.file_name
$observeSeconds = [int]$runCfg.observe_seconds
$target = Join-Path $shared $targetName

function Get-SystemSnapshot {
    $procs = Get-Process | Select-Object -ExpandProperty Name | Sort-Object -Unique
    $services = Get-Service | Where-Object { $_.Status -eq "Running" } | Select-Object -ExpandProperty Name | Sort-Object -Unique
    $tasks = (Get-ScheduledTask | Select-Object -ExpandProperty TaskName) | Sort-Object -Unique

    $runKeys = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    $autoruns = @()
    foreach ($k in $runKeys) {
        $item = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
        if ($item) {
            $item.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
                $autoruns += "$k::$($_.Name)=$($_.Value)"
            }
        }
    }

    $watchDirs = @(
        "$env:APPDATA", "$env:LOCALAPPDATA", "$env:TEMP",
        "$env:USERPROFILE\Start Menu\Programs\Startup",
        "C:\Windows\System32\Tasks"
    )
    $files = @()
    foreach ($d in $watchDirs) {
        Get-ChildItem -Path $d -Recurse -File -ErrorAction SilentlyContinue |
            ForEach-Object { $files += $_.FullName }
    }

    $conns = @()
    Get-NetTCPConnection -ErrorAction SilentlyContinue |
        Where-Object { $_.RemoteAddress -ne "0.0.0.0" -and $_.RemoteAddress -ne "127.0.0.1" -and $_.RemoteAddress -ne "::" } |
        ForEach-Object { $conns += "$($_.RemoteAddress):$($_.RemotePort)" }

    return [PSCustomObject]@{
        processes = $procs
        services  = $services
        tasks     = $tasks
        autoruns  = $autoruns
        files     = ($files | Sort-Object -Unique)
        conns     = ($conns | Sort-Object -Unique)
    }
}

function Diff-Set($before, $after) {
    if (-not $before) { $before = @() }
    if (-not $after) { $after = @() }
    return @(Compare-Object -ReferenceObject $before -DifferenceObject $after |
        Where-Object { $_.SideIndicator -eq "=>" } |
        Select-Object -ExpandProperty InputObject)
}

$before = Get-SystemSnapshot

$launched = $false
$launchError = ""
try {
    $ext = [System.IO.Path]::GetExtension($targetName).ToLower()
    switch ($ext) {
        ".ps1" { Start-Process powershell.exe -ArgumentList "-ExecutionPolicy","Bypass","-File","`"$target`"" }
        ".bat" { Start-Process cmd.exe -ArgumentList "/c","`"$target`"" }
        ".cmd" { Start-Process cmd.exe -ArgumentList "/c","`"$target`"" }
        ".vbs" { Start-Process wscript.exe -ArgumentList "`"$target`"" }
        ".js"  { Start-Process wscript.exe -ArgumentList "`"$target`"" }
        ".jar" { Start-Process cmd.exe -ArgumentList "/c","java -jar `"$target`"" }
        default { Start-Process -FilePath $target }
    }
    $launched = $true
} catch {
    $launchError = $_.Exception.Message
}

Start-Sleep -Seconds $observeSeconds

$after = Get-SystemSnapshot

$report = [PSCustomObject]@{
    target            = $targetName
    launched          = $launched
    launch_error      = $launchError
    observed_seconds  = $observeSeconds
    new_processes     = Diff-Set $before.processes $after.processes
    new_services      = Diff-Set $before.services $after.services
    new_tasks         = Diff-Set $before.tasks $after.tasks
    new_autoruns      = Diff-Set $before.autoruns $after.autoruns
    new_files         = Diff-Set $before.files $after.files
    new_connections   = Diff-Set $before.conns $after.conns
}

$report | ConvertTo-Json -Depth 6 | Out-File -FilePath $reportPath -Encoding UTF8
