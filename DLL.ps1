
#Requires -RunAsAdministrator

$allDlls = @()

function Get-FileHashes {
    param (
        [string]$FilePath
    )
    try {
        if (Test-Path $FilePath) {
            try {
                $md5 = Get-FileHash -Path $FilePath -Algorithm MD5 -ErrorAction Stop
                $sha256 = Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop
                return @{
                    MD5 = $md5.Hash
                    SHA256 = $sha256.Hash
                    Status = "Success"
                }
            }
            catch [System.IO.IOException] {
                return @{
                    MD5 = "File in uso"
                    SHA256 = "File in uso"
                    Status = "Locked"
                }
            }
            catch {
                return @{
                    MD5 = "Errore: $($_.Exception.Message)"
                    SHA256 = "Errore: $($_.Exception.Message)"
                    Status = "Error"
                }
            }
        }
        return @{
            MD5 = "File non trovato"
            SHA256 = "File non trovato"
            Status = "NotFound"
        }
    }
    catch {
        return @{
            MD5 = "Errore accesso file"
            SHA256 = "Errore accesso file"
            Status = "AccessError"
        }
    }
}

$processes = Get-Process
Write-Host "Starting DLL analysis..." -ForegroundColor Cyan

$lockedFiles = @()
$errorFiles = @()
$processedFiles = 0
$totalModules = ($processes | ForEach-Object { $_.Modules.Count } | Measure-Object -Sum).Sum

foreach ($proc in $processes) {
    try {
        if ($totalModules -gt 0) {
            $percent = ($processedFiles / $totalModules) * 100
        } else {
            $percent = 0
        }
        Write-Progress -Activity "Analisi Processi" -Status "Processo: $($proc.Name) (PID: $($proc.Id))" -PercentComplete $percent

        $modules = $proc.Modules
        if ($modules) {
            foreach ($module in $modules) {
                $processedFiles++
                if ($module) {
                    try {
                        $dllInfo = @{
                            ProcessName = $proc.Name
                            ProcessId = $proc.Id
                            DllName = $module.ModuleName
                            DllPath = $module.FileName
                            Company = if ($module.Company) { [string]$module.Company } else { "N/A" }
                            FileVersion = [string]$module.FileVersion
                        }

                        $hashes = Get-FileHashes -FilePath $module.FileName
                        $dllInfo.MD5Hash = $hashes.MD5
                        $dllInfo.SHA256Hash = $hashes.SHA256
                        $dllInfo.HashStatus = $hashes.Status

                        try {
                            $fileInfo = Get-Item -Path $module.FileName -ErrorAction SilentlyContinue
                            if ($fileInfo) {
                                $dllInfo.FileSize = $fileInfo.Length
                                $dllInfo.LastWriteTime = $fileInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                            }
                        }
                        catch {
                            $dllInfo.FileSize = 0
                            $dllInfo.LastWriteTime = "Non accessibile"
                        }

                        $allDlls += $dllInfo

                        if ($hashes.Status -eq "Locked") {
                            $lockedFiles += $module.FileName
                        }
                        elseif ($hashes.Status -eq "Error" -or $hashes.Status -eq "AccessError") {
                            $errorFiles += $module.FileName
                        }
                    }
                    catch {
                        Write-Host "Warning: Unable to fully analyze $($module.ModuleName)" -ForegroundColor Yellow
                        continue
                    }
                }
            }
        }
    }
    catch {
        Write-Host "Error analyzing process $($proc.Name): $_" -ForegroundColor Red
        continue
    }
}

Write-Progress -Activity "Analisi Processi" -Completed

$output = @{
    timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    hostname = $env:COMPUTERNAME
    totalDlls = $allDlls.Count
    lockedDlls = $lockedFiles.Count
    errorDlls = $errorFiles.Count
    dlls = $allDlls
}

$desktopPath = [Environment]::GetFolderPath("Desktop")
$fileName = "$env:COMPUTERNAME`_$(Get-Date -Format 'yyyyMMdd_HHmmss')_DllList.json"
$outputPath = Join-Path $desktopPath $fileName
$output | ConvertTo-Json -Depth 10 | Out-File $outputPath -Encoding UTF8

Write-Host "`nAnalysis complete!" -ForegroundColor Green
Write-Host "Statistics:" -ForegroundColor Cyan
Write-Host "- Total DLLs analyzed: $($allDlls.Count)" -ForegroundColor White
Write-Host "- Locked/In-use DLLs: $($lockedFiles.Count)" -ForegroundColor Yellow
Write-Host "- DLLs with errors: $($errorFiles.Count)" -ForegroundColor Red
Write-Host "`nOutput saved to: $outputPath" -ForegroundColor Green

if ($lockedFiles.Count -gt 0 -or $errorFiles.Count -gt 0) {
    $logPath = Join-Path $desktopPath "$env:COMPUTERNAME`_$(Get-Date -Format 'yyyyMMdd_HHmmss')_DllErrors.log"
    "=== DLL Bloccate ===" | Out-File $logPath
    $lockedFiles | Out-File $logPath -Append
    "`n=== DLL con Errori ===" | Out-File $logPath -Append
    $errorFiles | Out-File $logPath -Append
    Write-Host "`nError log saved to: $logPath" -ForegroundColor Yellow
}
