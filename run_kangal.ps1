param(
    [string]$Dir = "./data/malware",
    [string]$Label = "malware",
    [string]$Csv = "kangal_malware.csv",
    [string]$Env = "frida"
)

# Conda ortamini aktive et
conda activate $Env

Write-Host "===============================" -ForegroundColor Cyan
Write-Host " KangalGuard Batch Analyzer" -ForegroundColor Cyan
Write-Host "===============================" -ForegroundColor Cyan
Write-Host " Conda Env : $Env"
Write-Host " Dir       : $Dir"
Write-Host " Label     : $Label"
Write-Host " CSV       : $Csv"
Write-Host ""

$adbOutput = adb devices | Select-Object -Skip 1
$devices = $adbOutput | Where-Object { $_ -match "device$" } | ForEach-Object { ($_ -split "\s+")[0] }

if (-not $devices) {
    Write-Host "[!] Hic cihaz bulunamadi." -ForegroundColor Red
    exit 1
}

$deviceCount = @($devices).Count
Write-Host "[+] $deviceCount cihaz bulundu:" -ForegroundColor Green
$devices | ForEach-Object { Write-Host "    - $_" }
Write-Host ""

Write-Host "===============================" -ForegroundColor Yellow
Write-Host " ASAMA 1: Setup" -ForegroundColor Yellow
Write-Host "===============================" -ForegroundColor Yellow

foreach ($device in $devices) {
    Write-Host "[*] Setup: $device"
    conda run -n $Env python batch_analyzer.py --device $device --setup
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] Setup tamam: $device" -ForegroundColor Green
    } else {
        Write-Host "[!] Setup basarisiz: $device" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "===============================" -ForegroundColor Yellow
Write-Host " ASAMA 2: Analiz" -ForegroundColor Yellow
Write-Host "===============================" -ForegroundColor Yellow

foreach ($device in $devices) {
    Write-Host "[*] Analiz: $device"
    conda run -n $Env python batch_analyzer.py --device $device --dir $Dir --label $Label --csv $Csv
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] Tamam: $device" -ForegroundColor Green
    } else {
        Write-Host "[!] Basarisiz: $device" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "[+] Tum islemler tamamlandi." -ForegroundColor Cyan
