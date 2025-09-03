# YARA Rule Validation Script for DBK64.sys Detection
# Based on verified analysis from dry run

Write-Host "=== DBK64.sys YARA Rule Validation ===" -ForegroundColor Green

# Setup test environment
$TestDir = "C:\Analysis\YARA_Testing"
$PositiveDir = "$TestDir\positives"
$NegativeDir = "$TestDir\negatives"
$ResultsFile = "$TestDir\validation_results.txt"

# Create directories
New-Item -ItemType Directory -Path $TestDir -Force | Out-Null
New-Item -ItemType Directory -Path $PositiveDir -Force | Out-Null
New-Item -ItemType Directory -Path $NegativeDir -Force | Out-Null

Write-Host "[*] Setting up test corpus..." -ForegroundColor Yellow

# Copy test files
if (Test-Path "C:\Windows\System32\drivers\DBK64.sys") {
    Copy-Item "C:\Windows\System32\drivers\DBK64.sys" $PositiveDir -Force
    Write-Host "[+] Added DBK64.sys to positive test set"
} elseif (Test-Path "C:\Analysis\Samples\DBK64.sys") {
    Copy-Item "C:\Analysis\Samples\DBK64.sys" $PositiveDir -Force
    Write-Host "[+] Added DBK64.sys to positive test set"
} else {
    Write-Host "[-] WARNING: DBK64.sys not found for positive testing"
}

# Add negative test cases (legitimate Windows drivers)
$LegitDrivers = @(
    "C:\Windows\System32\drivers\ntfs.sys",
    "C:\Windows\System32\drivers\tcpip.sys", 
    "C:\Windows\System32\drivers\http.sys",
    "C:\Windows\System32\drivers\ndis.sys",
    "C:\Windows\System32\drivers\volmgr.sys"
)

foreach ($driver in $LegitDrivers) {
    if (Test-Path $driver) {
        Copy-Item $driver $NegativeDir -Force
        Write-Host "[+] Added $(Split-Path $driver -Leaf) to negative test set"
    }
}

Write-Host "[*] Test corpus prepared" -ForegroundColor Yellow
Write-Host "    Positive samples: $(Get-ChildItem $PositiveDir\*.sys | Measure-Object | Select-Object -ExpandProperty Count)"
Write-Host "    Negative samples: $(Get-ChildItem $NegativeDir\*.sys | Measure-Object | Select-Object -ExpandProperty Count)"

# Check if YARA is available
if (-not (Get-Command yara -ErrorAction SilentlyContinue)) {
    Write-Host "[-] YARA not found in PATH" -ForegroundColor Red
    Write-Host "[*] Download YARA from: https://github.com/VirusTotal/yara/releases" -ForegroundColor Yellow
    Write-Host "[*] Manual testing commands:" -ForegroundColor Yellow
    Write-Host "    yara dbk64_detection.yar $PositiveDir\*.sys"
    Write-Host "    yara dbk64_detection.yar $NegativeDir\*.sys"
    exit 1
}

# Run YARA tests
Write-Host "[*] Running YARA validation tests..." -ForegroundColor Yellow

$YaraRules = "C:\Analysis\dbk64_detection.yar"
if (-not (Test-Path $YaraRules)) {
    Write-Host "[-] YARA rules file not found: $YaraRules" -ForegroundColor Red
    exit 1
}

# Clear results file
"=== DBK64.sys YARA Validation Results ===" | Out-File $ResultsFile -Encoding UTF8
"Generated: $(Get-Date)" | Out-File $ResultsFile -Append -Encoding UTF8
"" | Out-File $ResultsFile -Append -Encoding UTF8

# Test positive samples
"POSITIVE TESTS (should match):" | Out-File $ResultsFile -Append -Encoding UTF8
$TruePositives = 0
$TotalPositives = 0

Get-ChildItem "$PositiveDir\*.sys" | ForEach-Object {
    $TotalPositives++
    $result = & yara $YaraRules $_.FullName 2>&1
    if ($result -match "DBK64") {
        $TruePositives++
        "MATCH: $($_.Name) - $result" | Out-File $ResultsFile -Append -Encoding UTF8
        Write-Host "[+] MATCH: $($_.Name)" -ForegroundColor Green
    } else {
        "NO MATCH: $($_.Name)" | Out-File $ResultsFile -Append -Encoding UTF8
        Write-Host "[-] NO MATCH: $($_.Name)" -ForegroundColor Red
    }
}

# Test negative samples  
"" | Out-File $ResultsFile -Append -Encoding UTF8
"NEGATIVE TESTS (should NOT match):" | Out-File $ResultsFile -Append -Encoding UTF8
$FalsePositives = 0
$TotalNegatives = 0

Get-ChildItem "$NegativeDir\*.sys" | ForEach-Object {
    $TotalNegatives++
    $result = & yara $YaraRules $_.FullName 2>&1
    if ($result -match "DBK64") {
        $FalsePositives++
        "FALSE POSITIVE: $($_.Name) - $result" | Out-File $ResultsFile -Append -Encoding UTF8
        Write-Host "[-] FALSE POSITIVE: $($_.Name)" -ForegroundColor Red
    } else {
        "CORRECT NEGATIVE: $($_.Name)" | Out-File $ResultsFile -Append -Encoding UTF8
        Write-Host "[+] CORRECT NEGATIVE: $($_.Name)" -ForegroundColor Green
    }
}

# Calculate metrics
"" | Out-File $ResultsFile -Append -Encoding UTF8
"METRICS:" | Out-File $ResultsFile -Append -Encoding UTF8

if ($TotalPositives -gt 0) {
    $Recall = $TruePositives / $TotalPositives
    "Recall (True Positive Rate): $($Recall.ToString('P2'))" | Out-File $ResultsFile -Append -Encoding UTF8
}

if (($TruePositives + $FalsePositives) -gt 0) {
    $Precision = $TruePositives / ($TruePositives + $FalsePositives)
    "Precision: $($Precision.ToString('P2'))" | Out-File $ResultsFile -Append -Encoding UTF8
}

if ($TotalNegatives -gt 0) {
    $FPR = $FalsePositives / $TotalNegatives  
    "False Positive Rate: $($FPR.ToString('P2'))" | Out-File $ResultsFile -Append -Encoding UTF8
}

"True Positives: $TruePositives / $TotalPositives" | Out-File $ResultsFile -Append -Encoding UTF8
"False Positives: $FalsePositives / $TotalNegatives" | Out-File $ResultsFile -Append -Encoding UTF8

# Display summary
Write-Host "" 
Write-Host "=== VALIDATION SUMMARY ===" -ForegroundColor Green
Write-Host "True Positives: $TruePositives / $TotalPositives"
Write-Host "False Positives: $FalsePositives / $TotalNegatives"

if ($TotalPositives -gt 0) {
    Write-Host "Recall: $($Recall.ToString('P2'))"
}
if (($TruePositives + $FalsePositives) -gt 0) {
    Write-Host "Precision: $($Precision.ToString('P2'))"  
}
if ($TotalNegatives -gt 0) {
    Write-Host "False Positive Rate: $($FPR.ToString('P2'))"
}

Write-Host ""
Write-Host "Full results saved to: $ResultsFile" -ForegroundColor Yellow

# Validation criteria check
$ValidationPassed = $true

if ($TruePositives -eq 0) {
    Write-Host "❌ FAIL: Must detect DBK64.sys (0 true positives)" -ForegroundColor Red
    $ValidationPassed = $false
}

if ($FalsePositives -gt 0) {
    Write-Host "❌ FAIL: No false positives allowed on legitimate drivers ($FalsePositives found)" -ForegroundColor Red
    $ValidationPassed = $false
}

if ($ValidationPassed) {
    Write-Host "✅ PASS: All validation criteria met" -ForegroundColor Green
} else {
    Write-Host "❌ FAIL: Validation criteria not met" -ForegroundColor Red
}
