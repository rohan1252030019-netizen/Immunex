# IMMUNEX Canara Bank SuRaksha Live Demo Automation Script
# =========================================================

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   IMMUNEX CANARA BANK SURAKSHA CYBER-DEFENSE PLATFORM   " -ForegroundColor Cyan
Write-Host "           LIVE DEMO AUTOMATION INTERFACE                " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Start the Backend API & Telemetry Engine
Write-Host "`n[+] Booting Backend API and Ingestion Engine..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd C:\Users\Admin\Downloads\IMMUNEX_ENTERPRISE_SOC_FINAL; .\venv\Scripts\activate; python main.py --api" -WindowStyle Normal

# 2. Start the Next.js Frontend Console
Write-Host "[+] Booting Next.js Glassmorphism Console..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd C:\Users\Admin\Downloads\IMMUNEX_ENTERPRISE_SOC_FINAL\frontend; npm run dev" -WindowStyle Normal

# 3. Wait for booting sequences
Write-Host "`n[+] Waiting 6 seconds for compilers and local servers to bind..." -ForegroundColor DarkYellow
Start-Sleep -Seconds 6

# 4. Launch Browser Panel
Write-Host "[+] Launching Secure Command Deck in Default Browser..." -ForegroundColor Green
Start-Process "http://localhost:3000"

Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host "                  DEMO READY TO EXECUTE                   " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "1. Log in using:"
Write-Host "   - Identity: admin" -ForegroundColor Cyan
Write-Host "   - Cipher:   administrator_secret_soc" -ForegroundColor Cyan
Write-Host "2. Navigate to the dashboard or alert feed."
Write-Host "3. Press [ENTER] in this window to inject a real, unmocked critical fraud incident!" -ForegroundColor Yellow
Write-Host "=========================================================="

Read-Host "Press [ENTER] to inject live incident..."

# 5. Inject Live Malicious Transaction
Write-Host "`n[+] Injecting Critical Fraud incident (Keystroke Anomaly + Impossible Travel)..." -ForegroundColor Red

$postParams = @{
    src_ip = "198.51.100.42"
    dst_ip = "10.0.0.5"
    src_port = 50123
    dst_port = 445
    protocol = "TCP"
    user_id = "clerk_operator_02"
    process_name = "cmd.exe"
    process_hash = "b4c2b9a7c39de0f85b88c1c1f19d20c3a5e88f192b8d00eeff4b98cd6b73a21a"
    event_type = "privilege_change"
    src_bytes = 1024
    dst_bytes = 45000
    duration = 2.5
    failed_logins = 3
    connection_count = 12
    packet_rate = 85.0
    geo_location = "USA"
    asset_criticality = "HIGH"
} | ConvertTo-Json

Invoke-WebRequest -Uri "http://localhost:8080/api/v1/telemetry" -Method POST -Body $postParams -ContentType "application/json"

Write-Host "`n[+] Incident injected! Check your browser window to witness the live Command Center reaction." -ForegroundColor Green
Write-Host "[+] Demonstrating Explainable AI, Attack Graph changes, and RBI Compliance updates." -ForegroundColor Green
Write-Host "`n==========================================================" -ForegroundColor Cyan
