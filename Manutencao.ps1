<#
    Script de manutenção avançada para Windows
    Versão Full: Verificação Geral, Hardware, Rede e Corporativo.
#>

param(
    [switch]$Silent
)

# --- Verificação de permissão administrativa ---
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Warning "Este script precisa ser executado como Administrador."
    Pause
    exit
}

# --- Configuração de Log ---
$LogFile = Join-Path $PSScriptRoot "Manutencao_$(Get-Date -Format 'yyyyMMdd_HHmm').log"
Start-Transcript -Path $LogFile -Append
Write-Host "Iniciando log em: $LogFile" -ForegroundColor Cyan
Write-Host "---------------------------------------------------"

# --- Funções auxiliares ---
function Instalar-Winget {
    Write-Host "winget não encontrado. Tentando instalar..."
    # URL direta para o instalador oficial
    $wingetMsixUrl = "https://github.com/microsoft/winget-cli/releases/latest/download/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
    $wingetInstaller = "$env:TEMP\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
    try {
        Invoke-WebRequest -Uri $wingetMsixUrl -OutFile $wingetInstaller -UseBasicParsing
        Add-AppxPackage -Path $wingetInstaller
        Write-Host "winget instalado. Por favor, reinicie o computador e execute o script novamente."
    } catch {
        Write-Warning "Falha ao instalar o winget. Instale manualmente via Microsoft Store."
    }
    Pause
    exit
}

function Limpar-Pasta($Path, $Filtro = '*.*') {
    if (Test-Path $Path) {
        Write-Host "Limpando: $Path (Itens com mais de $Dias dias)" -ForegroundColor Gray
        try {
            $limitDate = (Get-Date).AddDays(-$Dias)
            Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -lt $limitDate } |
                Where-Object { $_.PSIsContainer -eq $false -or (Get-ChildItem $_.FullName -ErrorAction SilentlyContinue).Count -eq 0 } |
                Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
        } catch {
            Write-Warning "Alguns itens em $Path estao em uso e foram ignorados."
        }
    }
}

function Limpar-WindowsUpdateCache {
    Write-Host "Limpando cache do Windows Update..." -ForegroundColor Yellow
    Stop-Service -Name wuauserv, bits -Force -ErrorAction SilentlyContinue
    Limpar-Pasta "$env:SystemRoot\SoftwareDistribution\Download"
    Start-Service -Name wuauserv, bits -ErrorAction SilentlyContinue
}

function Verificar-Bateria {
    Write-Host "Analisando saúde da bateria..." -ForegroundColor Cyan
    $battery = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue
    if ($battery) {
        # Nota: FullChargeCapacity nem sempre está disponível via CIM em todos os notebooks
        # Em alguns casos, usamos o powercfg /batteryreport para maior precisão
        $design = $battery.DesignCapacity
        $full = $battery.FullChargeCapacity
        if ($design -gt 0 -and $full -gt 0) {
            $health = [math]::Round(($full / $design), 2)
            Write-Host "Saúde da Bateria: $($health * 100)%"
            if ($health -lt 0.15) { Write-Warning "ALERTA: Saúde da bateria crítica (abaixo de 15%)!" }
        }
    } else {
        Write-Host "Bateria não detectada (Desktop)."
    }
}
function Verificar-Servicos {
    $servicos = @(
        "wuauserv",
        "msiserver",
        "bits",
        "TrustedInstaller"
    )
    Write-Host "`nStatus dos serviços principais:"
    foreach ($srv in $servicos) {
        $status = Get-Service -Name $srv -ErrorAction SilentlyContinue
        if ($status) {
            Write-Host ("{0,-25} {1}" -f $status.DisplayName, $status.Status)
        } else {
            Write-Host ("{0,-25} NÃO ENCONTRADO" -f $srv)
        }
    }
}

function Atualizar-WindowsUpdateEdrivers {
    Write-Host "Forçando atualização do Windows Update (incluindo drivers)..."
    if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction SilentlyContinue
        Install-Module -Name PSWindowsUpdate -Force -AllowClobber -Scope CurrentUser
    }
    Import-Module PSWindowsUpdate
    Get-WindowsUpdate -AcceptAll -Install -MicrosoftUpdate -Drivers -AutoReboot:$false
}

function Atualizar-WindowsDefender {
    Write-Host "`nAtualizando definições do Windows Defender..."
    try {
        Update-MpSignature
        Start-MpScan -ScanType QuickScan
    } catch { Write-Warning "Falha no Windows Defender." }
}

# --- INÍCIO DO PROCESSO ---

Write-Host "`n[1/8] Verificação Geral do Sistema" -ForegroundColor Cyan
# Uptime Check
$lastBoot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$uptime = (Get-Date) - $lastBoot
Write-Host "Uptime atual: $($uptime.Days) dias, $($uptime.Hours) horas."
if ($uptime.Days -gt 14) {
    Write-Warning "AVISO: O sistema não é reiniciado há mais de 2 semanas!"
}

# Espaço em Disco
Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
    $freeGB = [math]::Round($_.FreeSpace / 1GB, 2)
    Write-Host "Disco $($_.DeviceID) - Espaço Livre: $freeGB GB"
    if ($freeGB -lt 10) { Write-Warning "Espaço em disco baixo no $($_.DeviceID)!" }
}

Write-Host "`n[2/8] Atualizações de Software e Windows" -ForegroundColor Cyan
$Whitelist = @{
    "Apps" = @("Microsoft.Edge", "Mozilla.Firefox", "Google.Chrome", "Git.Git", "7zip.7zip", "Notepad++.Notepad++", "Zoom.Zoom.EXE", "Microsoft.Teams")
    "Utils" = @("CrystalDewWorld.CrystalDiskInfo", "Microsoft.PowerToys", "Adobe.Acrobat.Reader.64-bit")
}
$allWhitelistIds = $Whitelist.Values | ForEach-Object { $_ }

if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Instalar-Winget
}

$updatesDisponiveisRaw = winget upgrade --accept-source-agreements | Out-String
$appsParaAtualizar = $allWhitelistIds | Where-Object { $updatesDisponiveisRaw -match [regex]::Escape($_) }
$totalApps = ($appsParaAtualizar).Count

if ($totalApps -gt 0) {
    $current = 1
    foreach ($app in $appsParaAtualizar) {
        Write-Host "[$current/$totalApps] Winget -> Atualizando: $app" -ForegroundColor Yellow
        winget upgrade --id $app --silent --accept-package-agreements --accept-source-agreements --include-unknown -e > $null
        $current++
    }
} else {
    Write-Host "Aplicativos Winget já estão atualizados." -ForegroundColor Green
}

Write-Host "Verificando Windows Updates (incluindo opcionais/drivers)..."
Atualizar-WindowsUpdateEdrivers

Write-Host "`n[3/8] Limpeza do Sistema" -ForegroundColor Cyan
Limpar-WindowsUpdateCache
Limpar-Pasta $env:TEMP 0
Get-CimInstance Win32_UserProfile | Where-Object { $_.Special -eq $false } | ForEach-Object {
    $userTemp = Join-Path $_.LocalPath 'AppData\Local\Temp'
    $userDownloads = Join-Path $_.LocalPath 'Downloads'
    if (Test-Path $userTemp) { Limpar-Pasta $userTemp 0 }
    if (Test-Path $userDownloads) { Limpar-Pasta $userDownloads 30 }
}
Limpar-Pasta "$env:SystemRoot\Temp" 0
Limpar-Pasta "$env:SystemRoot\Prefetch" 0

Write-Host "Limpando logs de eventos antigos (mais de 14 dias)..."
$logDirs = @("$env:SystemRoot\Logs", "$env:SystemRoot\System32\LogFiles")
foreach ($dir in $logDirs) { Limpar-Pasta $dir 14 }

Write-Host "Esvaziando Lixeira..."
Clear-RecycleBin -Force -ErrorAction SilentlyContinue

Write-Host "Removendo programas indesejados (Dell OS Recovery)..."
winget uninstall --id "Dell.RecoveryManager" --silent --accept-source-agreements -e 2>$null
winget uninstall --id "Dell.PeripheralManager" --silent --accept-source-agreements -e 2>$null

Write-Host "`n[4/8] Verificação de Hardware" -ForegroundColor Cyan
Verificar-Bateria

Write-Host "`n[5/8] Verificação de Rede" -ForegroundColor Cyan
Write-Host "Limpando cache de DNS..."
ipconfig /flushdns > $null

Write-Host "`n[6/8] Verificação Corporativa (Domínio/GPO)" -ForegroundColor Cyan
$compSystem = Get-CimInstance Win32_ComputerSystem
if ($compSystem.PartOfDomain) {
    Write-Host "Domínio detectado: $($compSystem.Domain)" -ForegroundColor Green
    Write-Host "Verificando GPOs aplicadas..."
    gpresult /r /scope computer | Select-String "Applied Group Policy Objects" -Context 5
} else {
    Write-Host "Computador em Workgroup."
}

Write-Host "`n[7/8] Otimização Final (Reparos de Imagem)" -ForegroundColor Cyan
DISM /Online /Cleanup-Image /ScanHealth
DISM /Online /Cleanup-Image /RestoreHealth
SFC /Scannow

Write-Host "`n[8/8] Finalização" -ForegroundColor Cyan
Verificar-Servicos
Atualizar-WindowsDefender

Write-Host "`n Manutenção concluída com sucesso!"
Stop-Transcript

if (-not $Silent) {
    $choice = Read-Host "`nManutenção finalizada. Deseja reiniciar a máquina agora? (S/N)"
    if ($choice -eq 'S' -or $choice -eq 's') {
        Restart-Computer -Force
    }
}
