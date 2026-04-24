<#
    Script de manutenção avançada para Windows
    Versão Full: Verificação Geral, Hardware, Rede e Corporativo.
#>

param(
    [switch]$Silent
)

# --- Verificação de permissão administrativa ---
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Warning "Este script precisa ser executado como Administrador."
    Pause
    exit
}

# --- Configuração de Log ---
$NomeMaquina = $env:COMPUTERNAME
$UsuarioLogado = $env:USERNAME
$DataExecucao = Get-Date -Format 'yyyyMMdd_HHmm'

# Pasta Logs
$LogFolder = Join-Path $PSScriptRoot "Logs"

# Criar pasta se não existir
if (-not (Test-Path $LogFolder)) {
    New-Item -ItemType Directory -Path $LogFolder | Out-Null
}

$LogFile = Join-Path $LogFolder "Manutencao_${NomeMaquina}_${UsuarioLogado}_${DataExecucao}.log"

Start-Transcript -Path $LogFile -Append

Write-Host "Iniciando log em: $LogFile" -ForegroundColor Cyan
Write-Host "---------------------------------------------------"

# --- Funções auxiliares ---
function Instalar-Winget {
    Write-Host "winget não encontrado. Tentando instalar..."
    $wingetMsixUrl = "https://github.com/microsoft/winget-cli/releases/latest/download/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
    $wingetInstaller = "$env:TEMP\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
    try {
        Invoke-WebRequest -Uri $wingetMsixUrl -OutFile $wingetInstaller -UseBasicParsing
        Add-AppxPackage -Path $wingetInstaller
        Write-Host "winget instalado. Reinicie o computador e execute novamente."
    } catch {
        Write-Warning "Falha ao instalar o winget."
    }
    Pause
    exit
}

function Limpar-Pasta($Path, $Dias = 0) {
    if (Test-Path $Path) {
        Write-Host "Limpando: $Path (Itens com mais de $Dias dias)" -ForegroundColor Gray
        try {
            $limitDate = (Get-Date).AddDays(-$Dias)

            Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object {
                $_.LastWriteTime -lt $limitDate -and
                (
                    -not $_.PSIsContainer -or
                    (Get-ChildItem $_.FullName -ErrorAction SilentlyContinue).Count -eq 0
                )
            } |
            Remove-Item -Force -Recurse -ErrorAction SilentlyContinue

        } catch {
            Write-Warning "Alguns itens em $Path estão em uso."
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
        $design = $battery.DesignCapacity
        $full = $battery.FullChargeCapacity

        if ($design -gt 0 -and $full -gt 0) {
            $health = [math]::Round(($full / $design), 2)
            Write-Host "Saúde da Bateria: $($health * 100)%"

            if ($health -lt 0.15) {
                Write-Warning "Saúde da bateria crítica"
            }
        }
    } else {
        Write-Host "Bateria não detectada"
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
        }
    }
}

function Atualizar-WindowsUpdateEdrivers {

    Write-Host "Atualizando Windows Update..."

    if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
        Install-PackageProvider -Name NuGet -Force
        Install-Module PSWindowsUpdate -Force
    }

    Import-Module PSWindowsUpdate

    Get-WindowsUpdate -AcceptAll -Install -MicrosoftUpdate -IgnoreReboot
}

function Atualizar-WindowsDefender {

    Write-Host "Atualizando Windows Defender..."

    try {
        Update-MpSignature
        Start-MpScan -ScanType QuickScan
    } catch {
        Write-Warning "Falha no Defender"
    }
}

Write-Host "`n[1/8] Verificação Geral do Sistema" -ForegroundColor Cyan

$lastBoot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$uptime = (Get-Date) - $lastBoot

Write-Host "Uptime atual: $($uptime.Days) dias"

if ($uptime.Days -gt 14) {
    Write-Warning "Sistema sem reiniciar há mais de 14 dias"
}

Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {

    $freeGB = [math]::Round($_.FreeSpace / 1GB, 2)

    Write-Host "Disco $($_.DeviceID) - Livre: $freeGB GB"

    if ($freeGB -lt 10) {
        Write-Warning "Pouco espaço em disco"
    }
}

Write-Host "`n[2/8] Atualizações"

if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Instalar-Winget
}

winget upgrade --all --silent --accept-package-agreements --accept-source-agreements

Atualizar-WindowsUpdateEdrivers

Write-Host "`n[3/8] Limpeza"

Limpar-WindowsUpdateCache

Limpar-Pasta $env:TEMP

Get-CimInstance Win32_UserProfile | Where-Object {$_.Special -eq $false} | ForEach-Object {

    $temp = Join-Path $_.LocalPath "AppData\Local\Temp"

    if (Test-Path $temp) {
        Limpar-Pasta $temp
    }
}

Clear-RecycleBin -Force -ErrorAction SilentlyContinue

Write-Host "`n[4/8] Hardware"

Verificar-Bateria

Write-Host "`n[5/8] Rede"

ipconfig /flushdns

Write-Host "`n[6/8] Domínio"

$comp = Get-CimInstance Win32_ComputerSystem

if ($comp.PartOfDomain) {
    Write-Host "Domínio: $($comp.Domain)"
}

Write-Host "`n[7/8] Reparos"

Get-WmiObject win32_bios | Select-Object SerialNumber
DISM /Online /Cleanup-Image /ScanHealth
DISM /Online /Cleanup-Image /RestoreHealth
SFC /Scannow

Write-Host "`n[8/8] Finalização"

Verificar-Servicos

Atualizar-WindowsDefender

Write-Host "`nManutenção concluída com sucesso"

Stop-Transcript

if (-not $Silent) {

    $choice = Read-Host "Deseja reiniciar? (S/N)"

    if ($choice -eq "S") {
        Restart-Computer -Force
    }

}