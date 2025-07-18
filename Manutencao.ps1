<#
    Script de manutenção avançada para Windows
    Última atualização: 11/07/2025
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

# --- Funções auxiliares ---
function Instalar-Winget {
    Write-Host "winget não encontrado. Tentando instalar..."
    $wingetMsixUrl = "https://aka.ms/getwinget"
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
        Write-Host "Limpando: $Path"
        try {
            $itens = Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
            $itens | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
        } catch {
            Write-Warning "Erro ao limpar $Path- ${_}"
        }
    }
}

function Limpar-LogsAntigos {
    Write-Host "Limpando todos os logs do Windows..."
    $logDirs = @(
        "C:\Windows\Logs",
        "C:\Windows\Temp",
        "C:\Windows\System32\LogFiles",
        "C:\Windows\System32\winevt\Logs"
    )
    foreach ($dir in $logDirs) {
        Limpar-Pasta $dir '*.*'
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
    } catch {
        Write-Warning "Falha ao atualizar ou escanear com o Windows Defender. Verifique se ele está habilitado."
    }
}

# --- Fluxo principal ---
if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Instalar-Winget
}

Write-Host "`n[1/7] Atualizando aplicativos com winget..."
$apps = @(
    "CrystalDewWorld.CrystalDiskInfo",
    "Docker.DockerDesktop",
    "Git.Git",
    "Notepad++.Notepad++",
    "TeamViewer.TeamViewer",
    "JanDeDobbeleer.OhMyPosh",
    "Adobe.Acrobat.Reader.64-bit",
    "Adobe.Acrobat.Reader.32-bit",
    "Adobe.CreativeCloud",
    "Google.ChromeRemoteDesktopHost",
    "Python.Launcher",
    "Microsoft.Teams.Classic",
    "Microsoft.Teams",
    "Microsoft.VCRedist.2015+.x64",
    "Microsoft.VCRedist.2015+.x86",
    "GitHub.GitHubDesktop",
    "Postman.Postman",
    "Zoom.Zoom.EXE",
    "XP89DCGQ3K6VLD",
    "XPDP273C0XHQH2",
    "7zip.7zip",
    "EaseUS.PartitionMaster",
    "OCSInventoryNG.WindowsAgent",
    "Fortinet.FortiClientVPN",
    "Microsoft.AzureDataStudio",
    "Oracle.MySQLWorkbench",
    "Microsoft.Edge",
    "Oracle.MySQL",
    "Microsoft.PowerToys",
    "Microsoft.SQLServerManagementStudio",
    "9NZVDKPMR9RD",
    "Mozilla.Firefox",
    "Mozilla.Firefox.ESR",
    "Mozilla.Firefox.MSIX",
    "Mozilla.Firefox.ESR.MSIX"
) | Sort-Object -Unique

foreach ($app in $apps) {
    Write-Host "Atualizando $app ..."
    winget update --id $app --silent --accept-package-agreements --accept-source-agreements
}

Write-Host "`n[2/7] Desinstalando softwares indesejados..."
winget uninstall Dell.PeripheralManager

Write-Host "`n[3/7] Atualizando Windows e drivers..."
Atualizar-WindowsUpdateEdrivers

Write-Host "`n[4/7] Limpando arquivos temporários e logs antigos..."
Limpar-Pasta $env:TEMP
Limpar-Pasta "C:\Windows\Temp"
Get-ChildItem 'C:\Users' -Directory | ForEach-Object {
    $userTemp = Join-Path $_.FullName 'AppData\Local\Temp'
    if (Test-Path $userTemp) {
        Limpar-Pasta $userTemp
    } else {
        Write-Warning "Temp não encontrado para o usuário $($_.Name)"
    }
}
Limpar-LogsAntigos

Write-Host "`n[5/7] Executando manutenção do sistema (DISM/SFC)..."
DISM /Online /Cleanup-Image /ScanHealth
DISM /Online /Cleanup-Image /RestoreHealth
SFC /Scannow

Write-Host "`n[6/7] Verificando status dos serviços principais..."
Verificar-Servicos

Write-Host "`n[7/7] Atualizando e escaneando com o Windows Defender..."
Atualizar-WindowsDefender

Write-Host "`n✅ Manutenção concluída com sucesso!"

if (-not $Silent) {
    Pause
}
