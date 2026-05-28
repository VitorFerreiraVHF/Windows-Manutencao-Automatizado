<#
    Script de manutencao avancada para Windows
    Versao POP: verificacao geral, limpeza segura, updates, seguranca,
    rede/VPN, desempenho, DISM/SFC e resumo pronto para card.
#>

param(
    [switch]$Silent,
    [switch]$FullDefenderScan,
    [switch]$CleanPrefetch,
    [switch]$CleanMinidump,
    [int]$DiasLogsAntigos = 30,
    [string[]]$CorporateHosts = @()
)

$InicioExecucao = Get-Date
$TranscriptAtivo = $false

function ConvertTo-SafeFileName {
    param(
        [string]$Value,
        [string]$Fallback = "SEM_INFO"
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $Fallback
    }

    $clean = $Value -replace '[\\/:*?"<>|]', '_' -replace '\s+', '-'
    $clean = $clean.Trim([char[]]" ._-")

    if ([string]::IsNullOrWhiteSpace($clean)) {
        return $Fallback
    }

    return $clean
}

function Testar-Administrador {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal] $identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

# --- Verificacao de permissao administrativa ---
if (-not (Testar-Administrador)) {
    Write-Warning "Este script precisa ser executado como Administrador."
    if (-not $Silent) {
        Pause
    }
    exit 1
}

# --- Configuracao de Log ---
$NomeMaquina = $env:COMPUTERNAME
$UsuarioLogado = $env:USERNAME
$DominioUsuario = $env:USERDOMAIN

try {
    $ServiceTag = (Get-CimInstance Win32_BIOS -ErrorAction Stop | Select-Object -ExpandProperty SerialNumber)
} catch {
    $ServiceTag = ""
}

if ([string]::IsNullOrWhiteSpace($ServiceTag)) {
    $ServiceTag = "SEM_SERVICE_TAG"
}

$DataExecucao = Get-Date -Format 'yyyyMMdd_HHmm'
$LogFolder = Join-Path $PSScriptRoot "Logs"

if (-not (Test-Path -LiteralPath $LogFolder)) {
    New-Item -ItemType Directory -Path $LogFolder | Out-Null
}

$SafeMachine = ConvertTo-SafeFileName -Value $NomeMaquina -Fallback "SEM_MAQUINA"
$SafeUser = ConvertTo-SafeFileName -Value $UsuarioLogado -Fallback "SEM_USUARIO"
$SafeTag = ConvertTo-SafeFileName -Value $ServiceTag -Fallback "SEM_SERVICE_TAG"

$LogFile = Join-Path $LogFolder "Manutencao_${SafeMachine}_${SafeUser}_${SafeTag}_${DataExecucao}.log"
$ResumoCardFile = Join-Path $LogFolder "ResumoCard_${SafeMachine}_${SafeUser}_${SafeTag}_${DataExecucao}.txt"

Start-Transcript -Path $LogFile -Append
$TranscriptAtivo = $true

Write-Host "Iniciando log em: $LogFile" -ForegroundColor Cyan
Write-Host "Resumo do card sera gerado em: $ResumoCardFile" -ForegroundColor Cyan
Write-Host "---------------------------------------------------"

$Script:Checklist = [ordered]@{
    "Verificacao geral do equipamento" = $false
    "Limpeza de arquivos temporarios e residuos do sistema" = $false
    "Verificacao de espaco em disco" = $false
    "Execucao de Windows Update" = $false
    "Atualizacao de drivers e softwares corporativos" = $false
    "Verificacao de antivirus e seguranca do ambiente" = $false
    "Execucao de verificacoes DISM/SFC" = $false
    "Validacao de conectividade de rede/VPN" = $false
    "Testes operacionais gerais" = $false
    "Validacao de desempenho do equipamento" = $false
}

$Script:Resultados = New-Object 'System.Collections.Generic.List[string]'
$Script:Pendencias = New-Object 'System.Collections.Generic.List[string]'
$Script:Observacoes = New-Object 'System.Collections.Generic.List[string]'
$Script:ResumoTecnico = [ordered]@{}
$Script:ReinicioPendente = $false

function Add-ItemUnico {
    param(
        [System.Collections.Generic.List[string]]$Lista,
        [string]$Texto
    )

    if (-not [string]::IsNullOrWhiteSpace($Texto) -and -not $Lista.Contains($Texto)) {
        [void]$Lista.Add($Texto)
    }
}

function Registrar-Resultado {
    param([string]$Texto)
    Add-ItemUnico -Lista $Script:Resultados -Texto $Texto
}

function Registrar-Pendencia {
    param([string]$Texto)
    Add-ItemUnico -Lista $Script:Pendencias -Texto $Texto
}

function Registrar-Observacao {
    param([string]$Texto)
    Add-ItemUnico -Lista $Script:Observacoes -Texto $Texto
}

function Marcar-Atividade {
    param([string]$Nome)

    if ($Script:Checklist.Contains($Nome)) {
        $Script:Checklist[$Nome] = $true
    }
}

function Escrever-Secao {
    param(
        [string]$Numero,
        [string]$Titulo
    )

    Write-Host ""
    Write-Host "[$Numero] $Titulo" -ForegroundColor Cyan
}

function Executar-Processo {
    param(
        [string]$Arquivo,
        [string[]]$Argumentos,
        [string]$Descricao
    )

    if (-not [string]::IsNullOrWhiteSpace($Descricao)) {
        Write-Host $Descricao -ForegroundColor Gray
    }

    & $Arquivo @Argumentos
    $exitCode = $LASTEXITCODE

    if ($null -ne $exitCode -and $exitCode -ne 0) {
        Registrar-Pendencia "$Arquivo retornou codigo $exitCode ao executar: $($Argumentos -join ' ')"
    }
}

function Instalar-Winget {
    Write-Host "winget nao encontrado. Tentando instalar..." -ForegroundColor Yellow
    $wingetMsixUrl = "https://github.com/microsoft/winget-cli/releases/latest/download/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
    $wingetInstaller = Join-Path $env:TEMP "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"

    try {
        Invoke-WebRequest -Uri $wingetMsixUrl -OutFile $wingetInstaller -UseBasicParsing -ErrorAction Stop
        Add-AppxPackage -Path $wingetInstaller -ErrorAction Stop
        Registrar-Pendencia "winget foi instalado ou reparado; pode ser necessario reiniciar e reexecutar para concluir atualizacoes de aplicativos."
        return $true
    } catch {
        Write-Warning "Falha ao instalar o winget: $($_.Exception.Message)"
        Registrar-Pendencia "winget nao estava disponivel e nao foi possivel instalar automaticamente."
        return $false
    }
}

function Limpar-Pasta {
    param(
        [string]$Path,
        [int]$Dias = 0
    )

    $removidos = 0

    if (Test-Path -LiteralPath $Path) {
        Write-Host "Limpando: $Path (itens com mais de $Dias dias)" -ForegroundColor Gray

        try {
            $limitDate = (Get-Date).AddDays(-[math]::Abs($Dias))
            $items = @(
                Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -lt $limitDate } |
                Sort-Object FullName -Descending
            )

            foreach ($item in $items) {
                try {
                    Remove-Item -LiteralPath $item.FullName -Force -Recurse -ErrorAction Stop
                    $removidos++
                } catch {
                    # Arquivos em uso sao esperados durante manutencao.
                }
            }
        } catch {
            Write-Warning "Alguns itens em $Path nao puderam ser analisados."
        }
    }

    return $removidos
}

function Limpar-WindowsUpdateCache {
    Write-Host "Limpando cache do Windows Update..." -ForegroundColor Yellow
    $servicos = "wuauserv", "bits"
    $statusAnterior = @{}

    foreach ($srv in $servicos) {
        $service = Get-Service -Name $srv -ErrorAction SilentlyContinue
        if ($service) {
            $statusAnterior[$srv] = $service.Status
        }
    }

    try {
        Stop-Service -Name $servicos -Force -ErrorAction SilentlyContinue
        Limpar-Pasta "$env:SystemRoot\SoftwareDistribution\Download" | Out-Null
    } finally {
        foreach ($srv in $servicos) {
            if ($statusAnterior.ContainsKey($srv) -and $statusAnterior[$srv] -eq "Running") {
                Start-Service -Name $srv -ErrorAction SilentlyContinue
            }
        }
    }
}

function Limpar-CacheNavegadores {
    $perfis = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue |
        Where-Object { $_.Special -eq $false -and $_.LocalPath -and (Test-Path -LiteralPath $_.LocalPath) }

    $navegadores = @(
        @{
            Nome = "Google Chrome"
            Processo = "chrome"
            Pastas = @(
                "AppData\Local\Google\Chrome\User Data\*\Cache",
                "AppData\Local\Google\Chrome\User Data\*\Code Cache",
                "AppData\Local\Google\Chrome\User Data\*\GPUCache"
            )
        },
        @{
            Nome = "Microsoft Edge"
            Processo = "msedge"
            Pastas = @(
                "AppData\Local\Microsoft\Edge\User Data\*\Cache",
                "AppData\Local\Microsoft\Edge\User Data\*\Code Cache",
                "AppData\Local\Microsoft\Edge\User Data\*\GPUCache"
            )
        },
        @{
            Nome = "Mozilla Firefox"
            Processo = "firefox"
            Pastas = @(
                "AppData\Local\Mozilla\Firefox\Profiles\*\cache2"
            )
        }
    )

    foreach ($nav in $navegadores) {
        $processoAberto = Get-Process -Name $nav.Processo -ErrorAction SilentlyContinue

        if ($processoAberto) {
            Write-Warning "$($nav.Nome) esta aberto; cache nao sera limpo para evitar perda de sessao."
            Registrar-Pendencia "Cache do $($nav.Nome) nao foi limpo porque o navegador estava aberto."
            continue
        }

        foreach ($perfil in $perfis) {
            foreach ($relativo in $nav.Pastas) {
                $wildcardPath = Join-Path $perfil.LocalPath $relativo
                $pastasCache = @(Get-ChildItem -Path $wildcardPath -Directory -ErrorAction SilentlyContinue)

                foreach ($pasta in $pastasCache) {
                    Limpar-Pasta -Path $pasta.FullName | Out-Null
                }
            }
        }
    }
}

function Limpar-LogsDiagnostico {
    Limpar-Pasta "$env:SystemRoot\Logs" -Dias $DiasLogsAntigos | Out-Null

    if ($CleanMinidump) {
        Limpar-Pasta "$env:SystemRoot\Minidump" -Dias $DiasLogsAntigos | Out-Null
    } else {
        Registrar-Observacao "C:\Windows\Minidump nao foi limpo; use -CleanMinidump apenas apos analise de incidentes."
    }
}

function Verificar-Bateria {
    Write-Host "Analisando saude da bateria..." -ForegroundColor Cyan
    $battery = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue

    if ($battery) {
        $design = $battery.DesignCapacity
        $full = $battery.FullChargeCapacity
        $charge = $battery.EstimatedChargeRemaining

        if ($design -gt 0 -and $full -gt 0) {
            $health = [math]::Round(($full / $design) * 100, 0)
            Write-Host "Saude da bateria: $health%"
            $Script:ResumoTecnico["Bateria"] = "$health% de saude"

            if ($health -lt 50) {
                Registrar-Pendencia "Saude da bateria abaixo de 50%."
            }
        } elseif ($charge -ne $null) {
            Write-Host "Carga estimada da bateria: $charge%"
            $Script:ResumoTecnico["Bateria"] = "$charge% de carga estimada"
        }
    } else {
        Write-Host "Bateria nao detectada"
        $Script:ResumoTecnico["Bateria"] = "Nao detectada ou desktop"
    }
}

function Verificar-Servicos {
    $servicos = @(
        "wuauserv",
        "msiserver",
        "bits",
        "TrustedInstaller",
        "WinDefend",
        "MpsSvc"
    )

    Write-Host "`nStatus dos servicos principais:"

    foreach ($srv in $servicos) {
        $status = Get-Service -Name $srv -ErrorAction SilentlyContinue

        if ($status) {
            Write-Host ("{0,-35} {1}" -f $status.DisplayName, $status.Status)

            if ($status.Status -eq "Stopped" -and $srv -in @("WinDefend", "MpsSvc")) {
                Registrar-Pendencia "Servico essencial parado: $($status.DisplayName)."
            }
        }
    }
}

function Atualizar-WindowsUpdateEdrivers {
    Write-Host "Atualizando Windows Update e drivers Microsoft..." -ForegroundColor Yellow

    try {
        if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            Install-PackageProvider -Name NuGet -Force -ErrorAction Stop | Out-Null
            Install-Module PSWindowsUpdate -Scope CurrentUser -Force -AllowClobber -SkipPublisherCheck -ErrorAction Stop
        }

        Import-Module PSWindowsUpdate -ErrorAction Stop
        Get-WindowsUpdate -AcceptAll -Install -MicrosoftUpdate -IgnoreReboot -ErrorAction Stop
        Registrar-Resultado "Windows Update executado com instalacao de atualizacoes criticas, seguranca e drivers Microsoft disponiveis."
    } catch {
        Write-Warning "Falha no Windows Update via PSWindowsUpdate: $($_.Exception.Message)"
        Registrar-Pendencia "Windows Update nao concluiu via PSWindowsUpdate; validar historico do Windows Update manualmente."

        try {
            UsoClient StartScan
            UsoClient StartDownload
            UsoClient StartInstall
            Registrar-Observacao "Fallback do UsoClient acionado para scan/download/install do Windows Update."
        } catch {
            Registrar-Pendencia "Fallback UsoClient tambem nao foi acionado com sucesso."
        }
    }
}

function Atualizar-ProgramasCorporativos {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Instalar-Winget | Out-Null
    }

    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Host "Atualizando aplicativos via winget..." -ForegroundColor Yellow
        winget source update
        winget upgrade --all --silent --accept-package-agreements --accept-source-agreements

        if ($LASTEXITCODE -eq 0) {
            Registrar-Resultado "Softwares atualizados via winget, incluindo ferramentas corporativas catalogadas."
        } else {
            Registrar-Pendencia "winget upgrade retornou codigo $LASTEXITCODE; validar aplicativos pendentes."
        }
    }

    Validar-AppsCorporativos
}

function Validar-AppsCorporativos {
    $nomes = @("Microsoft 365", "Office", "Firefox", "Visual Studio Code", "Visual Studio")
    $chaves = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $apps = @(
        foreach ($chave in $chaves) {
            Get-ItemProperty -Path $chave -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName } |
                Select-Object -ExpandProperty DisplayName
        }
    )

    foreach ($nome in $nomes) {
        $encontrado = $apps | Where-Object { $_ -match [regex]::Escape($nome) } | Select-Object -First 1

        if ($encontrado) {
            Write-Host "Aplicativo validado: $encontrado"
        }
    }

    Registrar-Observacao "Apps especificos por setor devem ser conferidos contra o controle corporativo quando nao estiverem catalogados no winget."
}

function Atualizar-WindowsDefender {
    Write-Host "Atualizando Windows Defender..." -ForegroundColor Yellow

    try {
        Update-MpSignature -ErrorAction Stop

        if ($FullDefenderScan) {
            Start-MpScan -ScanType FullScan -ErrorAction Stop
            Registrar-Resultado "Windows Defender atualizado e verificacao completa executada."
        } else {
            Start-MpScan -ScanType QuickScan -ErrorAction Stop
            Registrar-Resultado "Windows Defender atualizado e verificacao rapida executada."
        }
    } catch {
        Write-Warning "Falha no Defender: $($_.Exception.Message)"
        Registrar-Pendencia "Atualizacao ou verificacao do Windows Defender nao concluiu."
    }
}

function Verificar-InformacoesGerais {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue

    Write-Host "Hostname: $NomeMaquina"
    Write-Host "Usuario logado: $DominioUsuario\$UsuarioLogado"
    Write-Host "Service Tag/Serial: $ServiceTag"

    if ($cs) {
        Write-Host "Fabricante/Modelo: $($cs.Manufacturer) $($cs.Model)"
        Write-Host "Dominio/Workgroup: $($cs.Domain)"
        $Script:ResumoTecnico["Equipamento"] = "$($cs.Manufacturer) $($cs.Model)"
    }

    if ($os) {
        Write-Host "Sistema: $($os.Caption) - Versao $($os.Version) - Build $($os.BuildNumber)"
        Write-Host "Ultimo boot: $($os.LastBootUpTime)"
        $Script:ResumoTecnico["Sistema"] = "$($os.Caption) build $($os.BuildNumber)"

        if ($os.Caption -notmatch "Windows 10|Windows 11") {
            Registrar-Pendencia "Sistema operacional fora do escopo padrao do POP: $($os.Caption)."
        }

        $uptime = (Get-Date) - $os.LastBootUpTime
        Write-Host "Uptime atual: $($uptime.Days) dias"

        if ($uptime.Days -gt 14) {
            Registrar-Pendencia "Sistema sem reiniciar ha mais de 14 dias."
        }
    }

    if ($bios) {
        Write-Host "BIOS: $($bios.SMBIOSBIOSVersion)"
    }

    Registrar-Resultado "Identificacao de usuario, hostname, patrimonio/Service Tag e versao do Windows validada."
    Registrar-Observacao "Backup de dados do usuario e registro de chamado devem estar validados antes da intervencao."
}

function Verificar-ReinicioPendente {
    $chaves = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
        "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
    )

    foreach ($chave in $chaves) {
        if ($chave -like "*Session Manager") {
            try {
                $valor = (Get-ItemProperty -Path $chave -Name PendingFileRenameOperations -ErrorAction Stop).PendingFileRenameOperations
                if ($valor) {
                    $Script:ReinicioPendente = $true
                }
            } catch {}
        } elseif (Test-Path -LiteralPath $chave) {
            $Script:ReinicioPendente = $true
        }
    }

    if ($Script:ReinicioPendente) {
        Write-Warning "Reinicio pendente detectado."
        Registrar-Pendencia "Reinicio pendente detectado para concluir atualizacoes/reparos."
    } else {
        Write-Host "Nenhum reinicio pendente detectado."
    }
}

function Verificar-Disco {
    $discos = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue

    foreach ($disco in $discos) {
        $freeGB = [math]::Round($disco.FreeSpace / 1GB, 2)
        $totalGB = [math]::Round($disco.Size / 1GB, 2)
        $freePct = 0

        if ($disco.Size -gt 0) {
            $freePct = [math]::Round(($disco.FreeSpace / $disco.Size) * 100, 2)
        }

        Write-Host "Disco $($disco.DeviceID) - Livre: $freeGB GB de $totalGB GB ($freePct%)"

        if ($disco.DeviceID -eq "C:") {
            $Script:ResumoTecnico["Disco C"] = "$freeGB GB livres ($freePct%)"
        }

        if ($freePct -lt 20) {
            Registrar-Pendencia "Disco $($disco.DeviceID) com menos de 20% de espaco livre."
        }

        if ($disco.FileSystem -eq "NTFS") {
            Executar-Processo -Arquivo "chkdsk.exe" -Argumentos @($disco.DeviceID, "/scan") -Descricao "Verificacao online de integridade do disco $($disco.DeviceID)"
        }
    }

    try {
        $fisicos = Get-PhysicalDisk -ErrorAction Stop
        foreach ($fisico in $fisicos) {
            Write-Host "Disco fisico: $($fisico.FriendlyName) - Health: $($fisico.HealthStatus) - Operational: $($fisico.OperationalStatus)"

            if ($fisico.HealthStatus -ne "Healthy") {
                Registrar-Pendencia "Disco fisico $($fisico.FriendlyName) reportou HealthStatus $($fisico.HealthStatus)."
            }
        }
    } catch {
        try {
            $smart = Get-CimInstance -Namespace root\wmi -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction Stop
            if ($smart | Where-Object { $_.PredictFailure }) {
                Registrar-Pendencia "SMART indicou previsao de falha em ao menos um disco."
            }
        } catch {
            Registrar-Observacao "Saude fisica do disco nao foi obtida pelas interfaces disponiveis."
        }
    }

    Registrar-Resultado "Espaco em disco e integridade basica de armazenamento avaliados."
}

function Verificar-Memoria {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue

    if ($os -and $os.TotalVisibleMemorySize -gt 0) {
        $totalGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
        $freeGB = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
        $usedPct = [math]::Round((($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize) * 100, 2)
        Write-Host "Memoria: $freeGB GB livres de $totalGB GB ($usedPct% em uso)"
        $Script:ResumoTecnico["Memoria"] = "$usedPct% em uso"
    }

    try {
        $eventos = Get-WinEvent -FilterHashtable @{
            LogName = "System"
            Id = 41, 1001
            StartTime = (Get-Date).AddDays(-30)
        } -MaxEvents 10 -ErrorAction Stop

        if ($eventos.Count -gt 0) {
            Registrar-Pendencia "Eventos recentes de travamento/tela azul encontrados no log System."
        }
    } catch {
        Registrar-Observacao "Nao foram encontrados eventos recentes de travamento/tela azul ou o log nao pode ser consultado."
    }

    Registrar-Observacao "Diagnostico de Memoria do Windows deve ser executado sob demanda quando houver travamentos ou suspeita fisica."
}

function Verificar-Seguranca {
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        Write-Host "Defender ativo: $($mp.AntivirusEnabled)"
        Write-Host "Assinatura AV atualizada em: $($mp.AntivirusSignatureLastUpdated)"
        Write-Host "Protecao em tempo real: $($mp.RealTimeProtectionEnabled)"

        if (-not $mp.AntivirusEnabled -or -not $mp.RealTimeProtectionEnabled) {
            Registrar-Pendencia "Windows Defender ou protecao em tempo real nao esta ativa."
        }

        if ($mp.AntivirusSignatureAge -gt 7) {
            Registrar-Pendencia "Assinatura do antivirus com mais de 7 dias."
        }

        $Script:ResumoTecnico["Antivirus"] = "Defender ativo=$($mp.AntivirusEnabled), assinatura=$($mp.AntivirusSignatureLastUpdated)"
    } catch {
        Write-Warning "Get-MpComputerStatus indisponivel: $($_.Exception.Message)"

        try {
            Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntivirusProduct -ErrorAction Stop |
                ForEach-Object { Write-Host "Antivirus detectado: $($_.displayName)" }
        } catch {
            Registrar-Pendencia "Nao foi possivel validar antivirus pelo Defender nem pelo SecurityCenter2."
        }
    }

    try {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop
        foreach ($profile in $profiles) {
            Write-Host "Firewall $($profile.Name): Enabled=$($profile.Enabled)"

            if (-not $profile.Enabled) {
                Registrar-Pendencia "Firewall desabilitado no perfil $($profile.Name)."
            }
        }
    } catch {
        Registrar-Pendencia "Nao foi possivel validar perfis do Firewall."
    }

    if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
        try {
            $volumes = Get-BitLockerVolume -ErrorAction Stop
            foreach ($volume in $volumes) {
                Write-Host "BitLocker $($volume.MountPoint): $($volume.ProtectionStatus)"

                if ($volume.VolumeType -in @("OperatingSystem", "Data") -and $volume.ProtectionStatus -eq "Off") {
                    Registrar-Observacao "BitLocker desligado em $($volume.MountPoint); validar se e aplicavel pela politica corporativa."
                }
            }
        } catch {
            Registrar-Observacao "BitLocker nao pode ser consultado neste equipamento."
        }
    }
}

function Validar-Rede {
    Write-Host "Limpando cache de DNS..."
    ipconfig /flushdns

    try {
        $adaptadores = Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq "Up" }
        foreach ($adaptador in $adaptadores) {
            Write-Host "Adaptador ativo: $($adaptador.Name) - $($adaptador.InterfaceDescription) - $($adaptador.LinkSpeed)"
        }
    } catch {
        Registrar-Observacao "Adaptadores de rede nao puderam ser listados."
    }

    try {
        Resolve-DnsName "www.microsoft.com" -ErrorAction Stop | Out-Null
        Write-Host "Resolucao DNS validada."
    } catch {
        Registrar-Pendencia "Falha na resolucao DNS externa."
    }

    try {
        $testeInternet = Test-NetConnection -ComputerName "www.microsoft.com" -Port 443 -InformationLevel Quiet

        if ($testeInternet) {
            Write-Host "Conectividade HTTPS externa validada."
        } else {
            Registrar-Pendencia "Falha no teste HTTPS externo para www.microsoft.com:443."
        }
    } catch {
        Registrar-Pendencia "Nao foi possivel executar teste de conectividade HTTPS."
    }

    $vpnPattern = "VPN|GlobalProtect|Forti|AnyConnect|Cisco|Pulse|Zscaler|WireGuard|OpenVPN|TAP|WAN Miniport"

    try {
        $vpns = Get-NetAdapter -IncludeHidden -ErrorAction Stop |
            Where-Object { $_.Name -match $vpnPattern -or $_.InterfaceDescription -match $vpnPattern }

        if ($vpns) {
            foreach ($vpn in $vpns) {
                Write-Host "Adaptador VPN detectado: $($vpn.Name) - Status: $($vpn.Status)"
            }
        } else {
            Registrar-Observacao "Nenhum adaptador VPN conhecido detectado; validar VPN se aplicavel ao usuario."
        }
    } catch {
        Registrar-Observacao "Validacao de adaptadores VPN nao foi concluida."
    }

    foreach ($hostAlvo in $CorporateHosts) {
        if (-not [string]::IsNullOrWhiteSpace($hostAlvo)) {
            try {
                $ok = Test-NetConnection -ComputerName $hostAlvo -Port 443 -InformationLevel Quiet

                if ($ok) {
                    Write-Host "Sistema corporativo validado: ${hostAlvo}:443"
                } else {
                    Registrar-Pendencia "Falha de conectividade com sistema corporativo ${hostAlvo}:443."
                }
            } catch {
                Registrar-Pendencia "Nao foi possivel validar sistema corporativo $hostAlvo."
            }
        }
    }

    Registrar-Observacao "Atualizacao de politicas de rede depende das ferramentas corporativas instaladas e da VPN/perfil do usuario."
    Registrar-Resultado "Rede, DNS, conectividade externa e adaptadores VPN foram validados dentro do escopo automatizavel."
}

function Verificar-ProgramasInicializacao {
    try {
        $startup = @(Get-CimInstance Win32_StartupCommand -ErrorAction Stop)
        Write-Host "Itens de inicializacao automatica encontrados: $($startup.Count)"

        $startup |
            Select-Object -First 20 Name, Location, User |
            Format-Table -AutoSize
    } catch {
        Registrar-Observacao "Itens de inicializacao nao puderam ser consultados."
    }

    $chaves = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $apps = @(
        foreach ($chave in $chaves) {
            Get-ItemProperty -Path $chave -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName }
        }
    )

    Write-Host "Programas instalados catalogados: $($apps.Count)"
    Registrar-Observacao "Remocao de softwares desnecessarios nao e automatica; revisar lista quando houver suspeita ou baixa performance."
}

function Verificar-Performance {
    $cpu = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue |
        Measure-Object -Property LoadPercentage -Average

    if ($cpu.Count -gt 0) {
        $cpuMedia = [math]::Round($cpu.Average, 2)
        Write-Host "Uso medio de CPU no momento: $cpuMedia%"
        $Script:ResumoTecnico["CPU"] = "$cpuMedia% no momento da coleta"
    }

    try {
        $erros = @(Get-WinEvent -FilterHashtable @{
            LogName = "System"
            Level = 2
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 50 -ErrorAction Stop)

        Write-Host "Erros System nos ultimos 7 dias (amostra max. 50): $($erros.Count)"

        if ($erros.Count -gt 0) {
            Registrar-Observacao "Foram encontrados erros no log System nos ultimos 7 dias; amostra registrada no log tecnico."
            $erros | Select-Object -First 10 TimeCreated, Id, ProviderName, Message | Format-List
        }
    } catch {
        Registrar-Observacao "Logs de erro do sistema nao puderam ser avaliados."
    }

    Registrar-Resultado "Tempo de inicializacao, uso de recursos e logs basicos de erro foram avaliados."
}

function Executar-ReparosSistema {
    Get-CimInstance win32_bios | Select-Object SerialNumber
    Executar-Processo -Arquivo "DISM.exe" -Argumentos @("/Online", "/Cleanup-Image", "/ScanHealth") -Descricao "Executando DISM ScanHealth"
    Executar-Processo -Arquivo "DISM.exe" -Argumentos @("/Online", "/Cleanup-Image", "/RestoreHealth") -Descricao "Executando DISM RestoreHealth"
    Executar-Processo -Arquivo "SFC.exe" -Argumentos @("/Scannow") -Descricao "Executando SFC /Scannow"
    Registrar-Resultado "Verificacoes DISM e SFC executadas."
}

function Registrar-LimpezaFisica {
    Registrar-Observacao "Limpeza fisica, ventilacao, cabos e carregador devem ser validados presencialmente quando aplicavel."
}

function Gerar-ResumoDemanda {
    param([string]$Caminho)

    $fim = Get-Date
    $tempo = New-TimeSpan -Start $InicioExecucao -End $fim
    $horas = [math]::Round($tempo.TotalHours, 1)

    if ($horas -lt 0.1) {
        $horas = 0.1
    }

    $culture = [Globalization.CultureInfo]::GetCultureInfo("pt-BR")
    $horasTexto = $horas.ToString("0.0", $culture)
    $usuarioCompleto = $UsuarioLogado

    if (-not [string]::IsNullOrWhiteSpace($DominioUsuario)) {
        $usuarioCompleto = "$DominioUsuario\$UsuarioLogado"
    }

    $ativoDescricao = "ServiceTag $ServiceTag / Hostname $NomeMaquina"

    $atividades = foreach ($item in $Script:Checklist.Keys) {
        $marcado = " "

        if ($Script:Checklist[$item]) {
            $marcado = "X"
        }

        "($marcado) $item"
    }

    $resultado = New-Object 'System.Collections.Generic.List[string]'

    foreach ($item in $Script:Resultados) {
        [void]$resultado.Add("- $item")
    }

    if ($Script:ResumoTecnico.Count -gt 0) {
        [void]$resultado.Add("- Resumo tecnico:")

        foreach ($key in $Script:ResumoTecnico.Keys) {
            [void]$resultado.Add("  ${key}: $($Script:ResumoTecnico[$key])")
        }
    }

    [void]$resultado.Add("- Evidencia tecnica: $LogFile")

    $pendencias = New-Object 'System.Collections.Generic.List[string]'

    foreach ($item in $Script:Pendencias) {
        [void]$pendencias.Add("- $item")
    }

    foreach ($item in $Script:Observacoes) {
        [void]$pendencias.Add("- Obs: $item")
    }

    if ($pendencias.Count -eq 0) {
        [void]$pendencias.Add("Sem pendencias identificadas pelo procedimento automatizado.")
    }

    $impacto = "Sem impacto relevante para o usuario; pode ocorrer lentidao temporaria durante updates, verificacoes e limpeza."

    if ($Script:ReinicioPendente) {
        $impacto = "Sem impacto permanente. Reinicio recomendado para concluir atualizacoes/reparos pendentes."
    }

    $linhas = @(
        "Realizada manutencao preventiva no ""$ativoDescricao"" do usuario ""$usuarioCompleto"".",
        "",
        "Atividades executadas:",
        ""
    ) + $atividades + @(
        "",
        "Resultado da atividade:",
        ""
    ) + $resultado + @(
        "",
        "Pendencias/observacoes:",
        ""
    ) + $pendencias + @(
        "",
        "Impacto da atividade:",
        "",
        $impacto,
        "",
        "Tempo tecnico utilizado:",
        "[$horasTexto horas]"
    )

    Set-Content -LiteralPath $Caminho -Value $linhas -Encoding UTF8
    return $Caminho
}

try {
    Escrever-Secao "1/12" "Verificacao geral do equipamento"
    Verificar-InformacoesGerais
    Verificar-ReinicioPendente
    Verificar-Bateria
    Marcar-Atividade "Verificacao geral do equipamento"

    Escrever-Secao "2/12" "Verificacao de disco"
    Verificar-Disco
    Marcar-Atividade "Verificacao de espaco em disco"

    Escrever-Secao "3/12" "Atualizacoes do sistema"
    Atualizar-WindowsUpdateEdrivers
    Marcar-Atividade "Execucao de Windows Update"

    Escrever-Secao "4/12" "Atualizacao de softwares corporativos"
    Atualizar-ProgramasCorporativos
    Marcar-Atividade "Atualizacao de drivers e softwares corporativos"

    Escrever-Secao "5/12" "Verificacoes de seguranca"
    Verificar-Seguranca
    Atualizar-WindowsDefender
    Marcar-Atividade "Verificacao de antivirus e seguranca do ambiente"

    Escrever-Secao "6/12" "Limpeza de arquivos temporarios e residuos"
    Limpar-WindowsUpdateCache
    Limpar-Pasta "$env:SystemRoot\Temp" | Out-Null
    Limpar-Pasta $env:TEMP | Out-Null

    if ($CleanPrefetch) {
        Limpar-Pasta "$env:SystemRoot\Prefetch" | Out-Null
    } else {
        Registrar-Observacao "C:\Windows\Prefetch nao foi limpo; use -CleanPrefetch se a limpeza opcional for aprovada."
    }

    Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue |
        Where-Object { $_.Special -eq $false -and $_.LocalPath } |
        ForEach-Object {
            $temp = Join-Path $_.LocalPath "AppData\Local\Temp"

            if (Test-Path -LiteralPath $temp) {
                Limpar-Pasta $temp | Out-Null
            }
        }

    Limpar-CacheNavegadores
    Limpar-LogsDiagnostico
    Clear-RecycleBin -Force -ErrorAction SilentlyContinue
    Registrar-Resultado "Limpeza executada em pastas permitidas: Windows Temp, cache Windows Update, Temp de usuarios, caches de navegadores fechados, logs antigos e lixeira."
    Marcar-Atividade "Limpeza de arquivos temporarios e residuos do sistema"

    Escrever-Secao "7/12" "Rede, dominio e VPN"
    $comp = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue

    if ($comp -and $comp.PartOfDomain) {
        Write-Host "Dominio: $($comp.Domain)"
    } elseif ($comp) {
        Write-Host "Equipamento fora de dominio: $($comp.Domain)"
        Registrar-Observacao "Equipamento nao esta ingressado em dominio AD."
    }

    Validar-Rede
    Marcar-Atividade "Validacao de conectividade de rede/VPN"

    Escrever-Secao "8/12" "Programas e inicializacao"
    Verificar-ProgramasInicializacao
    Registrar-Resultado "Programas instalados, aplicativos controlados e itens de inicializacao foram revisados por inventario automatizado."
    Marcar-Atividade "Testes operacionais gerais"

    Escrever-Secao "9/12" "Performance e estabilidade"
    Verificar-Memoria
    Verificar-Performance
    Marcar-Atividade "Validacao de desempenho do equipamento"

    Escrever-Secao "10/12" "Reparos DISM/SFC"
    Executar-ReparosSistema
    Marcar-Atividade "Execucao de verificacoes DISM/SFC"

    Escrever-Secao "11/12" "Servicos e boas praticas"
    Verificar-Servicos
    Registrar-LimpezaFisica
    Registrar-Resultado "Servicos principais validados e boas praticas de nao remover pastas sensiveis preservadas."

    Escrever-Secao "12/12" "Finalizacao"
    Write-Host "Manutencao concluida. Gerando resumo para card..." -ForegroundColor Green
} finally {
    try {
        $resumoGerado = Gerar-ResumoDemanda -Caminho $ResumoCardFile
        Write-Host "Resumo do card gerado em: $resumoGerado" -ForegroundColor Green
    } catch {
        Write-Warning "Falha ao gerar resumo do card: $($_.Exception.Message)"
    }

    if ($TranscriptAtivo) {
        Stop-Transcript
        $TranscriptAtivo = $false
    }
}

if (-not $Silent) {
    $choice = Read-Host "Deseja reiniciar? (S/N)"

    if ($choice -match '^[sS]') {
        Restart-Computer -Force
    }
}
