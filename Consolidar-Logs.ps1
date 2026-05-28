Write-Host "=========================================="
Write-Host "Consolidador de Logs de Manutencao"
Write-Host "=========================================="
Write-Host ""

$ScriptRoot = $PSScriptRoot
$LogsFolder = Join-Path $ScriptRoot "Logs"
$ArquivoSaida = Join-Path $ScriptRoot "Consolidado_Manutencao.xlsx"

if (-not (Test-Path -LiteralPath $LogsFolder)) {
    Write-Host "Pasta Logs nao encontrada." -ForegroundColor Red
    exit 1
}

if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
    Write-Host "Instalando modulo ImportExcel..." -ForegroundColor Yellow
    Install-Module ImportExcel -Scope CurrentUser -Force -AllowClobber
}

Import-Module ImportExcel

function Converter-NomeLog {
    param([string]$Nome)

    $base = [IO.Path]::GetFileNameWithoutExtension($Nome)

    if ($base -notmatch '^Manutencao_(?<Prefixo>.+)_(?<Data>\d{8}_\d{4})$') {
        return $null
    }

    $partes = $Matches.Prefixo -split '_'
    $maquina = ""
    $usuario = ""
    $serviceTag = ""

    if ($partes.Count -ge 3) {
        $serviceTag = $partes[-1]
        $usuario = $partes[-2]
        $maquina = ($partes[0..($partes.Count - 3)] -join '_')
    } elseif ($partes.Count -eq 2) {
        $maquina = $partes[0]
        $usuario = $partes[1]
    } elseif ($partes.Count -eq 1) {
        $maquina = $partes[0]
    }

    [PSCustomObject]@{
        Maquina = $maquina
        Usuario = $usuario
        ServiceTag = $serviceTag
        DataTexto = $Matches.Data
    }
}

function Converter-DataExecucao {
    param([string]$DataTexto)

    try {
        return [datetime]::ParseExact($DataTexto, "yyyyMMdd_HHmm", $null)
    } catch {
        return $null
    }
}

function Obter-TempoExecucaoMinutos {
    param([string[]]$Linhas)

    $inicio = $Linhas | Select-String -Pattern "Start time|Hora de in|Hora de ini" | Select-Object -First 1
    $fim = $Linhas | Select-String -Pattern "End time|Hora de termino|Hora de t" | Select-Object -First 1

    if (-not $inicio -or -not $fim) {
        return $null
    }

    if ($inicio.Line -notmatch '(\d{14})' -or $fim.Line -notmatch '(\d{14})') {
        return $null
    }

    $inicioTexto = ([regex]::Match($inicio.Line, '\d{14}')).Value
    $fimTexto = ([regex]::Match($fim.Line, '\d{14}')).Value

    try {
        $inicioData = [datetime]::ParseExact($inicioTexto, "yyyyMMddHHmmss", $null)
        $fimData = [datetime]::ParseExact($fimTexto, "yyyyMMddHHmmss", $null)
        return ($fimData - $inicioData).TotalMinutes
    } catch {
        return $null
    }
}

Write-Host "Lendo logs..." -ForegroundColor Cyan

$Resultados = @()
$Detalhes = @()
$Logs = Get-ChildItem -Path $LogsFolder -Filter "Manutencao_*.log" -ErrorAction SilentlyContinue

foreach ($Log in $Logs) {
    Write-Host "Processando: $($Log.Name)"

    $dadosNome = Converter-NomeLog -Nome $Log.Name

    if (-not $dadosNome) {
        Write-Warning "Nome de log fora do padrao: $($Log.Name)"
        continue
    }

    $conteudo = Get-Content -LiteralPath $Log.FullName -Raw
    $linhas = $conteudo -split "`r?`n"

    $errosEncontrados = @($linhas | Select-String -Pattern "ERROR|TerminatingError|Falha|Erro|retornou codigo [1-9]")
    $avisosEncontrados = @($linhas | Select-String -Pattern "WARNING|AVISO|Write-Warning|Pendente|Pendencia")

    $erros = $errosEncontrados.Count
    $avisos = $avisosEncontrados.Count

    if ($erros -gt 0) {
        $status = "Com Erros"
    } elseif ($avisos -gt 0) {
        $status = "Com Avisos"
    } else {
        $status = "Sucesso"
    }

    $tempoExecucao = Obter-TempoExecucaoMinutos -Linhas $linhas
    $dataExecucao = Converter-DataExecucao -DataTexto $dadosNome.DataTexto

    $resumoCard = Get-ChildItem -Path $LogsFolder -Filter "ResumoCard_*_$($dadosNome.DataTexto).txt" -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -like "*_$($dadosNome.Usuario)_*" -and
            ($dadosNome.ServiceTag -eq "" -or $_.Name -like "*_$($dadosNome.ServiceTag)_*")
        } |
        Select-Object -First 1

    $Resultados += [PSCustomObject]@{
        Maquina = $dadosNome.Maquina
        Usuario = $dadosNome.Usuario
        ServiceTag = $dadosNome.ServiceTag
        Data = $dataExecucao
        Status = $status
        Erros = $erros
        Avisos = $avisos
        Tempo_Minutos = if ($null -ne $tempoExecucao) { [math]::Round($tempoExecucao, 2) } else { $null }
        Log = $Log.Name
        Resumo_Card = if ($resumoCard) { $resumoCard.Name } else { "" }
    }

    foreach ($linha in ($errosEncontrados + $avisosEncontrados)) {
        $tipo = "INFO"

        if ($linha.Line -match "ERROR|TerminatingError|Falha|Erro|retornou codigo [1-9]") {
            $tipo = "ERROR"
        } elseif ($linha.Line -match "WARNING|AVISO|Write-Warning|Pendente|Pendencia") {
            $tipo = "WARNING"
        }

        $Detalhes += [PSCustomObject]@{
            Maquina = $dadosNome.Maquina
            Usuario = $dadosNome.Usuario
            ServiceTag = $dadosNome.ServiceTag
            Data = $dataExecucao
            Tipo = $tipo
            Mensagem = $linha.Line
            Arquivo = $Log.Name
        }
    }
}

$Estatisticas = @(
    [PSCustomObject]@{
        Metrica = "Total Logs"
        Valor = $Resultados.Count
    },
    [PSCustomObject]@{
        Metrica = "Sucesso"
        Valor = ($Resultados | Where-Object Status -eq "Sucesso").Count
    },
    [PSCustomObject]@{
        Metrica = "Com Avisos"
        Valor = ($Resultados | Where-Object Status -eq "Com Avisos").Count
    },
    [PSCustomObject]@{
        Metrica = "Com Erros"
        Valor = ($Resultados | Where-Object Status -eq "Com Erros").Count
    }
)

if (Test-Path -LiteralPath $ArquivoSaida) {
    Remove-Item -LiteralPath $ArquivoSaida -Force
}

Write-Host ""
Write-Host "Gerando Excel..." -ForegroundColor Yellow

$Resultados | Export-Excel $ArquivoSaida `
    -WorksheetName "Consolidado" `
    -AutoSize `
    -TableName "Resumo"

$Detalhes | Export-Excel $ArquivoSaida `
    -WorksheetName "Detalhes" `
    -AutoSize `
    -TableName "Ocorrencias" `
    -Append

$Estatisticas | Export-Excel $ArquivoSaida `
    -WorksheetName "Estatisticas" `
    -AutoSize `
    -TableName "Metricas" `
    -Append

Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host "Consolidacao finalizada com sucesso"
Write-Host "Arquivo gerado:"
Write-Host $ArquivoSaida
Write-Host "=========================================="
