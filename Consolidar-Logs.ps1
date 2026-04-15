

Write-Host "=========================================="
Write-Host "Consolidador de Logs de Manutencao"
Write-Host "=========================================="
Write-Host ""

# Caminhos
$ScriptRoot = $PSScriptRoot
$LogsFolder = Join-Path $ScriptRoot "Logs"
$ArquivoSaida = Join-Path $ScriptRoot "Consolidado_Manutencao.xlsx"

# Verifica se pasta existe
if (-not (Test-Path $LogsFolder)) {
    Write-Host "Pasta Logs nao encontrada." -ForegroundColor Red
    exit
}

# Verifica modulo Excel
if (-not (Get-Module -ListAvailable -Name ImportExcel)) {

    Write-Host "Instalando modulo ImportExcel..." -ForegroundColor Yellow

    Install-Module ImportExcel -Scope CurrentUser -Force -AllowClobber
}

Import-Module ImportExcel

Write-Host "Lendo logs..." -ForegroundColor Cyan

$Resultados = @()
$Detalhes = @()

$Logs = Get-ChildItem -Path $LogsFolder -Filter "Manutencao_*.log" -ErrorAction SilentlyContinue

foreach ($Log in $Logs) {

    Write-Host "Processando: $($Log.Name)"

    $Conteudo = Get-Content $Log.FullName -Raw

    # Extrair dados do nome
    if ($Log.Name -match "Manutencao_(.+?)_(.+?)_(\d{8}_\d{4})\.log") {

        $Maquina = $Matches[1]
        $Usuario = $Matches[2]
        $Data = $Matches[3]
    }

    # Converter Data
    $DataExecucao = $null

    try {
        $DataExecucao = [datetime]::ParseExact($Data,"yyyyMMdd_HHmm",$null)
    }
    catch {}

    # Contagem
    $Erros = ($Conteudo | Select-String "ERROR|TerminatingError|Falha|Erro").Count
    $Avisos = ($Conteudo | Select-String "WARNING|AVISO").Count

    # Status
    if ($Erros -gt 0) {
        $Status = "Com Erros"
    }
    elseif ($Avisos -gt 0) {
        $Status = "Com Avisos"
    }
    else {
        $Status = "Sucesso"
    }

    # Tempo Execucao
    $TempoExecucao = ""

    $Inicio = ($Conteudo | Select-String "Hora de ini­cio").Line
    $Fim = ($Conteudo | Select-String "Hora de termino").Line

    if ($Inicio -and $Fim) {

        try {

            $InicioData = ($Inicio -split ": ")[1]
            $FimData = ($Fim -split ": ")[1]

            $InicioObj = [datetime]::ParseExact($InicioData,"yyyyMMddHHmmss",$null)
            $FimObj = [datetime]::ParseExact($FimData,"yyyyMMddHHmmss",$null)

            $TempoExecucao = ($FimObj - $InicioObj).TotalMinutes

        } catch {}
    }

    # Consolidado
    $Resultados += [PSCustomObject]@{

        Maquina = $Maquina
        Usuario = $Usuario
        Data = $DataExecucao
        Status = $Status
        Erros = $Erros
        Avisos = $Avisos
        Tempo_Minutos = [math]::Round($TempoExecucao,2)
        Arquivo = $Log.Name
    }

    # Detalhes
    $Linhas = $Conteudo | Select-String "ERROR|TerminatingError|Falha|Erro|WARNING|AVISO"

    foreach ($Linha in $Linhas) {

        $Tipo = "INFO"

        if ($Linha -match "ERROR|TerminatingError|Falha|Erro") {
            $Tipo = "ERROR"
        }

        if ($Linha -match "WARNING|AVISO") {
            $Tipo = "WARNING"
        }

        $Detalhes += [PSCustomObject]@{

            Maquina = $Maquina
            Usuario = $Usuario
            Data = $DataExecucao
            Tipo = $Tipo
            Mensagem = $Linha.Line
        }
    }
}

# Estati­sticas

$Estatisticas = @()

$Estatisticas += [PSCustomObject]@{
    Metrica = "Total Logs"
    Valor = $Resultados.Count
}

$Estatisticas += [PSCustomObject]@{
    Metrica = "Sucesso"
    Valor = ($Resultados | Where-Object Status -eq "Sucesso").Count
}

$Estatisticas += [PSCustomObject]@{
    Metrica = "Com Avisos"
    Valor = ($Resultados | Where-Object Status -eq "Com Avisos").Count
}

$Estatisticas += [PSCustomObject]@{
    Metrica = "Com Erros"
    Valor = ($Resultados | Where-Object Status -eq "Com Erros").Count
}

# Export Excel

Write-Host ""
Write-Host "Gerando Excel..." -ForegroundColor Yellow

$Resultados | Export-Excel $ArquivoSaida `
    -WorksheetName "Consolidado" `
    -AutoSize `
    -TableName "Resumo"

$Detalhes | Export-Excel $ArquivoSaida `
    -WorksheetName "Detalhes" `
    -AutoSize `
    -TableName "Erros"

$Estatisticas | Export-Excel $ArquivoSaida `
    -WorksheetName "Estatisticas" `
    -AutoSize `
    -TableName "Metricas"

Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host "Consolidacao finalizada com sucesso"
Write-Host "Arquivo gerado:"
Write-Host $ArquivoSaida
Write-Host "=========================================="