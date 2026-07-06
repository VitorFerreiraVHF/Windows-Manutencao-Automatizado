<#
    Complemento local de manutencao BIT.
    Este arquivo contem rotinas especificas da empresa e deve ficar fora do Git.
#>

param(
    [string]$NomeUsuario = $env:USERNAME,
    [string]$ServiceTag = "",
    [string]$LogFolder = (Join-Path $PSScriptRoot "..\Logs"),
    [string]$AbsoluteMsiPath = "",
    [string]$ReportFolder = (Join-Path $PSScriptRoot "..\Relatorios"),
    [int]$NetworkScriptTimeoutSeconds = 300,
    [ValidateSet("SIM", "NAO")]
    [string]$DryRunAbsoluteStatus = "NAO",
    [switch]$DryRun
)

$ErrorActionPreference = "Continue"

function Get-SafeFileName {
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

function Get-ServiceTagLocal {
    if (-not [string]::IsNullOrWhiteSpace($ServiceTag)) {
        return $ServiceTag
    }

    try {
        $serial = Get-CimInstance Win32_BIOS -ErrorAction Stop | Select-Object -ExpandProperty SerialNumber

        if (-not [string]::IsNullOrWhiteSpace($serial)) {
            return $serial
        }
    } catch {}

    return "SEM_SERVICE_TAG"
}

function Invoke-AbsoluteInstall {
    param(
        [string]$MsiPath,
        [string]$InstallLog
    )

    if (Test-AbsoluteInstalled) {
        Write-Host "Absolute Full Agent ja consta instalado." -ForegroundColor Green
        return "SIM"
    }

    if (-not (Test-Path -LiteralPath $MsiPath)) {
        Write-Warning "Instalador Absolute nao encontrado: $MsiPath"
        return "NAO"
    }

    Write-Host "Instalando Absolute em modo silencioso..." -ForegroundColor Yellow
    Write-Host "MSI: $MsiPath"

    $arguments = "/i `"$MsiPath`" /qn /norestart /L*v `"$InstallLog`""

    try {
        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $arguments -Wait -PassThru -WindowStyle Hidden
        Write-Host "msiexec retornou codigo: $($process.ExitCode)"

        if ($process.ExitCode -in @(0, 3010)) {
            return "SIM"
        }

        return "NAO"
    } catch {
        Write-Warning "Falha ao executar instalador Absolute: $($_.Exception.Message)"
        return "NAO"
    }
}

function Test-AbsoluteInstalled {
    $uninstallKeys = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($key in $uninstallKeys) {
        $found = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -match "Absolute Full Agent|Absolute" } |
            Select-Object -First 1

        if ($found) {
            return $true
        }
    }

    $services = @("rpcnet", "ctes", "Absolute")

    foreach ($serviceName in $services) {
        if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
            return $true
        }
    }

    return $false
}

function Invoke-NetworkScript {
    param(
        [string]$ScriptPath,
        [int]$TimeoutSeconds = 300,
        [string]$OutputLog = ""
    )

    Write-Host "Executando script de rede: $ScriptPath" -ForegroundColor Yellow

    if (-not (Test-Path -Path $ScriptPath)) {
        Write-Warning "Script de rede nao encontrado ou inacessivel: $ScriptPath"
        return
    }

    try {
        $redirectOut = $null
        $redirectErr = $null

        if (-not [string]::IsNullOrWhiteSpace($OutputLog)) {
            $redirectOut = "$OutputLog.out.log"
            $redirectErr = "$OutputLog.err.log"
        }

        $arguments = @("-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $ScriptPath)
        $startInfo = @{
            FilePath = "powershell.exe"
            ArgumentList = $arguments
            PassThru = $true
            WindowStyle = "Hidden"
        }

        if ($redirectOut) {
            $startInfo.RedirectStandardOutput = $redirectOut
            $startInfo.RedirectStandardError = $redirectErr
        }

        $process = Start-Process @startInfo

        $completed = $process.WaitForExit($TimeoutSeconds * 1000)

        if (-not $completed) {
            try {
                $process.Kill()
            } catch {}

            Write-Warning "Script de rede excedeu o timeout de $TimeoutSeconds segundos e foi interrompido: $ScriptPath"
            return
        }

        if ($process.ExitCode -eq 0) {
            Write-Host "Script de rede concluido com sucesso: $ScriptPath" -ForegroundColor Green
        } else {
            Write-Warning "Script de rede retornou codigo $($process.ExitCode): $ScriptPath"
        }
    } catch {
        Write-Warning "Falha ao executar script de rede ${ScriptPath}: $($_.Exception.Message)"
    }
}

function Export-SimpleXlsx {
    param(
        [object[]]$Rows,
        [string]$Path
    )

    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $tempRoot = Join-Path $env:TEMP ("xlsx_absolute_" + [guid]::NewGuid().ToString("N"))
    $relsDir = Join-Path $tempRoot "_rels"
    $xlDir = Join-Path $tempRoot "xl"
    $xlRelsDir = Join-Path $xlDir "_rels"
    $worksheetsDir = Join-Path $xlDir "worksheets"

    New-Item -ItemType Directory -Path $relsDir, $xlRelsDir, $worksheetsDir -Force | Out-Null

    function Escape-XmlText {
        param([string]$Text)
        return [System.Security.SecurityElement]::Escape([string]$Text)
    }

    function New-InlineCell {
        param(
            [string]$Column,
            [int]$RowNumber,
            [string]$Value
        )

        $safe = Escape-XmlText $Value
        return "<c r=`"$Column$RowNumber`" t=`"inlineStr`"><is><t>$safe</t></is></c>"
    }

    $headers = @("Nome", "service teg", "Absolute status")
    $rowXml = New-Object System.Text.StringBuilder
    [void]$rowXml.Append("<row r=`"1`">")
    [void]$rowXml.Append((New-InlineCell -Column "A" -RowNumber 1 -Value $headers[0]))
    [void]$rowXml.Append((New-InlineCell -Column "B" -RowNumber 1 -Value $headers[1]))
    [void]$rowXml.Append((New-InlineCell -Column "C" -RowNumber 1 -Value $headers[2]))
    [void]$rowXml.Append("</row>")

    $rowNumber = 2

    foreach ($row in $Rows) {
        [void]$rowXml.Append("<row r=`"$rowNumber`">")
        [void]$rowXml.Append((New-InlineCell -Column "A" -RowNumber $rowNumber -Value $row.Nome))
        [void]$rowXml.Append((New-InlineCell -Column "B" -RowNumber $rowNumber -Value $row."service teg"))
        [void]$rowXml.Append((New-InlineCell -Column "C" -RowNumber $rowNumber -Value $row."Absolute status"))
        [void]$rowXml.Append("</row>")
        $rowNumber++
    }

    $lastRow = [math]::Max(1, $rowNumber - 1)
    $dimension = "A1:C$lastRow"

    $contentTypes = @'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
</Types>
'@

    $rootRels = @'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>
'@

    $workbook = @'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    <sheet name="Absolute" sheetId="1" r:id="rId1"/>
  </sheets>
</workbook>
'@

    $workbookRels = @'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>
'@

    $styles = @'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <fonts count="1"><font><sz val="11"/><name val="Calibri"/></font></fonts>
  <fills count="1"><fill><patternFill patternType="none"/></fill></fills>
  <borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>
  <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
  <cellXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/></cellXfs>
  <cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>
</styleSheet>
'@

    $sheet = @"
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <dimension ref="$dimension"/>
  <sheetViews>
    <sheetView workbookViewId="0"/>
  </sheetViews>
  <sheetFormatPr defaultRowHeight="15"/>
  <cols>
    <col min="1" max="1" width="28" customWidth="1"/>
    <col min="2" max="2" width="24" customWidth="1"/>
    <col min="3" max="3" width="18" customWidth="1"/>
  </cols>
  <sheetData>
    $($rowXml.ToString())
  </sheetData>
  <autoFilter ref="$dimension"/>
</worksheet>
"@

    try {
        Set-Content -LiteralPath (Join-Path $tempRoot "[Content_Types].xml") -Value $contentTypes -Encoding UTF8
        Set-Content -LiteralPath (Join-Path $relsDir ".rels") -Value $rootRels -Encoding UTF8
        Set-Content -LiteralPath (Join-Path $xlDir "workbook.xml") -Value $workbook -Encoding UTF8
        Set-Content -LiteralPath (Join-Path $xlRelsDir "workbook.xml.rels") -Value $workbookRels -Encoding UTF8
        Set-Content -LiteralPath (Join-Path $xlDir "styles.xml") -Value $styles -Encoding UTF8
        Set-Content -LiteralPath (Join-Path $worksheetsDir "sheet1.xml") -Value $sheet -Encoding UTF8

        if (Test-Path -LiteralPath $Path) {
            Remove-Item -LiteralPath $Path -Force
        }

        $parent = Split-Path -Parent $Path

        if (-not (Test-Path -LiteralPath $parent)) {
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
        }

        [System.IO.Compression.ZipFile]::CreateFromDirectory($tempRoot, $Path)
    } finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force
        }
    }
}

function Update-AbsoluteReport {
    param(
        [string]$ReportDirectory,
        [string]$Nome,
        [string]$Tag,
        [string]$AbsoluteStatus
    )

    if (-not (Test-Path -LiteralPath $ReportDirectory)) {
        New-Item -ItemType Directory -Path $ReportDirectory -Force | Out-Null
    }

    $csvPath = Join-Path $ReportDirectory "Relatorio_Absolute.csv"
    $xlsxPath = Join-Path $ReportDirectory "Relatorio_Absolute.xlsx"

    $rows = @()

    if (Test-Path -LiteralPath $csvPath) {
        $rows = @(Import-Csv -LiteralPath $csvPath -Encoding UTF8)
    }

    $rows = @(
        $rows | Where-Object {
            $_."service teg" -ne $Tag -or [string]::IsNullOrWhiteSpace($Tag)
        }
    )

    $rows += [PSCustomObject]@{
        Nome = $Nome
        "service teg" = $Tag
        "Absolute status" = $AbsoluteStatus
    }

    $rows = @($rows | Sort-Object Nome, "service teg")
    $rows | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
    Export-SimpleXlsx -Rows $rows -Path $xlsxPath

    Write-Host "Relatorio Absolute atualizado: $xlsxPath" -ForegroundColor Green
}

$scriptRootResolved = Resolve-Path -LiteralPath $PSScriptRoot
$repoRoot = Split-Path -Parent $scriptRootResolved.Path
$maintenanceRoot = Split-Path -Parent $repoRoot

if ([string]::IsNullOrWhiteSpace($AbsoluteMsiPath)) {
    $AbsoluteMsiPath = Join-Path $maintenanceRoot "AbsoluteWinFullAgent\AbsoluteFullAgent.msi"
}

if (-not (Test-Path -LiteralPath $LogFolder)) {
    New-Item -ItemType Directory -Path $LogFolder -Force | Out-Null
}

$ServiceTag = Get-ServiceTagLocal
$safeMachine = Get-SafeFileName -Value $env:COMPUTERNAME -Fallback "SEM_MAQUINA"
$safeTag = Get-SafeFileName -Value $ServiceTag -Fallback "SEM_SERVICE_TAG"
$installLog = Join-Path $LogFolder "AbsoluteInstall_${safeMachine}_${safeTag}_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

Write-Host ""
Write-Host "[BIT] Rotinas corporativas locais" -ForegroundColor Cyan

if ($DryRun) {
    Write-Host "DryRun ativo: instalador Absolute e scripts de rede nao serao executados." -ForegroundColor Yellow
    $absoluteStatus = $DryRunAbsoluteStatus
} else {
    $absoluteStatus = Invoke-AbsoluteInstall -MsiPath $AbsoluteMsiPath -InstallLog $installLog
}

Update-AbsoluteReport -ReportDirectory $ReportFolder `
    -Nome $NomeUsuario `
    -Tag $ServiceTag `
    -AbsoluteStatus $absoluteStatus

if (-not $DryRun) {
    $networkLogPrefix = Join-Path $LogFolder "RedeScript_${safeMachine}_${safeTag}_$(Get-Date -Format 'yyyyMMdd_HHmmss')"

    Invoke-NetworkScript `
        -ScriptPath "\\bitpagg.com.br\netlogon\assinatoken\token.ps1" `
        -TimeoutSeconds $NetworkScriptTimeoutSeconds `
        -OutputLog "${networkLogPrefix}_token"

    Invoke-NetworkScript `
        -ScriptPath "\\bitpagg.com.br\netlogon\assinatoken\acl.ps1" `
        -TimeoutSeconds $NetworkScriptTimeoutSeconds `
        -OutputLog "${networkLogPrefix}_acl"
}

exit 0
