<#
.SYNOPSIS
    Inventário de APLICAÇÕES WEB/CLOUD via Defender Advanced Hunting.
    v2 - Fallback automático entre Microsoft 365 Defender e WindowsDefenderATP APIs
#>

#region ======================== CONFIGURAÇÃO ========================

$TenantId     = " "       # Ex: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
$ClientId     = " "       # App Registration Client ID
$ClientSecret = " "   # App Registration Secret

# ── Janela de análise ───────────────────────────────────────────────────────
$DiasLookback  = 30
$TopResultados = 100000

# ── Coleta ──────────────────────────────────────────────────────────────────
$ColetarCloudAppEvents   = $true
$ColetarNetworkEvents    = $true
$FiltrarDominiosInternos = $true

# ── Token ───────────────────────────────────────────────────────────────────
$TokenRefreshBuffer = 300
$MaxRetries         = 5
$RetryBaseDelay     = 10

# ── Saída ───────────────────────────────────────────────────────────────────
$Timestamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
$basePath   = (Get-Location).Path
$CsvPath       = Join-Path $basePath "Relatorio_WebApps_$Timestamp.csv"
$OutputPath    = Join-Path $basePath "Relatorio_WebApps_$Timestamp.xlsx"
$PastaParciais = Join-Path $basePath "Parciais_WebApps_$Timestamp"

if (-not (Test-Path $PastaParciais)) {
    New-Item -ItemType Directory -Path $PastaParciais -Force | Out-Null
}

try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding            = [System.Text.Encoding]::UTF8
} catch {}

#endregion

#region ======================== FUNÇÕES ========================

function Get-ApiAccessToken {
    param ([string]$TenantId, [string]$ClientId, [string]$ClientSecret, [string]$Scope)
    $body = @{
        grant_type    = "client_credentials"
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = $Scope
    }
    try {
        $r = Invoke-RestMethod -Method POST `
            -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
            -ContentType "application/x-www-form-urlencoded" -Body $body
        return [PSCustomObject]@{
            AccessToken = $r.access_token
            ExpiresAt   = (Get-Date).AddSeconds($r.expires_in)
            Scope       = $Scope
        }
    } catch {
        Write-Host "      ❌ Token: $_" -ForegroundColor Red
        return $null
    }
}

function Get-ValidToken {
    param ([PSCustomObject]$TokenObj, [string]$TenantId, [string]$ClientId,
           [string]$ClientSecret, [int]$BufferSeconds = 300)
    if (-not $TokenObj) { return $null }
    if (($TokenObj.ExpiresAt - (Get-Date)).TotalSeconds -le $BufferSeconds) {
        Write-Host "      🔄 Renovando token..." -ForegroundColor Cyan
        $new = Get-ApiAccessToken $TenantId $ClientId $ClientSecret $TokenObj.Scope
        if ($new) { return $new }
    }
    return $TokenObj
}

# ── Advanced Hunting com FALLBACK entre APIs ─────────────────────────────────
function Invoke-AdvancedHunting {
    param (
        [string]$Query,
        [string]$BearerTokenM365,
        [string]$BearerTokenWDATP,
        [int]$MaxRetries = 5
    )

    $endpoints = @(
        @{
            Nome  = "M365 Defender"
            Uri   = "https://api.security.microsoft.com/api/advancedhunting/run"
            Token = $BearerTokenM365
        },
        @{
            Nome  = "WindowsDefenderATP"
            Uri   = "https://api.securitycenter.microsoft.com/api/advancedqueries/run"
            Token = $BearerTokenWDATP
        }
    )

    foreach ($ep in $endpoints) {
        if (-not $ep.Token) { continue }

        $headers = @{
            Authorization  = "Bearer $($ep.Token)"
            "Content-Type" = "application/json"
        }
        $body = @{ Query = $Query } | ConvertTo-Json -Depth 5

        Write-Host "         🔍 Tentando via $($ep.Nome)..." -ForegroundColor Gray

        $tentativa = 0
        while ($tentativa -le $MaxRetries) {
            try {
                $response = Invoke-RestMethod -Uri $ep.Uri -Headers $headers `
                    -Method POST -Body $body -ErrorAction Stop
                Write-Host "         ✅ Sucesso via $($ep.Nome)" -ForegroundColor Green
                return $response.Results
            } catch {
                $statusCode = $_.Exception.Response.StatusCode.value__
                $tentativa++

                if ($statusCode -eq 429) {
                    $delay = 30 * $tentativa
                    Write-Host "         ⏳ 429 — aguardando ${delay}s..." -ForegroundColor Yellow
                    Start-Sleep -Seconds $delay
                } elseif ($statusCode -eq 401 -or $statusCode -eq 403) {
                    Write-Host "         ⚠️  HTTP $statusCode via $($ep.Nome) — tentando próxima API..." -ForegroundColor Yellow
                    if ($_.ErrorDetails.Message) {
                        $err = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
                        Write-Host "            $($err.error.code): $($err.error.message)" -ForegroundColor Yellow
                    }
                    break
                } else {
                    Write-Host "         ❌ Erro HTTP $statusCode via $($ep.Nome)" -ForegroundColor Red
                    if ($_.ErrorDetails.Message) {
                        $err = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
                        Write-Host "            $($err.error.code): $($err.error.message)" -ForegroundColor Yellow
                    }
                    break
                }
            }
        }
    }

    Write-Host "         ❌ Todas as APIs falharam." -ForegroundColor Red
    return @()
}

function Invoke-ApiRequestWithRetry {
    param ([string]$Uri, [string]$BearerToken, [int]$MaxRetries = 5, [int]$RetryBaseDelay = 10)
    $headers = @{ Authorization = "Bearer $BearerToken" }
    $allResults = [System.Collections.Generic.List[object]]::new()
    do {
        $tentativa = 0; $sucesso = $false
        while (-not $sucesso -and $tentativa -le $MaxRetries) {
            try {
                $response = Invoke-RestMethod -Uri $Uri -Headers $headers -Method GET -ErrorAction Stop
                if ($response.value) { $allResults.AddRange($response.value) }
                $Uri = $response.'@odata.nextLink'
                $sucesso = $true
            } catch {
                $statusCode = $_.Exception.Response.StatusCode.value__
                $tentativa++
                if ($statusCode -eq 429) {
                    Start-Sleep -Seconds ($RetryBaseDelay * [math]::Pow(2, $tentativa - 1))
                } elseif ($statusCode -eq 401 -or $statusCode -eq 404) {
                    $Uri = $null; $sucesso = $true
                } else {
                    $Uri = $null; $sucesso = $true
                }
            }
        }
    } while ($Uri)
    return $allResults
}

function Export-CsvUtf8Bom {
    param (
        [Parameter(Mandatory=$true)] $InputObject,
        [Parameter(Mandatory=$true)] [string]$Path,
        [string]$Delimiter = ";"
    )
    if (-not $InputObject) { return }
    if (-not [System.IO.Path]::IsPathRooted($Path)) {
        $Path = Join-Path (Get-Location).Path $Path
    }
    $parentDir = Split-Path -Parent $Path
    if ($parentDir -and -not (Test-Path $parentDir)) {
        New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
    }
    $csvContent = $InputObject | ConvertTo-Csv -NoTypeInformation -Delimiter $Delimiter
    $utf8Bom    = New-Object System.Text.UTF8Encoding($true)
    [System.IO.File]::WriteAllLines($Path, $csvContent, $utf8Bom)
}

function Resolve-User {
    param (
        [string]$Upn,
        [string]$UserObjectId,
        [string]$AccountName,
        [hashtable]$UserMap,
        [hashtable]$UserIdMap,
        [hashtable]$SamAccountMap
    )

    if (-not [string]::IsNullOrWhiteSpace($Upn)) {
        $u = $UserMap[$Upn.Trim().ToLower()]
        if ($u) { return [PSCustomObject]@{ User = $u; Fonte = "1-UPN" } }
    }
    if (-not [string]::IsNullOrWhiteSpace($UserObjectId)) {
        $u = $UserIdMap[$UserObjectId]
        if ($u) { return [PSCustomObject]@{ User = $u; Fonte = "2-ObjectId" } }
    }
    if (-not [string]::IsNullOrWhiteSpace($AccountName)) {
        $sam = if ($AccountName.Contains('\')) { ($AccountName -split '\\')[-1].Trim() }
               elseif ($AccountName.Contains('@')) { ($AccountName -split '@')[0].Trim() }
               else { $AccountName.Trim() }
        $u = $SamAccountMap[$sam.ToLower()]
        if ($u) { return [PSCustomObject]@{ User = $u; Fonte = "3-SAM" } }
        if ($AccountName.Contains('@')) {
            $u = $UserMap[$AccountName.ToLower()]
            if ($u) { return [PSCustomObject]@{ User = $u; Fonte = "3-UPN match" } }
        }
    }
    return [PSCustomObject]@{ User = $null; Fonte = "9-Não Identificado" }
}

#endregion

#region ======================== INÍCIO ========================

Write-Host "`n╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  INVENTÁRIO DE APLICAÇÕES WEB/CLOUD — Defender AH v2     ║" -ForegroundColor Cyan
Write-Host "║  Fallback M365 Defender ↔ WDATP + Correlação Entra ID    ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host "📁 Pasta: $basePath" -ForegroundColor Gray
Write-Host "📅 Janela: últimos $DiasLookback dias" -ForegroundColor Gray

#endregion

#region ======================== [1/5] AUTENTICAÇÃO (DUPLO TOKEN) ========================

Write-Host "`n[1/5] Obtendo tokens..." -ForegroundColor Cyan

$GraphTokenObj = Get-ApiAccessToken $TenantId $ClientId $ClientSecret "https://graph.microsoft.com/.default"
if (-not $GraphTokenObj) { Write-Host "❌ Falha token Graph." -ForegroundColor Red; exit 1 }
Write-Host "      ✅ Graph OK" -ForegroundColor Green

# Token Microsoft 365 Defender (API Threat Protection)
$M365DefenderTokenObj = Get-ApiAccessToken $TenantId $ClientId $ClientSecret "https://api.security.microsoft.com/.default"
if ($M365DefenderTokenObj) {
    Write-Host "      ✅ M365 Defender OK" -ForegroundColor Green
} else {
    Write-Host "      ⚠️  M365 Defender indisponível" -ForegroundColor Yellow
}

# Token WindowsDefenderATP (fallback)
$WDATPTokenObj = Get-ApiAccessToken $TenantId $ClientId $ClientSecret "https://api.securitycenter.microsoft.com/.default"
if ($WDATPTokenObj) {
    Write-Host "      ✅ WDATP OK (fallback)" -ForegroundColor Green
} else {
    Write-Host "      ⚠️  WDATP indisponível" -ForegroundColor Yellow
}

if (-not $M365DefenderTokenObj -and -not $WDATPTokenObj) {
    Write-Host "❌ Nenhum token Defender disponível. Encerrando." -ForegroundColor Red
    exit 1
}

#endregion

#region ======================== [2/5] USUÁRIOS ENTRA ID ========================

Write-Host "`n[2/5] Coletando usuários do Entra ID..." -ForegroundColor Cyan

$entraUsers = Invoke-ApiRequestWithRetry `
    -Uri "https://graph.microsoft.com/v1.0/users?`$select=id,displayName,userPrincipalName,mail,mailNickname,onPremisesSamAccountName,department,jobTitle,officeLocation,companyName,accountEnabled&`$top=999" `
    -BearerToken $GraphTokenObj.AccessToken

$userMap = @{}; $userIdMap = @{}; $samAccountMap = @{}
foreach ($u in $entraUsers) {
    if ($u.userPrincipalName) { $userMap[$u.userPrincipalName.Trim().ToLower()] = $u }
    if ($u.id) { $userIdMap[$u.id] = $u }
    if ($u.onPremisesSamAccountName) { $samAccountMap[$u.onPremisesSamAccountName.ToLower()] = $u }
    if ($u.mailNickname) { $samAccountMap[$u.mailNickname.ToLower()] = $u }
    if ($u.userPrincipalName -and $u.userPrincipalName.Contains('@')) {
        $prefix = ($u.userPrincipalName -split '@')[0].Trim().ToLower()
        if (-not $samAccountMap.ContainsKey($prefix)) { $samAccountMap[$prefix] = $u }
    }
}
Write-Host "      ✅ $($entraUsers.Count) usuários | UPN: $($userMap.Count) | SAM: $($samAccountMap.Count)" -ForegroundColor Green

#endregion

#region ======================== [3/5] CLOUD APPS (CloudAppEvents) ========================

$cloudAppsResult = @()

if ($ColetarCloudAppEvents) {
    Write-Host "`n[3/5] Consultando CloudAppEvents (apps SaaS/M365)..." -ForegroundColor Cyan
	
$queryCloudApps = @"
CloudAppEvents
| where Timestamp > ago(${DiasLookback}d)
| where isnotempty(Application)
| where isnotempty(AccountDisplayName) or isnotempty(AccountObjectId)
| summarize
    AccessCount    = count(),
    FirstAccess    = min(Timestamp),
    LastAccess     = max(Timestamp),
    ActionTypes    = make_set(ActionType, 10),
    IPAddresses    = make_set(IPAddress, 5),
    UserAgents     = make_set(UserAgent, 3),
    DeviceTypes    = make_set(DeviceType, 5),
    Countries      = make_set(CountryCode, 5)
    by
        Application,
        ApplicationId = tostring(ApplicationId),
        AccountDisplayName,
        AccountObjectId = tostring(AccountObjectId),
        AccountUpn = tostring(AccountId)
| order by AccessCount desc
| take ${TopResultados}
"@

    Write-Host "      → Executando query (últimos $DiasLookback dias)..." -ForegroundColor Gray
$cloudAppsResult = Invoke-AdvancedHunting `
    -Query            $queryCloudApps `
    -BearerTokenM365  $M365DefenderTokenObj.AccessToken `
    -BearerTokenWDATP $null

    Write-Host "      ✅ $(@($cloudAppsResult).Count) registros CloudAppEvents coletados." -ForegroundColor Green

    if ($cloudAppsResult -and @($cloudAppsResult).Count -gt 0) {
        Export-CsvUtf8Bom -InputObject $cloudAppsResult `
            -Path (Join-Path $PastaParciais "Parcial_CloudAppEvents.csv") -Delimiter ";"
    }
}

#endregion

#region ======================== [4/5] NETWORK EVENTS (URLs/Domínios) ========================

$networkResult = @()

if ($ColetarNetworkEvents) {
    Write-Host "`n[4/5] Consultando DeviceNetworkEvents (URLs/domínios)..." -ForegroundColor Cyan

    $filtroInterno = if ($FiltrarDominiosInternos) {
@"
| where isnotempty(RemoteUrl)
| where RemoteUrl !endswith ".local"
| where RemoteUrl !endswith ".internal"
| where RemoteUrl !endswith ".corp"
| where RemoteUrl !startswith "10."
| where RemoteUrl !startswith "192.168."
| where RemoteUrl !startswith "172.16."
| where RemoteUrl !startswith "172.17."
| where RemoteUrl !startswith "172.18."
| where RemoteUrl !startswith "172.19."
| where RemoteUrl !startswith "172.2"
| where RemoteUrl !startswith "172.30."
| where RemoteUrl !startswith "172.31."
"@
    } else { "" }

    $queryNetwork = @"
DeviceNetworkEvents
| where Timestamp > ago(${DiasLookback}d)
| where ActionType == "ConnectionSuccess"
| where RemotePort in (80, 443, 8080, 8443)
$filtroInterno
| extend Dominio = tostring(parse_url(RemoteUrl).Host)
| where isnotempty(Dominio)
| where Dominio !endswith ".local" and Dominio !endswith ".internal"
| summarize
    AccessCount = count(),
    FirstAccess = min(Timestamp),
    LastAccess  = max(Timestamp),
    URLsSample  = make_set(RemoteUrl, 3)
    by
        Dominio,
        DeviceName,
        DeviceId,
        InitiatingProcessAccountUpn,
        InitiatingProcessAccountName,
        InitiatingProcessAccountDomain,
        InitiatingProcessAccountObjectId = tostring(InitiatingProcessAccountObjectId)
| where AccessCount >= 3
| order by AccessCount desc
| take ${TopResultados}
"@

    Write-Host "      → Executando query (últimos $DiasLookback dias)..." -ForegroundColor Gray
    $networkResult = Invoke-AdvancedHunting `
        -Query            $queryNetwork `
        -BearerTokenM365  $M365DefenderTokenObj.AccessToken `
        -BearerTokenWDATP $WDATPTokenObj.AccessToken

    Write-Host "      ✅ $(@($networkResult).Count) registros DeviceNetworkEvents coletados." -ForegroundColor Green

    if ($networkResult -and @($networkResult).Count -gt 0) {
        Export-CsvUtf8Bom -InputObject $networkResult `
            -Path (Join-Path $PastaParciais "Parcial_NetworkEvents.csv") -Delimiter ";"
    }
}

#endregion

#region ======================== [5/5] CORRELAÇÃO FINAL ========================

Write-Host "`n[5/5] Correlacionando com Entra ID..." -ForegroundColor Cyan

$relatorioFinal = [System.Collections.Generic.List[object]]::new()
$estatFontes = @{}

# ── CloudAppEvents ──────────────────────────────────────────────────────────
if ($cloudAppsResult) {
    Write-Host "      → Processando $(@($cloudAppsResult).Count) Cloud Apps..." -ForegroundColor Gray
    foreach ($reg in $cloudAppsResult) {
        $resolvido = Resolve-User `
            -Upn $reg.AccountUpn `
            -UserObjectId $reg.AccountObjectId `
            -AccountName $reg.AccountDisplayName `
            -UserMap $userMap -UserIdMap $userIdMap -SamAccountMap $samAccountMap

        $usuario   = $resolvido.User
        $fonteUser = $resolvido.Fonte
        if ($estatFontes.ContainsKey($fonteUser)) { $estatFontes[$fonteUser]++ } else { $estatFontes[$fonteUser] = 1 }

        $relatorioFinal.Add([PSCustomObject]@{
            "Tipo"                        = "Cloud App"
            "Aplicação Web"               = $reg.Application
            "ID Aplicação"                = $reg.ApplicationId
            "Domínio/URL"                 = ""
            "Estação (Nome)"              = ""     # ← CloudAppEvents não tem DeviceName
            "Tipo Dispositivo"            = ($reg.DeviceTypes -join "; ")
            "Países de Acesso"            = ($reg.Countries -join "; ")
            "UPN Usuário"                 = if ($usuario) { $usuario.userPrincipalName } else { $reg.AccountUpn }
            "Nome Usuário"                = if ($usuario) { $usuario.displayName } else { $reg.AccountDisplayName }
            "Departamento"                = $usuario.department
            "Cargo"                       = $usuario.jobTitle
            "Localização / Escritório"    = $usuario.officeLocation
            "Empresa"                     = $usuario.companyName
            "Conta Ativa"                 = $usuario.accountEnabled
            "Fonte do Usuário"            = $fonteUser
            "Total de Acessos"            = $reg.AccessCount
            "Primeiro Acesso"             = $reg.FirstAccess
            "Último Acesso"               = $reg.LastAccess
            "IPs (amostra)"               = ($reg.IPAddresses -join "; ")
            "User Agents"                 = ($reg.UserAgents -join "; ")
            "Tipos de Ação"               = ($reg.ActionTypes -join "; ")
            "URLs de Exemplo"             = ""
        })
    }
}

# ── DeviceNetworkEvents ─────────────────────────────────────────────────────
if ($networkResult) {
    Write-Host "      → Processando $(@($networkResult).Count) domínios web..." -ForegroundColor Gray
    foreach ($reg in $networkResult) {
        $resolvido = Resolve-User `
            -Upn $reg.InitiatingProcessAccountUpn `
            -UserObjectId $reg.InitiatingProcessAccountObjectId `
            -AccountName $reg.InitiatingProcessAccountName `
            -UserMap $userMap -UserIdMap $userIdMap -SamAccountMap $samAccountMap

        $usuario   = $resolvido.User
        $fonteUser = $resolvido.Fonte
        if ($estatFontes.ContainsKey($fonteUser)) { $estatFontes[$fonteUser]++ } else { $estatFontes[$fonteUser] = 1 }

        $relatorioFinal.Add([PSCustomObject]@{
            "Tipo"                        = "Domínio Web"
            "Aplicação Web"               = $reg.Dominio
            "ID Aplicação"                = ""
            "Domínio/URL"                 = $reg.Dominio
            "Estação (Nome)"              = $reg.DeviceName
            "Tipo Dispositivo"            = ""
            "Países de Acesso"            = ""
            "UPN Usuário"                 = if ($usuario) { $usuario.userPrincipalName } else { $reg.InitiatingProcessAccountUpn }
            "Nome Usuário"                = if ($usuario) { $usuario.displayName } else { $reg.InitiatingProcessAccountName }
            "Departamento"                = $usuario.department
            "Cargo"                       = $usuario.jobTitle
            "Localização / Escritório"    = $usuario.officeLocation
            "Empresa"                     = $usuario.companyName
            "Conta Ativa"                 = $usuario.accountEnabled
            "Fonte do Usuário"            = $fonteUser
            "Total de Acessos"            = $reg.AccessCount
            "Primeiro Acesso"             = $reg.FirstAccess
            "Último Acesso"               = $reg.LastAccess
            "IPs (amostra)"               = ""
            "User Agents"                 = ""
            "Tipos de Ação"               = ""
            "URLs de Exemplo"             = ($reg.URLsSample -join "; ")
        })
    }
}

Write-Host "      ✅ Total de registros: $($relatorioFinal.Count)" -ForegroundColor Green

#endregion

#region ======================== EXPORTAÇÃO ========================

Write-Host "`n📤 Exportando relatórios..." -ForegroundColor Cyan

try {
    Export-CsvUtf8Bom -InputObject $relatorioFinal -Path $CsvPath -Delimiter ";"
    Write-Host "✅ CSV (UTF-8 BOM): $CsvPath" -ForegroundColor Green
} catch {
    Write-Host "❌ Erro CSV: $_" -ForegroundColor Red
}

if (Get-Module -ListAvailable -Name ImportExcel) {
    try {
        $relatorioFinal | Export-Excel -Path $OutputPath `
            -WorksheetName "WebApps" `
            -AutoSize -AutoFilter -FreezeTopRow -BoldTopRow `
            -TableName "WebAppsInventario" -TableStyle Medium2
        Write-Host "✅ Excel:           $OutputPath" -ForegroundColor Green
    } catch {
        Write-Host "⚠️  Erro Excel: $_" -ForegroundColor Yellow
    }
} else {
    Write-Host "ℹ️  Para Excel: Install-Module ImportExcel -Scope CurrentUser" -ForegroundColor Yellow
}

#endregion

#region ======================== RESUMO ========================

Write-Host "`n╔══════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║    📊 RESUMO DE APLICAÇÕES WEB          ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host "  Janela analisada       : $DiasLookback dias"
Write-Host "  Cloud Apps (SaaS/M365) : $(@($cloudAppsResult).Count)"
Write-Host "  Domínios Web           : $(@($networkResult).Count)"
Write-Host "  Usuários Entra ID      : $($entraUsers.Count)"
Write-Host "  Total relatório        : $($relatorioFinal.Count)"

if ($relatorioFinal.Count -gt 0) {
    Write-Host "`n  📍 Fontes de identificação do usuário:" -ForegroundColor Cyan
    $estatFontes.GetEnumerator() | Sort-Object Name | ForEach-Object {
        $pct = [math]::Round(($_.Value / $relatorioFinal.Count) * 100, 1)
        $cor = if ($_.Key -like "9-*") { "Red" } elseif ($_.Key -like "1-*") { "Green" } else { "Yellow" }
        Write-Host ("     {0,-25} {1,6} ({2}%)" -f $_.Key, $_.Value, $pct) -ForegroundColor $cor
    }

    Write-Host "`n  🏢 Top 15 Departamentos (web apps):" -ForegroundColor Cyan
    $relatorioFinal | Where-Object { $_."Departamento" } |
        Group-Object "Departamento" | Sort-Object Count -Descending |
        Select-Object -First 15 |
        ForEach-Object { Write-Host ("     {0,-40} {1,6}" -f $_.Name, $_.Count) }

    Write-Host "`n  🌐 Top 20 Aplicações Web / Domínios:" -ForegroundColor Cyan
    $relatorioFinal | Where-Object { $_."Aplicação Web" } |
        Group-Object "Aplicação Web" | Sort-Object Count -Descending |
        Select-Object -First 20 |
        ForEach-Object { Write-Host ("     {0,-50} {1,6} acessos" -f $_.Name, $_.Count) }

    Write-Host "`n  👤 Top 15 Usuários mais ativos:" -ForegroundColor Cyan
    $relatorioFinal | Where-Object { $_."Nome Usuário" } |
        Group-Object "Nome Usuário" | Sort-Object Count -Descending |
        Select-Object -First 15 |
        ForEach-Object { Write-Host ("     {0,-40} {1,6} apps" -f $_.Name, $_.Count) }
}

Write-Host "`n✅ Concluído!`n" -ForegroundColor Green

#endregion