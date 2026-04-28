<#
.SYNOPSIS
    Inventário de aplicações Intune + Entra ID + Defender.
    v9 - Resolução robusta de usuário + UTF-8 BOM para acentuação correta
#>

#region ======================== CONFIGURAÇÃO ========================


$TenantId     = " "       # Ex: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
$ClientId     = " "       # App Registration Client ID
$ClientSecret = " "   # App Registration Secret

$MaxRetries        = 5
$RetryBaseDelay    = 10
$DelayEntreApps    = 300
$TamanhoBatch      = 20
$DelayEntreBatches = 5
$TokenRefreshBuffer = 300

# Consulta primaryUser/registeredUsers para devices sem UPN
$CorrelacionarViaEntraDevices = $true

$Timestamp     = Get-Date -Format 'yyyyMMdd_HHmmss'
$CsvPath       = ".\Relatorio_Aplicacoes_$Timestamp.csv"
$OutputPath    = ".\Relatorio_Aplicacoes_$Timestamp.xlsx"
$PastaParciais = ".\Parciais_$Timestamp"

# FIX: Converte todos os caminhos relativos para absolutos logo no início
$basePath      = (Get-Location).Path
$CsvPath       = Join-Path $basePath "Relatorio_Aplicacoes_$Timestamp.csv"
$OutputPath    = Join-Path $basePath "Relatorio_Aplicacoes_$Timestamp.xlsx"
$PastaParciais = Join-Path $basePath "Parciais_$Timestamp"

Write-Host "📁 Diretório de trabalho: $basePath" -ForegroundColor Gray
#endregion

#region ======================== FUNÇÕES BASE ========================

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
    param (
        [PSCustomObject]$TokenObj, [string]$TenantId, [string]$ClientId,
        [string]$ClientSecret, [int]$BufferSeconds = 300
    )
    if (-not $TokenObj) { return $null }
    if (($TokenObj.ExpiresAt - (Get-Date)).TotalSeconds -le $BufferSeconds) {
        Write-Host "      🔄 Renovando token..." -ForegroundColor Cyan
        $new = Get-ApiAccessToken $TenantId $ClientId $ClientSecret $TokenObj.Scope
        if ($new) {
            Write-Host "      ✅ Token renovado até $($new.ExpiresAt.ToString('HH:mm:ss'))" -ForegroundColor Green
            return $new
        }
    }
    return $TokenObj
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
                elseif ($response -and -not $response.value) { $allResults.Add($response) }
                $Uri = $response.'@odata.nextLink'
                $sucesso = $true
            } catch {
                $statusCode = $_.Exception.Response.StatusCode.value__
                $tentativa++
                if ($statusCode -eq 429) {
                    $retryAfter = $RetryBaseDelay * [math]::Pow(2, $tentativa - 1)
                    try {
                        $raHeader = $_.Exception.Response.Headers["Retry-After"]
                        if ($raHeader) { $retryAfter = [int]$raHeader }
                    } catch {}
                    if ($tentativa -le $MaxRetries) {
                        Write-Host ("      ⏳ 429 — aguardando {0}s..." -f [math]::Round($retryAfter)) -ForegroundColor Yellow
                        Start-Sleep -Seconds $retryAfter
                    } else { $Uri = $null; $sucesso = $true }
                } elseif ($statusCode -eq 401) {
                    Write-Host "      ⚠️  401 — token expirado" -ForegroundColor Yellow
                    $Uri = $null; $sucesso = $true
                } elseif ($statusCode -eq 404) {
                    $Uri = $null; $sucesso = $true
                } elseif ($statusCode -eq 503 -or $statusCode -eq 504) {
                    Start-Sleep -Seconds ($RetryBaseDelay * $tentativa)
                } else {
                    $Uri = $null; $sucesso = $true
                }
            }
        }
    } while ($Uri)
    return $allResults
}

# ── NOVA: Exporta CSV com UTF-8 BOM (resolve acentuação no Excel PT-BR) ────
function Export-CsvUtf8Bom {
    param (
        [Parameter(Mandatory=$true)] $InputObject,
        [Parameter(Mandatory=$true)] [string]$Path,
        [string]$Delimiter = ";"
    )
    if (-not $InputObject) { return }

    # FIX: Resolve caminho relativo para absoluto (baseado no diretório atual do PS)
    if (-not [System.IO.Path]::IsPathRooted($Path)) {
        $Path = Join-Path (Get-Location).Path $Path
    }

    # Garante que a pasta de destino existe
    $parentDir = Split-Path -Parent $Path
    if ($parentDir -and -not (Test-Path $parentDir)) {
        New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
    }

    $csvContent = $InputObject | ConvertTo-Csv -NoTypeInformation -Delimiter $Delimiter
    $utf8Bom    = New-Object System.Text.UTF8Encoding($true)
    [System.IO.File]::WriteAllLines($Path, $csvContent, $utf8Bom)
}

#endregion

#region ======================== FUNÇÃO DE RESOLUÇÃO DE USUÁRIO ========================

function Resolve-User {
    param (
        [string]$UpnIntune,
        [string]$UserIdIntune,
        [string]$NomeDispositivo,
        [string]$UsuariosDefender,
        [hashtable]$UserMap,
        [hashtable]$UserIdMap,
        [hashtable]$DeviceUserMap,
        [hashtable]$SamAccountMap
    )

    # 1. UPN Intune (trim + lower)
    if (-not [string]::IsNullOrWhiteSpace($UpnIntune)) {
        $u = $UserMap[$UpnIntune.Trim().ToLower()]
        if ($u) { return [PSCustomObject]@{ User = $u; Fonte = "1-Intune UPN" } }
    }

    # 2. userId Intune → Entra ID
    if (-not [string]::IsNullOrWhiteSpace($UserIdIntune)) {
        $u = $UserIdMap[$UserIdIntune]
        if ($u) { return [PSCustomObject]@{ User = $u; Fonte = "2-Intune UserId" } }
    }

    # 3. Dispositivo → usuário (Entra ID primaryUser/registered)
    if (-not [string]::IsNullOrWhiteSpace($NomeDispositivo)) {
        $upnEntra = $DeviceUserMap[$NomeDispositivo.ToLower()]
        if ($upnEntra) {
            $u = $UserMap[$upnEntra.ToLower()]
            if ($u) { return [PSCustomObject]@{ User = $u; Fonte = "3-Entra Device" } }
        }
    }

    # 4. Defender loggedOnUsers — parse DOMAIN\user ou user@domain
    if (-not [string]::IsNullOrWhiteSpace($UsuariosDefender)) {
        $candidatos = $UsuariosDefender -split ";\s*"
        foreach ($cand in $candidatos) {
            $cand = $cand.Trim()
            if ([string]::IsNullOrWhiteSpace($cand)) { continue }
            if ($cand -match '^(system|local\s*service|network\s*service|admin|administrator)$') { continue }

            $sam = if ($cand.Contains('\')) { ($cand -split '\\')[-1].Trim() }
                   elseif ($cand.Contains('@')) { ($cand -split '@')[0].Trim() }
                   else { $cand }

            $u = $SamAccountMap[$sam.ToLower()]
            if ($u) { return [PSCustomObject]@{ User = $u; Fonte = "4-Defender SAM" } }

            if ($cand.Contains('@')) {
                $u = $UserMap[$cand.ToLower()]
                if ($u) { return [PSCustomObject]@{ User = $u; Fonte = "4-Defender UPN" } }
            }
        }
    }

    return [PSCustomObject]@{ User = $null; Fonte = "9-Não Identificado" }
}

#endregion

#region ======================== SETUP ========================

if (-not (Test-Path $PastaParciais)) {
    New-Item -ItemType Directory -Path $PastaParciais -Force | Out-Null
}

# Força console a UTF-8 para exibir acentos corretamente
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding            = [System.Text.Encoding]::UTF8
} catch {}

Write-Host "`n╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  INVENTÁRIO v9 — Intune + Entra ID + Defender            ║" -ForegroundColor Cyan
Write-Host "║  Resolução robusta de usuário + UTF-8 BOM                ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

#endregion

#region ======================== [1/8] AUTENTICAÇÃO ========================

Write-Host "`n[1/8] Obtendo tokens..." -ForegroundColor Cyan

$GraphTokenObj = Get-ApiAccessToken $TenantId $ClientId $ClientSecret "https://graph.microsoft.com/.default"
if (-not $GraphTokenObj) { Write-Host "❌ Falha token Graph." -ForegroundColor Red; exit 1 }
Write-Host "      ✅ Graph OK (até $($GraphTokenObj.ExpiresAt.ToString('HH:mm:ss')))" -ForegroundColor Green

$DefenderTokenObj = Get-ApiAccessToken $TenantId $ClientId $ClientSecret "https://api.securitycenter.microsoft.com/.default"
if ($DefenderTokenObj) {
    Write-Host "      ✅ Defender OK (até $($DefenderTokenObj.ExpiresAt.ToString('HH:mm:ss')))" -ForegroundColor Green
}

#endregion

#region ======================== [2/8] DISPOSITIVOS INTUNE ========================

Write-Host "`n[2/8] Coletando dispositivos Intune..." -ForegroundColor Cyan
$GraphTokenObj = Get-ValidToken $GraphTokenObj $TenantId $ClientId $ClientSecret $TokenRefreshBuffer

$intuneDevices = Invoke-ApiRequestWithRetry `
    -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$select=id,deviceName,azureADDeviceId,operatingSystem,osVersion,userPrincipalName,userId,userDisplayName,emailAddress,lastSyncDateTime,complianceState,managedDeviceOwnerType&`$top=999" `
    -BearerToken $GraphTokenObj.AccessToken

Write-Host "      ✅ $($intuneDevices.Count) dispositivos." -ForegroundColor Green

$comUPN    = ($intuneDevices | Where-Object { $_.userPrincipalName }).Count
$comUserId = ($intuneDevices | Where-Object { $_.userId -and -not $_.userPrincipalName }).Count
$semNada   = ($intuneDevices | Where-Object { -not $_.userPrincipalName -and -not $_.userId }).Count
Write-Host "      📊 Com UPN: $comUPN | Só userId: $comUserId | Sem usuário: $semNada" -ForegroundColor Gray

#endregion

#region ======================== [3/8] USUÁRIOS ENTRA ID ========================

Write-Host "`n[3/8] Coletando usuários Entra ID..." -ForegroundColor Cyan
$GraphTokenObj = Get-ValidToken $GraphTokenObj $TenantId $ClientId $ClientSecret $TokenRefreshBuffer

$entraUsers = Invoke-ApiRequestWithRetry `
    -Uri "https://graph.microsoft.com/v1.0/users?`$select=id,displayName,userPrincipalName,mail,mailNickname,onPremisesSamAccountName,department,jobTitle,officeLocation,companyName,accountEnabled&`$top=999" `
    -BearerToken $GraphTokenObj.AccessToken

$userMap       = @{}
$userIdMap     = @{}
$samAccountMap = @{}

foreach ($u in $entraUsers) {
    if ($u.userPrincipalName) { $userMap[$u.userPrincipalName.Trim().ToLower()] = $u }
    if ($u.id)                { $userIdMap[$u.id] = $u }
    if ($u.onPremisesSamAccountName) {
        $samAccountMap[$u.onPremisesSamAccountName.ToLower()] = $u
    }
    if ($u.mailNickname) {
        $samAccountMap[$u.mailNickname.ToLower()] = $u
    }
    if ($u.userPrincipalName -and $u.userPrincipalName.Contains('@')) {
        $prefix = ($u.userPrincipalName -split '@')[0].Trim().ToLower()
        if (-not $samAccountMap.ContainsKey($prefix)) {
            $samAccountMap[$prefix] = $u
        }
    }
}
Write-Host "      ✅ $($entraUsers.Count) usuários | UPN: $($userMap.Count) | SAM: $($samAccountMap.Count)" -ForegroundColor Green

#endregion

#region ======================== [4/8] DEVICE → USER MAP ========================

$deviceUserMap = @{}

if ($CorrelacionarViaEntraDevices) {
    Write-Host "`n[4/8] Mapeando Dispositivo → Usuário (Entra ID + Intune primaryUser)..." -ForegroundColor Cyan
    $GraphTokenObj = Get-ValidToken $GraphTokenObj $TenantId $ClientId $ClientSecret $TokenRefreshBuffer

    $entraDevices = Invoke-ApiRequestWithRetry `
        -Uri "https://graph.microsoft.com/v1.0/devices?`$select=id,deviceId,displayName,accountEnabled&`$top=999" `
        -BearerToken $GraphTokenObj.AccessToken
    Write-Host "      ✅ $($entraDevices.Count) devices no Entra ID." -ForegroundColor Green

    $entraDeviceByAadId = @{}
    foreach ($ed in $entraDevices) {
        if ($ed.deviceId) { $entraDeviceByAadId[$ed.deviceId] = $ed }
    }

    $devicesSemUser = $intuneDevices | Where-Object {
        [string]::IsNullOrWhiteSpace($_.userPrincipalName) -and
        [string]::IsNullOrWhiteSpace($_.userId) -and
        -not [string]::IsNullOrWhiteSpace($_.deviceName)
    }
    Write-Host "      → $($devicesSemUser.Count) devices sem usuário — consultando fontes..." -ForegroundColor Gray

    $totalSem = $devicesSemUser.Count
    $cS = 0; $resolvidos = 0

    foreach ($dev in $devicesSemUser) {
        $cS++
        $GraphTokenObj = Get-ValidToken $GraphTokenObj $TenantId $ClientId $ClientSecret $TokenRefreshBuffer

        Write-Progress -Activity "Device → User lookup" `
            -Status ("Device {0}/{1} | Resolvidos: {2} | {3}" -f $cS, $totalSem, $resolvidos, $dev.deviceName) `
            -PercentComplete (($cS / $totalSem) * 100)

        $upnEncontrado = $null

        # A. Intune primaryUser
        try {
            $primUsers = Invoke-ApiRequestWithRetry `
                -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$($dev.id)/users?`$select=id,userPrincipalName,displayName" `
                -BearerToken $GraphTokenObj.AccessToken -MaxRetries 2 -RetryBaseDelay 5
            if ($primUsers -and $primUsers.Count -gt 0) {
                $first = $primUsers | Where-Object { $_.userPrincipalName } | Select-Object -First 1
                if ($first) { $upnEncontrado = $first.userPrincipalName }
            }
        } catch {}

        # B. Entra ID registeredUsers
        if (-not $upnEncontrado -and $dev.azureADDeviceId) {
            $entraDev = $entraDeviceByAadId[$dev.azureADDeviceId]
            if ($entraDev) {
                try {
                    $regUsers = Invoke-ApiRequestWithRetry `
                        -Uri "https://graph.microsoft.com/v1.0/devices/$($entraDev.id)/registeredUsers?`$select=id,userPrincipalName" `
                        -BearerToken $GraphTokenObj.AccessToken -MaxRetries 2 -RetryBaseDelay 5
                    if ($regUsers -and $regUsers.Count -gt 0) {
                        $first = $regUsers | Where-Object { $_.userPrincipalName } | Select-Object -First 1
                        if ($first) { $upnEncontrado = $first.userPrincipalName }
                    }
                } catch {}

                # C. registeredOwners
                if (-not $upnEncontrado) {
                    try {
                        $owners = Invoke-ApiRequestWithRetry `
                            -Uri "https://graph.microsoft.com/v1.0/devices/$($entraDev.id)/registeredOwners?`$select=id,userPrincipalName" `
                            -BearerToken $GraphTokenObj.AccessToken -MaxRetries 2 -RetryBaseDelay 5
                        if ($owners -and $owners.Count -gt 0) {
                            $first = $owners | Where-Object { $_.userPrincipalName } | Select-Object -First 1
                            if ($first) { $upnEncontrado = $first.userPrincipalName }
                        }
                    } catch {}
                }
            }
        }

        if ($upnEncontrado) {
            $deviceUserMap[$dev.deviceName.ToLower()] = $upnEncontrado
            $resolvidos++
        }
        Start-Sleep -Milliseconds 120
    }
    Write-Progress -Activity "Device → User lookup" -Completed
    Write-Host "      ✅ $resolvidos/$totalSem dispositivos resolvidos." -ForegroundColor Green

    if ($deviceUserMap.Count -gt 0) {
        $mapaArray = $deviceUserMap.GetEnumerator() | ForEach-Object {
            [PSCustomObject]@{ DeviceName = $_.Key; UPN = $_.Value }
        }
        Export-CsvUtf8Bom -InputObject $mapaArray `
            -Path (Join-Path $PastaParciais "DeviceUserMap.csv") -Delimiter ";"
    }
}

#endregion

#region ======================== [5/8] APPS DETECTADOS ========================

Write-Host "`n[5/8] Coletando apps detectados..." -ForegroundColor Cyan
$GraphTokenObj = Get-ValidToken $GraphTokenObj $TenantId $ClientId $ClientSecret $TokenRefreshBuffer

$detectedApps = Invoke-ApiRequestWithRetry `
    -Uri "https://graph.microsoft.com/v1.0/deviceManagement/detectedApps?`$select=id,displayName,version,sizeInByte,deviceCount&`$top=999" `
    -BearerToken $GraphTokenObj.AccessToken

Write-Host "      ✅ $($detectedApps.Count) apps distintos." -ForegroundColor Green

#endregion

#region ======================== [6/8] APPS → DISPOSITIVOS ========================

Write-Host "`n[6/8] Correlacionando apps com dispositivos..." -ForegroundColor Cyan

$intuneApps = [System.Collections.Generic.List[object]]::new()

$intuneByName = @{}
foreach ($d in $intuneDevices) {
    if ($d.deviceName) { $intuneByName[$d.deviceName.ToLower()] = $d }
}

$totalApps = $detectedApps.Count
$contador = 0; $numeroBatch = 0
$inicioCron = [System.Diagnostics.Stopwatch]::StartNew()

foreach ($app in $detectedApps) {
    $contador++; $numeroBatch++
    $GraphTokenObj = Get-ValidToken $GraphTokenObj $TenantId $ClientId $ClientSecret $TokenRefreshBuffer

    $tempoDec = [math]::Round($inicioCron.Elapsed.TotalMinutes, 1)
    $eta = if ($contador -gt 1) {
        [math]::Round(($inicioCron.Elapsed.TotalMinutes / $contador) * ($totalApps - $contador), 1)
    } else { "..." }

    Write-Progress -Activity "Apps → Dispositivos" `
        -Status ("App {0}/{1} | ⏱️ {2}min | ~{3}min | {4}" -f $contador, $totalApps, $tempoDec, $eta, $app.displayName) `
        -PercentComplete (($contador / $totalApps) * 100)

    $appDevices = Invoke-ApiRequestWithRetry `
        -Uri "https://graph.microsoft.com/v1.0/deviceManagement/detectedApps/$($app.id)/managedDevices?`$select=id,deviceName,operatingSystem,osVersion,userPrincipalName,lastSyncDateTime,complianceState" `
        -BearerToken $GraphTokenObj.AccessToken

    foreach ($dev in $appDevices) {
        $userIdResolvido = $null
        $upnResolvido = $dev.userPrincipalName
        if ($dev.deviceName) {
            $devFull = $intuneByName[$dev.deviceName.ToLower()]
            if ($devFull) {
                if (-not $upnResolvido) { $upnResolvido = $devFull.userPrincipalName }
                $userIdResolvido = $devFull.userId
            }
        }

        $intuneApps.Add([PSCustomObject]@{
            Aplicacao          = $app.displayName
            VersaoApp          = $app.version
            TamanhoKB          = [math]::Round($app.sizeInByte / 1KB, 2)
            NomeDispositivo    = $dev.deviceName
            DispositivoId      = $dev.id
            SistemaOperacional = $dev.operatingSystem
            VersaoOS           = $dev.osVersion
            UPNUsuario         = $upnResolvido
            UserIdIntune       = $userIdResolvido
            UltimaSincronia    = $dev.lastSyncDateTime
            Conformidade       = $dev.complianceState
        })
    }

    Start-Sleep -Milliseconds $DelayEntreApps

    if ($numeroBatch -ge $TamanhoBatch) {
        Write-Host ("      ⏸️  Batch {0} apps. Pausa ${1}s..." -f $contador, $DelayEntreBatches) -ForegroundColor Cyan
        if ($intuneApps.Count -gt 0) {
            Export-CsvUtf8Bom -InputObject $intuneApps `
                -Path (Join-Path $PastaParciais "Parcial_IntuneApps_batch$([math]::Ceiling($contador/$TamanhoBatch)).csv") `
                -Delimiter ";"
        }
        Start-Sleep -Seconds $DelayEntreBatches
        $numeroBatch = 0
    }
}
Write-Progress -Activity "Apps → Dispositivos" -Completed
$inicioCron.Stop()
Write-Host ("      ✅ $($intuneApps.Count) registros em {0:N1}min." -f $inicioCron.Elapsed.TotalMinutes) -ForegroundColor Green

#endregion

#region ======================== [7/8] DEFENDER ========================

Write-Host "`n[7/8] Coletando Defender..." -ForegroundColor Cyan

$defenderMachineMap = @{}
$defenderSoftware = [System.Collections.Generic.List[object]]::new()

if ($DefenderTokenObj) {
    try {
        $DefenderTokenObj = Get-ValidToken $DefenderTokenObj $TenantId $ClientId $ClientSecret $TokenRefreshBuffer
        $defenderMachines = Invoke-ApiRequestWithRetry `
            -Uri "https://api.securitycenter.microsoft.com/api/machines" `
            -BearerToken $DefenderTokenObj.AccessToken

        foreach ($m in $defenderMachines) {
            if ($m.computerDnsName) { $defenderMachineMap[$m.computerDnsName.ToLower()] = $m }
        }
        Write-Host "      ✅ $($defenderMachines.Count) máquinas." -ForegroundColor Green

        $totalM = $defenderMachines.Count; $cM = 0
        $inicioDef = [System.Diagnostics.Stopwatch]::StartNew()

        foreach ($machine in $defenderMachines) {
            $cM++
            $DefenderTokenObj = Get-ValidToken $DefenderTokenObj $TenantId $ClientId $ClientSecret $TokenRefreshBuffer

            $tD = [math]::Round($inicioDef.Elapsed.TotalMinutes, 1)
            $etaD = if ($cM -gt 1) {
                [math]::Round(($inicioDef.Elapsed.TotalMinutes / $cM) * ($totalM - $cM), 1)
            } else { "..." }

            Write-Progress -Activity "Software Defender" `
                -Status ("Máq {0}/{1} | ⏱️ {2}min | ~{3}min | {4}" -f $cM, $totalM, $tD, $etaD, $machine.computerDnsName) `
                -PercentComplete (($cM / $totalM) * 100)

            $sw = Invoke-ApiRequestWithRetry `
                -Uri "https://api.securitycenter.microsoft.com/api/machines/$($machine.id)/software" `
                -BearerToken $DefenderTokenObj.AccessToken

            foreach ($s in $sw) {
                $defenderSoftware.Add([PSCustomObject]@{
                    NomeDispositivo = $machine.computerDnsName
                    UltimoAcesso    = $machine.lastSeen
                    PlataformaOS    = $machine.osPlatform
                    VersaoOS        = $machine.osVersion
                    UltimoIP        = $machine.lastIpAddress
                    UsuariosLogados = ($machine.loggedOnUsers | ForEach-Object { $_.accountName }) -join "; "
                    Aplicacao       = $s.name
                    Fornecedor      = $s.vendor
                    VersaoApp       = $s.version
                })
            }
            Start-Sleep -Milliseconds 200
        }
        Write-Progress -Activity "Software Defender" -Completed
        $inicioDef.Stop()
        Write-Host ("      ✅ $($defenderSoftware.Count) registros em {0:N1}min." -f $inicioDef.Elapsed.TotalMinutes) -ForegroundColor Green

        if ($defenderSoftware.Count -gt 0) {
            Export-CsvUtf8Bom -InputObject $defenderSoftware `
                -Path (Join-Path $PastaParciais "Parcial_DefenderSoftware.csv") -Delimiter ";"
        }
    } catch {
        Write-Host "      ⚠️ Erro Defender: $_" -ForegroundColor Yellow
    }
}

#endregion

#region ======================== [8/8] CORRELAÇÃO FINAL ========================

Write-Host "`n[8/8] Gerando relatório..." -ForegroundColor Cyan

$relatorioFinal     = [System.Collections.Generic.List[object]]::new()
$chavesIntune       = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$estatisticasFontes = @{}

# ── Intune ──────────────────────────────────────────────────────────────────
Write-Host "      → Processando $($intuneApps.Count) registros Intune..." -ForegroundColor Gray
$cI = 0
foreach ($reg in $intuneApps) {
    $cI++
    if ($cI % 1000 -eq 0) {
        Write-Progress -Activity "Processando Intune" `
            -Status "$cI / $($intuneApps.Count)" -PercentComplete (($cI / $intuneApps.Count) * 100)
    }

    $dispLower = if ($reg.NomeDispositivo) { $reg.NomeDispositivo.ToLower() } else { "" }
    $maqDefender = $defenderMachineMap[$dispLower]
    $usuariosAtivos = ""; $ultimoAcesso = ""; $ultimoIP = ""
    if ($maqDefender) {
        $usuariosAtivos = ($maqDefender.loggedOnUsers | ForEach-Object { $_.accountName }) -join "; "
        $ultimoAcesso = $maqDefender.lastSeen
        $ultimoIP     = $maqDefender.lastIpAddress
    }

    $resolvido = Resolve-User `
        -UpnIntune $reg.UPNUsuario `
        -UserIdIntune $reg.UserIdIntune `
        -NomeDispositivo $reg.NomeDispositivo `
        -UsuariosDefender $usuariosAtivos `
        -UserMap $userMap `
        -UserIdMap $userIdMap `
        -DeviceUserMap $deviceUserMap `
        -SamAccountMap $samAccountMap

    $usuario   = $resolvido.User
    $fonteUser = $resolvido.Fonte
    $upnFinal  = if ($usuario) { $usuario.userPrincipalName } else { $reg.UPNUsuario }

    if ($estatisticasFontes.ContainsKey($fonteUser)) { $estatisticasFontes[$fonteUser]++ }
    else { $estatisticasFontes[$fonteUser] = 1 }

    if ($dispLower -and $reg.Aplicacao) {
        [void]$chavesIntune.Add("$dispLower|$($reg.Aplicacao)")
    }

    $relatorioFinal.Add([PSCustomObject]@{
        "Estação (Nome)"              = $reg.NomeDispositivo
        "Sistema Operacional"         = $reg.SistemaOperacional
        "Versão OS"                   = $reg.VersaoOS
        "Conformidade Intune"         = $reg.Conformidade
        "Última Sincronização Intune" = $reg.UltimaSincronia
        "Último Acesso (Defender)"    = $ultimoAcesso
        "Último IP"                   = $ultimoIP
        "UPN Usuário"                 = $upnFinal
        "Nome Usuário"                = $usuario.displayName
        "Conta Ativa"                 = $usuario.accountEnabled
        "Departamento"                = $usuario.department
        "Cargo"                       = $usuario.jobTitle
        "Localização / Escritório"    = $usuario.officeLocation
        "Empresa"                     = $usuario.companyName
        "Fonte do Usuário"            = $fonteUser
        "Usuários Ativos (Defender)"  = $usuariosAtivos
        "Aplicação"                   = $reg.Aplicacao
        "Versão App"                  = $reg.VersaoApp
        "Tamanho (KB)"                = $reg.TamanhoKB
        "Fonte dos Dados"             = "Intune"
    })
}
Write-Progress -Activity "Processando Intune" -Completed

# ── Defender exclusivo ──────────────────────────────────────────────────────
Write-Host "      → Processando $($defenderSoftware.Count) registros Defender..." -ForegroundColor Gray
$cD = 0; $adicionados = 0
foreach ($swDef in $defenderSoftware) {
    $cD++
    if ($cD % 1000 -eq 0) {
        Write-Progress -Activity "Processando Defender" `
            -Status "$cD / $($defenderSoftware.Count)" -PercentComplete (($cD / $defenderSoftware.Count) * 100)
    }
    if ([string]::IsNullOrWhiteSpace($swDef.NomeDispositivo)) { continue }

    $dispLower = $swDef.NomeDispositivo.ToLower()
    if ($chavesIntune.Contains("$dispLower|$($swDef.Aplicacao)")) { continue }

    $resolvido = Resolve-User `
        -UpnIntune "" -UserIdIntune "" `
        -NomeDispositivo $swDef.NomeDispositivo `
        -UsuariosDefender $swDef.UsuariosLogados `
        -UserMap $userMap -UserIdMap $userIdMap `
        -DeviceUserMap $deviceUserMap -SamAccountMap $samAccountMap

    $usuario   = $resolvido.User
    $fonteUser = $resolvido.Fonte

    if ($estatisticasFontes.ContainsKey($fonteUser)) { $estatisticasFontes[$fonteUser]++ }
    else { $estatisticasFontes[$fonteUser] = 1 }

    $relatorioFinal.Add([PSCustomObject]@{
        "Estação (Nome)"              = $swDef.NomeDispositivo
        "Sistema Operacional"         = $swDef.PlataformaOS
        "Versão OS"                   = $swDef.VersaoOS
        "Conformidade Intune"         = "Não Gerenciado (Defender Only)"
        "Última Sincronização Intune" = ""
        "Último Acesso (Defender)"    = $swDef.UltimoAcesso
        "Último IP"                   = $swDef.UltimoIP
        "UPN Usuário"                 = if ($usuario) { $usuario.userPrincipalName } else { "" }
        "Nome Usuário"                = $usuario.displayName
        "Conta Ativa"                 = $usuario.accountEnabled
        "Departamento"                = $usuario.department
        "Cargo"                       = $usuario.jobTitle
        "Localização / Escritório"    = $usuario.officeLocation
        "Empresa"                     = $usuario.companyName
        "Fonte do Usuário"            = $fonteUser
        "Usuários Ativos (Defender)"  = $swDef.UsuariosLogados
        "Aplicação"                   = $swDef.Aplicacao
        "Versão App"                  = $swDef.VersaoApp
        "Tamanho (KB)"                = ""
        "Fonte dos Dados"             = "Defender"
    })
    $adicionados++
}
Write-Progress -Activity "Processando Defender" -Completed
Write-Host "      ✅ $adicionados registros exclusivos Defender." -ForegroundColor Green
Write-Host "      ✅ Total: $($relatorioFinal.Count)" -ForegroundColor Green

#endregion

#region ======================== EXPORTAÇÃO COM ACENTUAÇÃO ========================

Write-Host "`n📤 Exportando relatórios..." -ForegroundColor Cyan

# CSV UTF-8 com BOM (Excel PT-BR lê acentos corretamente)
try {
    Export-CsvUtf8Bom -InputObject $relatorioFinal -Path $CsvPath -Delimiter ";"
    Write-Host "✅ CSV (UTF-8 BOM): $CsvPath" -ForegroundColor Green
} catch {
    Write-Host "❌ Erro CSV: $_" -ForegroundColor Red
}

# Versão ANSI (Windows-1252) como fallback
try {
    $CsvPathAnsi = $CsvPath -replace '\.csv$', '_ANSI.csv'
    $csvLines    = $relatorioFinal | ConvertTo-Csv -NoTypeInformation -Delimiter ";"
    $ansiEnc     = [System.Text.Encoding]::GetEncoding(1252)
    [System.IO.File]::WriteAllLines($CsvPathAnsi, $csvLines, $ansiEnc)
    Write-Host "✅ CSV (ANSI/1252): $CsvPathAnsi" -ForegroundColor Gray
} catch {
    Write-Host "⚠️  Erro CSV ANSI: $_" -ForegroundColor Yellow
}

# Excel (trata acentuação nativamente)
if (Get-Module -ListAvailable -Name ImportExcel) {
    try {
        $relatorioFinal | Export-Excel -Path $OutputPath `
            -WorksheetName "Inventário" `
            -AutoSize -AutoFilter -FreezeTopRow -BoldTopRow `
            -TableName "InventarioApps" -TableStyle Medium2
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
Write-Host "║        📊 RESUMO DO INVENTÁRIO          ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host "  Apps distintos (Intune)   : $($detectedApps.Count)"
Write-Host "  Dispositivos (Intune)     : $($intuneDevices.Count)"
Write-Host "  Dispositivos (Defender)   : $($defenderMachineMap.Count)"
Write-Host "  Usuários (Entra ID)       : $($entraUsers.Count)"
Write-Host "  Device→User map           : $($deviceUserMap.Count)"
Write-Host "  Total relatório           : $($relatorioFinal.Count)"

Write-Host "`n  📍 Fontes de identificação do usuário:" -ForegroundColor Cyan
$estatisticasFontes.GetEnumerator() | Sort-Object Name | ForEach-Object {
    $pct = [math]::Round(($_.Value / $relatorioFinal.Count) * 100, 1)
    $cor = if ($_.Key -like "9-*") { "Red" } elseif ($_.Key -like "1-*") { "Green" } else { "Yellow" }
    Write-Host ("     {0,-25} {1,6} ({2}%)" -f $_.Key, $_.Value, $pct) -ForegroundColor $cor
}

$comDept = ($relatorioFinal | Where-Object { $_."Departamento" }).Count
$pctDept = [math]::Round(($comDept / $relatorioFinal.Count) * 100, 1)
Write-Host "`n  🏢 Registros com departamento: $comDept ($pctDept%)" -ForegroundColor Cyan

Write-Host "`n  Top 15 Departamentos:" -ForegroundColor Cyan
$relatorioFinal | Where-Object { $_."Departamento" } |
    Group-Object "Departamento" | Sort-Object Count -Descending |
    Select-Object -First 15 |
    ForEach-Object { Write-Host ("     {0,-40} {1,6}" -f $_.Name, $_.Count) }

Write-Host "`n  💻 Top 10 Aplicações:" -ForegroundColor Cyan
$relatorioFinal | Where-Object { $_."Aplicação" } |
    Group-Object "Aplicação" | Sort-Object Count -Descending |
    Select-Object -First 10 |
    ForEach-Object { Write-Host ("     {0,-50} {1,6}" -f $_.Name, $_.Count) }

Write-Host "`n✅ Concluído!`n" -ForegroundColor Green

#endregion