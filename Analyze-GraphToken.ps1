function Decode-JWT {
    param ([string]$Token)

    $payload = $Token.Split('.')[1]
    $padded = $payload + '=' * ((4 - $payload.Length % 4) % 4)
    $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($padded))
    return $decoded | ConvertFrom-Json
}

function Analyze-GraphToken {
    param ([string]$Token)

    $decoded = Decode-JWT -Token $Token

    Write-Host "`n[+] Token para: $($decoded.aud)" -ForegroundColor Cyan
    Write-Host "[+] Emitido por: $($decoded.iss)"
    Write-Host "[+] Tipo de Token: " -NoNewline
    if ($decoded.appid) {
        Write-Host "Application Token" -ForegroundColor Yellow
    } else {
        Write-Host "Delegated Token" -ForegroundColor Green
    }

    if ($decoded.scp) {
        $scopes = $decoded.scp -split ' '
        Write-Host "`n[+] Escopos (scp):"
        $scopes | ForEach-Object { Write-Host " - $_" }

        # Dicionário: escopo → ação + comentário ofensivo
        $actionsMap = @{
            "User.Read"              = "Get-MgUser -UserId <me> # Verifica informações básicas da conta comprometida"
            "User.ReadBasic.All"     = "Get-MgUser # Enumeração parcial de usuários no diretório"
            "User.Read.All"          = "Get-MgUser -All # Enumeração completa de todos os usuários, ideal para mapeamento de alvos"
            "Group.Read.All"         = "Get-MgGroup -All # Enumeração de grupos, possível pivot para descobrir grupos privilegiados"
            "Directory.Read.All"     = "Get-MgUser / Get-MgGroup / Get-MgServicePrincipal # Permite completa enumeração de objetos no tenant"
            "Mail.Read"              = "Get-MgUserMessage -UserId <id> # Leitura de e-mails — possível exfiltração de dados sensíveis"
            "Calendars.Read"         = "Get-MgUserCalendar -UserId <id> # Acesso a calendários, ideal para espionagem corporativa"
            "Application.Read.All"   = "Get-MgApplication -All # Enumeração de apps registrados — possível targeting para consent abuse"
            "Application.ReadWrite.All" = "New-MgApplication / Remove-MgApplication # Criação ou clonagem de apps para obter tokens — uso em consent phishing"
            "Device.Read.All"        = "Get-MgDevice -All # Enumeração de dispositivos unidos ao tenant, útil para mapeamento e movimento lateral"
            "User.Export.All"        = "Export-MgReportUserCredentialUsageDetails # Exfiltração massiva de dados de usuários"
            "IdentityRiskEvent.Read.All" = "Get-MgRiskDetection # Acesso a alertas e eventos de risco — útil para antiforense"
            "DeviceManagementConfiguration.Read.All"     = "# Permite ler políticas de gerenciamento de dispositivos (Intune). Útil para entender regras de conformidade e segurança aplicadas"
            "DeviceManagementConfiguration.ReadWrite.All" = "# Permite leitura e modificação das configurações de gerenciamento de dispositivos. Pode ser usado para enfraquecer políticas de segurança (ex: afrouxar compliance)"
            "ServicePrincipalEndpoint.Read.All"          = "# Escopo raro, possivelmente relacionado à leitura de endpoints de SPNs. Útil para entender interações entre apps e APIs (pouco documentado publicamente)"

        }

        Write-Host "`n[+] Ações recomendadas com base nos escopos:"
        foreach ($scope in $scopes) {
            if ($actionsMap.ContainsKey($scope)) {
                Write-Host " - $scope → $($actionsMap[$scope])" -ForegroundColor Green
            } else {
                Write-Host " - $scope → [Escopo desconhecido no mapa]" -ForegroundColor Yellow
            }
        }
    }
    elseif ($decoded.roles) {
        Write-Host "`n[+] Roles encontradas:"
        $decoded.roles | ForEach-Object { Write-Host " - $_" }
    }
    else {
        Write-Host "`n[!] Nenhum campo 'scp' ou 'roles' encontrado." -ForegroundColor Red
    }
}
