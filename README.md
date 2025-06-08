# Graph Token Analyzer - Offensive PowerShell Script

Este script PowerShell tem como objetivo auxiliar analistas ofensivos (Red Teams) na identificação rápida das permissões contidas em um token JWT do Microsoft Graph, a partir do campo `scp` (Scope). Ele decodifica o token, interpreta os escopos e sugere comandos práticos baseados nas permissões concedidas, com foco ofensivo.

## Objetivos

- Decodificar tokens JWT (Access Tokens)
- Identificar se o token é Delegado ou de Aplicação
- Listar permissões (`scp`) encontradas
- Mapear automaticamente as permissões para ações possíveis no Microsoft Graph
- Sugerir comandos `MgGraph` com comentários ofensivos para exploração
- Acelerar a tomada de decisão em assessments de nuvem (Entra ID / M365)

## Exemplo de uso

```powershell
$token = "<cole aqui seu token JWT>"
Import-Module .\Analyze-GraphToken.ps1
Analyze-GraphToken -Token $token
```

![image](https://github.com/user-attachments/assets/d6a75867-7c72-4cbf-9db4-70657028a6ad)

## Exemplo de output
[+] Escopos (scp):
 - User.Read
 - Directory.Read.All
 - Application.Read.All

[+] Ações recomendadas com base nos escopos:
 - User.Read → Get-MgUser -UserId <me> # Verifica informações básicas da conta comprometida
 - Directory.Read.All → Get-MgUser / Get-MgGroup / Get-MgServicePrincipal # Permite completa enumeração de objetos no tenant
 - Application.Read.All → Get-MgApplication -All # Enumeração de apps registrados — possível targeting para consent abuse
