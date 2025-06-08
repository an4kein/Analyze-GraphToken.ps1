# Analyze-GraphToken.ps1
Este script PowerShell tem como objetivo auxiliar analistas ofensivos (Red Teams) na identificação rápida das permissões contidas em um token JWT do Microsoft Graph, a partir do campo `scp` (Scope). Ele decodifica o token, interpreta os escopos e sugere comandos práticos baseados nas permissões concedidas, com foco ofensivo.
