# --- CONFIGURACIÓN ADAPTADA PARA GITHUB ---
$objetivo = $env:TARGET_DOMAIN
if (-not $objetivo) { $objetivo = "google.com" } # Dominio por defecto
$tuNombre = "Jonathan Segovia"
$puertos = @(21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 1433, 3306, 3389, 5432, 8080)

# El reporte se guarda en la carpeta actual para que GitHub pueda subirlo
$reportePath = "Reporte_Seguridad.html"

# Configuración de red avanzada
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

Write-Host "`n--- INICIANDO AUDITORÍA DETALLADA: $objetivo ---" -ForegroundColor Cyan

# 1. Inteligencia de Red (IP y Geo)
try {
    $ip = [System.Net.Dns]::GetHostAddresses($objetivo) | Select-Object -First 1 -ExpandProperty IPAddressToString
    $geo = Invoke-RestMethod -Uri "https://ipapi.co/$ip/json/" -ErrorAction SilentlyContinue
} catch { $ip = "No resuelta"; $geo = @{ city="N/A"; country_name="N/A"; org="N/A" } }

# 2. Configuración de Runspaces (Multithreading)
$RunspacePool = [runspacefactory]::CreateRunspacePool(1, 15)
$RunspacePool.Open()
$Jobs = New-Object System.Collections.Generic.List[PSCustomObject]

$ScriptBlock = {
    param($obj, $p)
    $res = [PSCustomObject]@{ Puerto = $p; Estado = "CERRADO"; Banner = "N/A"; Riesgo = "SEGURO"; Desc = "Puerto protegido." }
    $socket = New-Object System.Net.Sockets.TcpClient
    $conn = $socket.BeginConnect($obj, $p, $null, $null)
    if ($conn.AsyncWaitHandle.WaitOne(1200, $false)) {
        try {
            $socket.EndConnect($conn)
            $res.Estado = "ABIERTO"
            $eval = switch ($p) {
                21   { @("CRÍTICO", "FTP: Texto plano, riesgo de robo de credenciales.") }
                80   { @("ALTO", "HTTP: Tráfico no cifrado.") }
                3306 { @("CRÍTICO", "MySQL: Base de datos expuesta.") }
                1433 { @("CRÍTICO", "MSSQL: Base de datos expuesta.") }
                3389 { @("ALTO", "RDP: Escritorio remoto expuesto.") }
                443  { @("SEGURO", "HTTPS: Tráfico cifrado estándar.") }
                default { @("REVISAR", "Servicio detectado en puerto no estándar.") }
            }
            $res.Riesgo = $eval[0]; $res.Desc = $eval[1]

            # Banner Grabbing
            if ($p -eq 80 -or $p -eq 443 -or $p -eq 8080) {
                $proto = if ($p -eq 443) { "https" } else { "http" }
                $req = [System.Net.WebRequest]::Create("${proto}://${obj}")
                $req.Timeout = 1500; $req.Method = "HEAD"
                $resp = $req.GetResponse()
                $res.Banner = $resp.Headers["Server"]
                $resp.Close()
            } else {
                $stream = $socket.GetStream(); $stream.ReadTimeout = 1000
                $buffer = New-Object Byte[] 1024
                if ($stream.CanRead) {
                    $bytes = $stream.Read($buffer, 0, $buffer.Length)
                    $res.Banner = ([System.Text.Encoding]::ASCII.GetString($buffer, 0, $bytes) -replace '[^ -~]', '').Trim()
                }
            }
        } catch { $res.Banner = "Servicio activo (Banner oculto)" }
    }
    $socket.Close(); return $res
}

# 3. Lanzamiento
foreach ($p in $puertos) {
    $ps = [powershell]::Create().AddScript($ScriptBlock).AddArgument($objetivo).AddArgument($p)
    $ps.RunspacePool = $RunspacePool
    $Jobs.Add([PSCustomObject]@{ Pipe = $ps; Result = $ps.BeginInvoke() })
}

while ($Jobs.Result.IsCompleted -contains $false) { Start-Sleep -Milliseconds 100 }
$resultados = foreach ($j in $Jobs) { $j.Pipe.EndInvoke($j.Result); $j.Pipe.Dispose() }
$RunspacePool.Close()

# 4. HTML (Simplificado para compatibilidad)
$html = @"
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: sans-serif; background: #0d1117; color: #c9d1d9; padding: 20px; }
        .dashboard { max-width: 900px; margin: auto; background: #161b22; padding: 20px; border-radius: 8px; border: 1px solid #30363d; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th { background: #21262d; padding: 10px; text-align: left; color: #58a6ff; }
        td { padding: 10px; border-bottom: 1px solid #30363d; }
        .ABIERTO { color: #f85149; font-weight: bold; }
        .CRÍTICO { background: #f85149; color: white; padding: 2px 5px; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="dashboard">
        <h1>Auditoría: $objetivo</h1>
        <p>IP: $ip | Ubicación: $($geo.city), $($geo.country_name) | Auditor: $tuNombre</p>
        <table>
            <thead>
                <tr><th>Puerto</th><th>Estado</th><th>Banner</th><th>Riesgo</th><th>Análisis</th></tr>
            </thead>
            <tbody>
                $( $resultados | Sort-Object Puerto | ForEach-Object {
                    "<tr><td>$($_.Puerto)</td><td class='$($_.Estado)'>$($_.Estado)</td><td>$($_.Banner)</td><td><span class='$($_.Riesgo)'>$($_.Riesgo)</span></td><td>$($_.Desc)</td></tr>"
                } )
            </tbody>
        </table>
    </div>
</body>
</html>
"@

$html | Out-File $reportePath -Encoding UTF8