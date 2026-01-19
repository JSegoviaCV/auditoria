# --- CONFIGURACIÓN ---
$objetivo = "www.novatium.com.ar"
$tuNombre = "Auditoría Automática"
$puertos = @(21, 22, 25, 53, 80, 110, 143, 443, 3306, 3389)

# AJUSTE PARA GITHUB: Guardar en la carpeta actual
$reportePath = Join-Path $PSScriptRoot "Reporte_Seguridad.html"

# Configuración de red
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
} catch {}
try {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
} catch {}

Write-Host "Iniciando escaneo de puertos sobre $objetivo..." -ForegroundColor Cyan

# 1. Inteligencia de Red
try {
    $ip = [System.Net.Dns]::GetHostAddresses($objetivo) | Select-Object -First 1 -ExpandProperty IPAddressToString
} catch {
    $ip = "No resuelta"
}

# 2. Escaneo de Puertos
$resultados = New-Object System.Collections.Generic.List[PSObject]

foreach ($p in $puertos) {
    $socket = New-Object System.Net.Sockets.TcpClient
    $res = [PSCustomObject]@{ Puerto = $p; Estado = "CERRADO"; Banner = "N/A"; Riesgo = "SEGURO"; Desc = "Puerto protegido." }

    try {
        $conn = $socket.BeginConnect($objetivo, $p, $null, $null)
        $wait = $conn.AsyncWaitHandle.WaitOne(1000, $false)

        if ($wait) {
            $socket.EndConnect($conn) | Out-Null
            $res.Estado = "ABIERTO"

            # Clasificación de Riesgo
            switch ($p) {
                21   { $res.Riesgo = "CRÍTICO"; $res.Desc = "FTP: Transferencia de archivos sin cifrar." }
                22   { $res.Riesgo = "BAJO"; $res.Desc = "SSH: Acceso seguro a la terminal." }
                25   { $res.Riesgo = "MEDIO"; $res.Desc = "SMTP: Envío de correo sin cifrar." }
                53   { $res.Riesgo = "MEDIO"; $res.Desc = "DNS: Consultas de nombres de dominio." }
                80   { $res.Riesgo = "ALTO"; $res.Desc = "HTTP: Tráfico web sin cifrar." }
                110  { $res.Riesgo = "ALTO"; $res.Desc = "POP3: Recepción de correo sin cifrar." }
                143  { $res.Riesgo = "ALTO"; $res.Desc = "IMAP: Recepción de correo sin cifrar." }
                443  { $res.Riesgo = "SEGURO"; $res.Desc = "HTTPS: Tráfico web cifrado." }
                3306 { $res.Riesgo = "CRÍTICO"; $res.Desc = "MySQL: Base de datos expuesta." }
                3389 { $res.Riesgo = "CRÍTICO"; $res.Desc = "RDP: Escritorio remoto expuesto." }
            }
            $res.Banner = "Servicio detectado"
        }
    } catch {
        # El estado por defecto es CERRADO, no se necesita acción
    } finally {
        if ($socket) { $socket.Close() }
    }

    $resultados.Add($res)
}

# 3. Generación de Reporte HTML
$riesgoColor = @{
    "SEGURO" = "#28a745"
    "BAJO"   = "#17a2b8"
    "MEDIO"  = "#ffc107"
    "ALTO"   = "#fd7e14"
    "CRÍTICO"= "#dc3545"
}

$html = @"
<!DOCTYPE html>
<html lang='es'>
<head>
    <meta charset='UTF-8'>
    <title>Reporte de Seguridad - $objetivo</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f7f9; color: #333; margin: 0; padding: 20px; }
        .container { max-width: 900px; margin: auto; background-color: #fff; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.05); }
        header { background-color: #007bff; color: white; padding: 20px; border-top-left-radius: 8px; border-top-right-radius: 8px; }
        header h1 { margin: 0; font-size: 24px; }
        header p { margin: 5px 0 0; }
        .summary { padding: 20px; border-bottom: 1px solid #eee; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; padding: 12px 15px; border-bottom: 1px solid #eee; }
        th { background-color: #f8f9fa; font-weight: 600; }
        .status-open { color: #dc3545; font-weight: bold; }
        .status-closed { color: #28a745; }
        .badge { display: inline-block; padding: .25em .6em; font-size: 75%; font-weight: 700; line-height: 1; text-align: center; white-space: nowrap; vertical-align: baseline; border-radius: .25rem; color: #fff; }
        footer { text-align: center; padding: 15px; font-size: 12px; color: #777; }
    </style>
</head>
<body>
    <div class='container'>
        <header>
            <h1>Reporte de Seguridad de Puertos</h1>
            <p>Generado por $tuNombre el $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')</p>
        </header>
        <div class='summary'>
            <strong>Dominio Analizado:</strong> $objetivo<br>
            <strong>Dirección IP:</strong> $ip
        </div>
        <table>
            <thead>
                <tr>
                    <th>Puerto</th>
                    <th>Estado</th>
                    <th>Nivel de Riesgo</th>
                    <th>Descripción</th>
                </tr>
            </thead>
            <tbody>
            $($resultados | ForEach-Object {
                $statusClass = if ($_.Estado -eq 'ABIERTO') { 'status-open' } else { 'status-closed' }
                $badgeColor = $riesgoColor[$_.Riesgo]
                "<tr>" +
                "<td>$($_.Puerto)</td>" +
                "<td class='$statusClass'>$($_.Estado)</td>" +
                "<td><span class='badge' style='background-color:$badgeColor'>$($_.Riesgo)</span></td>" +
                "<td>$($_.Desc)</td>" +
                "</tr>"
            })
            </tbody>
        </table>
        <footer>
            Reporte generado automáticamente.
        </footer>
    </div>
</body>
</html>
"@

$html | Out-File -FilePath $reportePath -Encoding UTF8
Write-Host "Reporte de seguridad guardado en: $reportePath" -ForegroundColor Green
