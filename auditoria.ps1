# --- CONFIGURACIÓN ---
$objetivo = "www.novatium.com.ar" # Puedes cambiar esto por el dominio que quieras
$tuNombre = "Jonathan Segovia"
$puertos = @(21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 1433, 3306, 3389, 5432, 8080)

# AJUSTE PARA GITHUB: Guardar en la carpeta actual
$reportePath = "$pwd\Reporte_Seguridad.html"

# Configuración de red
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

Write-Host "Iniciando auditoria sobre $objetivo..." -ForegroundColor Cyan

# 1. Inteligencia de Red
try {
    $ip = [System.Net.Dns]::GetHostAddresses($objetivo) | Select-Object -First 1 -ExpandProperty IPAddressToString
} catch { $ip = "No resuelta" }

# 2. Escaneo de Puertos (Lógica simplificada para estabilidad en la nube)
$resultados = New-Object System.Collections.Generic.List[PSObject]

foreach ($p in $puertos) {
    $socket = New-Object System.Net.Sockets.TcpClient
    $conn = $socket.BeginConnect($objetivo, $p, $null, $null)
    $wait = $conn.AsyncWaitHandle.WaitOne(1000, $false)
    
    $res = [PSCustomObject]@{ Puerto = $p; Estado = "CERRADO"; Banner = "N/A"; Riesgo = "SEGURO"; Desc = "Puerto protegido." }
    
    if ($wait) {
        $socket.EndConnect($conn)
        $res.Estado = "ABIERTO"
        # Clasificación básica
        if ($p -eq 3306 -or $p -eq 1433 -or $p -eq 21) { $res.Riesgo = "CRÍTICO"; $res.Desc = "Servicio sensible expuesto." }
        elseif ($p -eq 80) { $res.Riesgo = "ALTO"; $res.Desc = "Tráfico sin cifrar." }
        elseif ($p -eq 443) { $res.Riesgo = "SEGURO"; $res.Desc = "Tráfico HTTPS estándar." }
        $res.Banner = "Servicio detectado"
    }
    $resultados.Add($res)
    $socket.Close()
}

# 3. Generación de HTML (Diseño profesional)
$html = @"
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: sans-serif; background: #0d1117; color: #c9d1d9; padding: 20px; }
        .box { background: #161b22; border: 1px solid #30363d; padding: 20px; border-radius: 10px; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th { text-align: left; color: #58a6ff; border-bottom: 2px solid #30363d; padding: 10px; }
        td { padding: 10px; border-bottom: 1px solid #21262d; }
        .ABIERTO { color: #f85149; font-weight: bold; }
        .badge { padding: 4px 8px; border-radius: 5px; font-size: 12px; }
        .CRÍTICO { background: #f85149; color: white; }
    </style>
</head>
<body>
    <div class="box">
        <h1>Reporte de Auditoría: $objetivo</h1>
        <p>Auditor: $tuNombre | IP Detectada: $ip</p>
        <table>
            <tr><th>Puerto</th><th>Estado</th><th>Riesgo</th><th>Análisis</th></tr>
            $( $resultados | ForEach-Object { 
                "<tr><td>$($_.Puerto)</td><td class='$($_.Estado)'>$($_.Estado)</td><td><span class='badge $($_.Riesgo)'>$($_.Riesgo)</span></td><td>$($_.Desc)</td></tr>" 
            } )
        </table>
    </div>
</body>
</html>
"@

$html | Out-File $reportePath -Encoding UTF8
Write-Host "Auditoria finalizada con exito." -ForegroundColor Green