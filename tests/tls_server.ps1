param(
    [int]$Port = 8443,
    [int]$DelayMs = 0,
    [int]$Count = 0
)

$ErrorActionPreference = "Stop"

$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -eq "CN=localhost" -and $_.HasPrivateKey } | Select-Object -First 1
if (-not $cert) {
    $cert = New-SelfSignedCertificate -DnsName "localhost" -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddYears(2) -KeyAlgorithm RSA -KeyLength 2048 -KeyExportPolicy Exportable -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1")
}
Write-Host "server cert: $($cert.Subject) hasPrivateKey=$($cert.HasPrivateKey)"

$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
$listener.Start()
Write-Host "tls_server listening on 127.0.0.1:$Port (delay $DelayMs ms, count $Count)"

$accepted = 0
try {
    while ($true) {
        if ($Count -gt 0 -and $accepted -ge $Count) {
            break
        }
        $client = $listener.AcceptTcpClient()
        $accepted++
        $ssl = $null
        try {
            $ssl = [System.Net.Security.SslStream]::new($client.GetStream(), $false)
            $ssl.AuthenticateAsServer($cert, $false, [System.Security.Authentication.SslProtocols]::Tls12 -bor [System.Security.Authentication.SslProtocols]::Tls13, $false)
            $ms = [System.IO.MemoryStream]::new()
            $buf = New-Object byte[] 4096
            while ($true) {
                $n = $ssl.Read($buf, 0, $buf.Length)
                if ($n -le 0) {
                    break
                }
                $ms.Write($buf, 0, $n)
                $text = [System.Text.Encoding]::ASCII.GetString($ms.ToArray())
                if ($text.Contains("`r`n`r`n")) {
                    break
                }
            }
            if ($DelayMs -gt 0) {
                Start-Sleep -Milliseconds $DelayMs
            }
            $requestText = [System.Text.Encoding]::ASCII.GetString($ms.ToArray())
            $isHttp = $requestText -match "HTTP/"
            if ($isHttp) {
                $body = '{"ok":true,"from":"tls_server"}'
                $resp = "HTTP/1.1 200 OK`r`nContent-Type: application/json`r`nContent-Length: $($body.Length)`r`nConnection: close`r`n`r`n$body"
                $respBytes = [System.Text.Encoding]::ASCII.GetBytes($resp)
                $ssl.Write($respBytes, 0, $respBytes.Length)
                $ssl.Flush()
            } else {
                $raw = [System.Text.Encoding]::ASCII.GetBytes("RAW-ECHO-0123456789abcdefghijklmnopqrstuvwxyz")
                $ssl.Write($raw, 0, $raw.Length)
                $ssl.Flush()
            }
        }
        catch {
            Write-Host "connection $accepted error: $($_.Exception.Message)"
        }
        finally {
            if ($ssl) {
                $ssl.Close()
            }
            $client.Close()
        }
    }
}
finally {
    $listener.Stop()
}
Write-Host "tls_server stopped after $accepted connection(s)"
