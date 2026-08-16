# Usage

All binaries live in `build/bin/x64/Release/` after a successful build (see [[Getting Started|Getting-Started]]). The general flow is: **start the logger first**, then launch or attach the target.

## 1. Start the logger

```bat
BirriLogger.exe
```

Options:

| Flag | Meaning |
|---|---|
| `--timeout <seconds>` | How long an unfinished transaction/stream waits before being rendered as timed out. Default `300`. |

The logger is a single-instance app: a second `BirriLogger.exe` exits immediately with `another BirriLogger instance is already running` (guarded by a named mutex). Press `Ctrl+C` to stop it cleanly; pending transactions are flushed on shutdown.

**Console channels matter:**

- **stdout** — rendered traffic (the `TRANSACTION` / `SCHANNEL` blocks).
- **stderr** — startup line and per-message debug lines, e.g. `[dbg] type=2 id=7 pid=1234`. If you redirect output, capture stderr separately or you will miss diagnostics.

## 2. Capture traffic

**Method A — start a fresh target (recommended):**

```bat
BirriLauncher.exe C:\path\to\target.exe [target args...]
```

The launcher starts the target suspended, injects the DLL, waits for the hooks-ready handshake (10 s timeout), then resumes. Capture is live from the first instruction of the target — no startup traffic is lost.

**Method B — attach to an already-running process:**

```bat
BirriLauncher.exe --pid <pid>
```

The launcher opens the process (`PROCESS_ALL_ACCESS`, falling back to minimal rights if denied), injects, and waits for the handshake (5 s timeout). Traffic generated *before* injection is not captured.

Other flags: `BirriLauncher.exe --help` (or `-h`) prints usage.

The DLL is located next to `BirriLauncher.exe` and must be `BirriMonitor.dll`; if the file is missing the launcher reports `BirriMonitor.dll not found` and exits.

## 3. Read the output — WinHTTP transactions

Each completed HTTP request/response pair is one `TRANSACTION` block. A transaction is printed when its response finishes (all bytes read, or the request handle closed). A realistic example, exactly as the logger renders it:

```text
+----[ TRANSACTION #2 ]----+ 2026-08-16 20:54:55.552
| REQUEST
|   Method  : GET
|   URL     : https://127.0.0.1:8443/
|   Protocol: HTTP/1.1
|   Headers :
|     Host  : 127.0.0.1:8443
|   Body    : (none)
|
| RESPONSE
|   Status  : 200 OK
|   Protocol: HTTP/1.1
|   Headers :
|     Connection      : close
|     Content-Length  : 31
|     Content-Type    : application/json
|   Body    :
|     {"ok":true,"from":"tls_server"}
+------------------------------------------+ 18.00ms
```

Reading it:

- **Header line** — `+----[ TRANSACTION #N ]----+ <start timestamp>`. Numbers are display sequence, not request IDs.
- **REQUEST** — method, the full rebuilt URL (`scheme://host:port/path?query`, port always shown), protocol, headers, and body. A request with no body prints `Body : (none)`.
- **RESPONSE** — status line and protocol (parsed from the raw headers the DLL reads via `WinHttpQueryHeaders`), headers, and body. Response bodies are automatically **decompressed** (`gzip`/`deflate` via zlib, `br` via brotli) and **de-chunked** if the server used chunked transfer. If decompression fails, the raw body is shown with `(decompression failed, showing raw)`.
- **Footer** — elapsed request→response time (`12.34ms` or `2.31s`).
- Long bodies are capped at 64 KiB on screen with `... (truncated, full in debug log)`.
- Bodies truncated at capture time (over the 64 MiB per-direction cap in the DLL) show `(truncated at source, total N bytes)`.

If a response never arrives within the timeout window, the block is rendered with `Status : (no response - timed out or connection lost)`.

## 4. Read the output — Schannel/SSPI streams

Applications that do TLS directly through SSPI (not via WinHTTP) produce `SCHANNEL` blocks instead. These capture the plaintext at the `EncryptMessage`/`DecryptMessage` boundary, so a stream is reconstructed even when the underlying protocol is not HTTP.

An HTTP stream over Schannel, as rendered:

```text
+----[ SCHANNEL #1 ]----+ 2026-08-16 20:55:01.234
| REQUEST (est.)
|   Stream  : 0x481036337152
|   Target  : 127.0.0.1
|   Data    :
|     GET /?marker=T0 HTTP/1.1
|     Host: 127.0.0.1:8443
|     Connection: close
|
| RESPONSE (parsed)
|   Status  : 200 OK
|   Protocol: HTTP/1.1
|   Headers :
|     Content-Type    : application/json
|     Content-Length  : 31
|     Connection      : close
|   Body    :
|     {"ok":true,"from":"tls_server"}
+------------------------------------------+ 12.34ms
```

Reading it:

- **`REQUEST (est.)`** — the stream is not parsed as HTTP; the raw plaintext sent by the app is shown under `Data`. `(est.)` flags that this is an estimate of the request, not a parsed one.
- **`Stream`** — the stream ID, printed as `0x` followed by the numeric ID (`(thread_id << 32) | seq`). Use it to tell concurrent streams apart.
- **`Target`** — the SNI hostname the app passed to `InitializeSecurityContextW` (`pszTargetName`), or `(schannel-tls)` if none was available.
- **`RESPONSE (parsed)`** — the receive direction *is* parsed when it looks like HTTP: status line, headers, and body, with the same decompression/de-chunking as WinHTTP transactions.
- When the response is not HTTP at all, the logger does not try to parse it. It prints a note and a hex preview of the first 32 bytes instead:

```text
| RESPONSE (parsed)
|   Note    : (non-HTTP schannel stream)
|   Hex     : 52 41 57 2D 45 43 48 4F 20 31 32 33 34 35 36 37 38 39 30 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D |RAW-ECHO-0123456789abcdefghijklm|
```

This is the only hex output in the whole tool — a deliberate exception for streams that carry no parseable structure. A stream with nothing received shows `Status : (none)`, or `(no response - timed out or connection lost)` after the timeout.

## 5. A worked smoke test

```powershell
# Terminal 1 — local TLS server (creates a CurrentUser self-signed CN=localhost cert on first run;
# no admin rights needed). -Count 3 = serve 3 connections then exit.
powershell -File tests\tls_server.ps1 -Port 8443 -Count 3

# Terminal 2 — logger
build\bin\x64\Release\BirriLogger.exe

# Terminal 3 — Method A launch of the test client.
# --winhttp   : also open one HTTPS request via WinHTTP in the same process (dual-layer demo)
# --delay-ms 1500 : pause after credential acquisition so the late-binding Schannel hooks
#                   are installed before the local handshake completes
build\bin\x64\Release\BirriLauncher.exe build\bin\x64\Release\SspiTarget.exe 127.0.0.1 8443 --winhttp --delay-ms 1500
```

`SspiTarget.exe` itself is a standalone client with these flags:

```text
SspiTarget.exe <host> <port> [--send] [--winhttp] [--count N] [--threads N] [--marker M] [--delay-ms N]
```

- default: one direct SSPI/Schannel HTTP request over TLS
- `--send` (alias `/raw`): send a non-HTTP raw payload (rendered as the hex-preview case above)
- `--winhttp`: also issue one WinHTTP HTTPS request in the same process
- `--count N` / `--threads N` / `--marker M`: repeat counts, concurrency, and per-thread scenario markers
- `--delay-ms N`: sleep after credential acquisition so the late-bind Schannel hooks install first (see [[Known Limitations|Known-Limitations]])

## If something is denied

The launcher prints detailed diagnostics whenever injection fails — see [[Permissions and Injection|Permissions-and-Injection]] for the symptom → cause → remedy table. The two most common startup mistakes: the logger is not running (the handshake times out because the DLL cannot connect to the pipe), and the launcher is not elevated for an elevated target.
