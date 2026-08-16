# BirriMonitor

A Windows x64 network traffic monitor that captures HTTPS and TLS traffic **in user mode** by injecting a hook DLL into a target process. It observes WinHTTP API calls and Schannel/SSPI TLS streams, streams the captured data to a separate logger process over a named pipe, and renders each request/response pair as readable transactions — without a kernel driver, without a proxy, and without touching certificates.

```
BirriLauncher.exe  --inject-->  Target process  --named pipe-->  BirriLogger.exe
                                     |
                            BirriMonitor.dll (hooks)
                     WinHTTP APIs  +  Schannel/SSPI (TLS 1.2/1.3)
```

---

## Features

- **WinHTTP capture** — hooks all nine core WinHTTP entry points (`WinHttpConnect`, `WinHttpOpenRequest`, `WinHttpAddRequestHeaders`, `WinHttpSendRequest`, `WinHttpWriteData`, `WinHttpReceiveResponse`, `WinHttpQueryDataAvailable`, `WinHttpReadData`, `WinHttpCloseHandle`) to rebuild full request URLs, headers, bodies, and responses.
- **Schannel/SSPI capture** — hooks `InitializeSecurityContextW`, `EncryptMessage`, `DecryptMessage`, and `DeleteSecurityContext` to reconstruct plaintext TLS streams (including TLS 1.3), with stream correlation and SNI target extraction.
- **Two injection methods**:
  - **Method A** — start the target suspended, inject, wait for the hooks-ready handshake event, then resume (no fixed sleeps, no lost startup traffic).
  - **Method B** — inject into an already-running process by PID, with full → minimal access-right fallback.
- **Detailed permission diagnostics** — when injection is denied, the launcher reports *why* (not elevated, integrity-level mismatch, protected process, race, AV/EDR) and the right remedy.
- **Named-pipe IPC** — length-prefixed framed messages, overlapped I/O, non-blocking hook path (hooks enqueue; a background IO thread writes).
- **Response decoding** — gzip/deflate via zlib, brotli via the brotli decoder, plus defensive chunked-transfer reassembly.
- **Clean console output** — transaction + schannel stream renderers with headers, parsed bodies, hex previews for non-HTTP streams, timestamps, and durations.
- **No admin required for common cases** — Method A avoids most elevation issues; the test TLS server uses a CurrentUser self-signed certificate.

---

## Architecture

| Module | Type | Role |
|---|---|---|
| `BirriMonitor.dll` | Injectable DLL | Installs hooks, extracts buffers, sends raw data over IPC. No parsing/formatting here — the hook path stays short and fast. |
| `BirriLauncher.exe` | EXE | Starts or attaches to the target, injects the DLL, runs the handshake, diagnoses permission failures. |
| `BirriLogger.exe` | EXE | Named-pipe server; receives raw data, correlates streams, decompresses, formats, and renders traffic. |
| `HookEngine` | Static lib | Hook orchestration (MinHook), context maps, guard flags, message dispatch. |
| `IpcClient` | Static lib | Named-pipe client inside the DLL, running on its own background IO thread. |
| `IpcCommon` | Shared header | Wire protocol structs, constants, serialize/deserialize, timestamps. |

### Injection & handshake

1. The launcher creates the `Local\BirriMonitorHooksReady` named event.
2. `DllMain(PROCESS_ATTACH)` only spawns a background init thread and returns immediately (no work under the loader lock, `DisableThreadLibraryCalls` is called, state is `std::atomic`).
3. The init thread installs the WinHTTP + Schannel hooks via MinHook, connects `IpcClient` to the pipe (`\\.\pipe\BirriMonitorIpc`), then signals the event.
4. Method A waits on that event (10 s timeout) **before** resuming the suspended main thread; Method B waits a shorter timeout before reporting success.

### IPC design notes

- Hooks never block: they enqueue into a thread-safe queue; a background IO thread performs overlapped pipe writes.
- Messages are length-prefixed and validated against a max size; the logger accumulates bytes until a full frame is available before parsing (named pipes do not guarantee message-aligned reads).
- Request IDs are monotonically increasing internal counters, never raw `HINTERNET` values (which can be reused after `WinHttpCloseHandle`).
- Broken pipes cause drops in the send path; reconnection is a separate concern, never inlined into message sending.

---

## Requirements

- Windows 10/11 x64
- Visual Studio 2022 with the C++ workload (MSBuild + v143 toolset; the bundled CMake is used for third-party builds)
- PowerShell 5.1+ (for `scripts/build.ps1`)

## Building

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build.ps1
```

This configures and builds the vendored third-party libraries (MinHook, zlib, brotli — plain source copies, no downloads at build time) with CMake `-A x64 -T v143`, then builds the solution with MSBuild. Outputs land in:

```
build/bin/x64/Release/
    BirriMonitor.dll     # injectable capture engine
    BirriLauncher.exe    # injection launcher
    BirriLogger.exe      # traffic viewer / pipe server
    SspiTarget.exe       # test client (direct SSPI / WinHTTP)
```

The build is warning-clean at `/W4 /WX`.

### CI

`.github/workflows/build.yml` builds on `windows-latest`, caches the third-party build directory (keyed on `third_party/**`), verifies the expected outputs, and uploads them as a build artifact.

---

## Usage

### 1. Start the logger

```bat
BirriLogger.exe
```

Optional: `--timeout <seconds>` controls how long an unfinished transaction waits before being rendered as timed out (default 300 s). The logger refuses to run twice (single-instance mutex) and prints per-message debug lines to **stderr**; rendered traffic goes to **stdout**.

### 2. Capture traffic

**Method A — start a fresh target:**

```bat
BirriLauncher.exe C:\path\to\target.exe [target args...]
```

**Method B — attach to a running process:**

```bat
BirriLauncher.exe --pid <pid>
```

### 3. Read the output

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

Non-HTTP TLS streams are rendered as `SCHANNEL #n` blocks with a hex preview instead of parsed HTTP.

### Permission failures

When `OpenProcess` fails at both access levels, the launcher diagnoses the cause and suggests the remedy:

| Situation | Message |
|---|---|
| Launcher not elevated, target needs it | rerun the launcher as Administrator |
| Target integrity level higher than launcher | run the launcher at an equal or higher integrity level |
| Elevated + equal integrity but still denied | process is likely protected (PPL/anti-tamper) — not injectable from user mode |
| `ERROR_INVALID_PARAMETER` | the PID no longer exists (exited between enumeration and injection) |
| Everything else looks fine | possibly blocked by AV/EDR — consider an exclusion in a test environment you control |

The launcher never auto-elevates, never retries forever, and never attempts PPL/anti-tamper bypass.

---

## Testing

The repo ships two helpers for end-to-end verification:

**`SspiTarget.exe`** — a client that exercises both capture layers from one process:

```
SspiTarget.exe <host> <port> [--send] [--winhttp] [--count N] [--threads N] [--marker M] [--delay-ms N]
```

- default: direct SSPI/Schannel HTTP request over TLS
- `--send`: non-HTTP raw payload (rendered as a hex preview)
- `--winhttp`: also opens one HTTPS request via WinHTTP in the same process (dual-layer mode)
- `--count` / `--threads` / `--marker`: repeat/concurrency/scenario markers
- `--delay-ms`: sleep after credential acquire so the late-binding Schannel hooks install before a fast local handshake completes

**`tests/tls_server.ps1`** — a local TLS server (CurrentUser self-signed `CN=localhost` cert, no admin needed; keeps serving after per-connection client errors):

```powershell
powershell -File tests/tls_server.ps1 -Port 8443 -Count 2
```

### Typical smoke test

```powershell
powershell -File tests/tls_server.ps1 -Port 8443 -Count 3
BirriLogger.exe
BirriLauncher.exe build\bin\x64\Release\SspiTarget.exe 127.0.0.1 8443 --winhttp --delay-ms 1500
```

---

## Known limitations

- **Schannel hooks late-bind via polling** (the DLL hooks `secur32.dll` once it is loaded). A TLS handshake that completes faster than the poll interval can be missed — this is documented in the spec (§16.4). `SspiTarget --delay-ms` exists to make local tests deterministic.
- **Double-capture avoidance**: when a WinHTTP request rides on Schannel, only the WinHTTP transaction is reported; the raw Schannel stream underneath is suppressed to avoid duplicates.
- Traffic generated **before** injection is not captured (inherent to late attachment; Method A's suspended-start closes this window).
- User-mode capture only: no kernel driver, no PPL bypass, no system-wide coverage.

---

## Repository layout

```
.github/workflows/build.yml   CI: build + third-party cache + artifact upload
scripts/build.ps1             One-shot build (third-party + solution)
third_party/                  Vendored MinHook, zlib, brotli (+ VERSIONS.md)
src/
  IpcCommon/                  Wire protocol, serialization, constants
  IpcClient/                  Named-pipe client static lib
  HookEngine/                 Hook installation + WinHTTP/Schannel detours
  BirriMonitor/               Injectable DLL + version resource
  BirriLauncher/              Injection launcher
  BirriLogger/                Pipe server + traffic renderer
  SspiTarget/                 Test client
tests/tls_server.ps1          Local TLS test server
```

## Third-party dependencies

| Library | Purpose | Pinned |
|---|---|---|
| [MinHook](https://github.com/TsudaKageyu/minhook) | API hooking | master @ `d94c64d` (2026-06-13, includes CMake support) |
| [zlib](https://github.com/madler/zlib) | gzip/deflate decoding | v1.3.1 @ `51b7f2a` |
| [brotli](https://github.com/google/brotli) | brotli decoding | v1.1.0 @ `ed738e8` |

All are vendored as unmodified plain source copies under `third_party/` — no submodules, no build-time downloads, no prebuilt binaries. See `third_party/VERSIONS.md` for full provenance.

---

## Development notes

- The full technical specification (in Vietnamese) is `birrimonitor_full_spec.md` at the repository root.
- Code is intentionally kept free of inline comments and documentation per the project's quality requirements (§17).
- Each component is committed after it builds warning-clean; history is organized in milestone commits (`build:` → `feat(dll):` → `feat(logger):` → `feat(launcher):` → `ci:` → `fix:`).

## License

See the project owner for licensing information.
