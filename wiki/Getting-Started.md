# Getting Started

This page is the mechanical build-and-verify walkthrough. For how the pieces fit together, see [[Architecture]]; for running the result, see [[Usage]].

## Prerequisites

| Requirement | Detail |
|---|---|
| OS | Windows 10 or Windows 11, **x64** (the tool is x64-only and refuses 32-bit targets) |
| Visual Studio 2022 | Any edition, with the **Desktop development with C++** workload installed (provides MSBuild, the v143 toolset, the Windows SDK, and the bundled CMake) |
| PowerShell | 5.1+ (for `scripts/build.ps1`) |

You do **not** need to open a Visual Studio Developer shell — `scripts/build.ps1` locates VS2022 itself via `vswhere` and uses the CMake/MSBuild binaries bundled with it.

## 1. Clone the repository

```bat
git clone https://github.com/callmebirri/BirriMonitor.git
cd BirriMonitor
```

There are no submodules to initialize: all third-party dependencies (MinHook, zlib, brotli) are vendored as plain source copies under `third_party/`, so a plain clone is complete. See [[Tech Stack|Tech-Stack]].

## 2. Build

From the repository root, in a regular PowerShell or cmd window:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build.ps1
```

That command:

1. Configures and builds the three vendored libraries with CMake (`-A x64 -T v143`; static libs for zlib and brotli) into `build/third_party/`.
2. Builds the solution (`BirriMonitor.sln`, all six projects) with MSBuild.

Optional parameters, all defaulting to Release x64:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build.ps1 -Configuration Release -Platform x64
```

The build is warning-clean at `/W4 /WX`; if it completes, it prints `Build OK: x64 Release`.

> **Building from the Visual Studio IDE:** the solution itself does *not* build the vendored libraries — those are produced by the CMake steps in `scripts/build.ps1`. If you want to use the IDE, run `build.ps1` once first so `build/third_party/.../*.lib` exists, then open `BirriMonitor.sln` and build normally.

## 3. Verify the build

A successful Release x64 build produces these files in `build/bin/x64/Release/`:

```
BirriMonitor.dll     # injectable capture engine
BirriLauncher.exe    # injection launcher
BirriLogger.exe      # traffic viewer / pipe server
SspiTarget.exe       # test client (direct SSPI / WinHTTP)
```

Each has a matching `.pdb` next to it. (CI additionally verifies the DLL/EXE/PDB set for the three main components — see `.github/workflows/build.yml` — and uploads them as a build artifact.)

A quick sanity check that the binaries exist:

```powershell
Get-ChildItem build\bin\x64\Release
```

## 4. Optional: run the test suite

The repo ships two end-to-end test helpers; see [[Usage]] for how they are driven. Typical smoke test:

```powershell
# terminal 1: local TLS server (creates a CurrentUser self-signed CN=localhost cert if needed)
powershell -File tests\tls_server.ps1 -Port 8443 -Count 3

# terminal 2: the logger
build\bin\x64\Release\BirriLogger.exe

# terminal 3: launch a test client that exercises both capture layers
build\bin\x64\Release\BirriLauncher.exe build\bin\x64\Release\SspiTarget.exe 127.0.0.1 8443 --winhttp --delay-ms 1500
```

If the logger window shows a `TRANSACTION` block and a `SCHANNEL` block, the build is working end to end.

## Troubleshooting the build

| Symptom | Cause / fix |
|---|---|
| `Visual Studio 2022 with MSBuild was not found.` | VS2022 with the C++ workload is not installed, or `vswhere` cannot see it. Install the workload and retry. |
| `CMake configure failed for ...` / `CMake build failed for ...` | The vendored tree is incomplete or corrupted. Re-clone the repo; do not download libraries yourself. |
| `MSBuild failed` | First-party compile error. The build treats warnings as errors (`/W4 /WX`), so a warning anywhere in `src/` fails the build. |
