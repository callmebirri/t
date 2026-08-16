# Tech Stack

Everything in BirriMonitor is built with the Microsoft C++ toolchain on Windows, from vendored source checked into the repository. There is no package-manager step, no `git clone` at build time, and no prebuilt binary from a third party anywhere in the chain.

## Languages & toolchain

| Item | Value |
|---|---|
| Language | C++17 (`<LanguageStandard>stdcpp17</LanguageStandard>` in every `.vcxproj`) |
| Compiler | MSVC via Visual Studio 2022 |
| Platform toolset | `v143` (declared in every `.vcxproj` and passed as `-T v143` to every third-party CMake build) |
| Windows SDK | `10.0` (`<WindowsTargetPlatformVersion>10.0</WindowsTargetPlatformVersion>`) |
| Warning policy | `/W4` + `/WX` (treat warnings as errors) on all first-party code |
| Character set | Unicode (`<CharacterSet>Unicode</CharacterSet>`) |
| Target architecture | x64 only (solution has no Win32 configurations; injection and hooking are 64-bit by design) |
| Build driver | `scripts/build.ps1` (PowerShell 5.1+), which locates VS2022 via `vswhere` and uses the bundled CMake + MSBuild |
| CI | GitHub Actions on `windows-latest` (see `.github/workflows/build.yml`) |

The `/W4 /WX` policy applies only to BirriMonitor-authored code. Vendored third-party sources are compiled with their own warning flags and are never modified.

## First-party modules

| Module | Type | Links against |
|---|---|---|
| `BirriMonitor.dll` | Injectable DLL | `winhttp.lib`, `secur32.lib`, `minhook.x64.lib` |
| `BirriLauncher.exe` | Console EXE | none beyond the CRT |
| `BirriLogger.exe` | Console EXE | `zlibstatic.lib`, `brotlidec.lib`, `brotlicommon.lib` |
| `HookEngine` | Static library | `minhook.x64.lib` (compiled into `BirriMonitor.dll`) |
| `IpcClient` | Static library | none (compiled into `BirriMonitor.dll`) |
| `IpcCommon` | Shared header only | — |
| `SspiTarget.exe` | Test client | `ws2_32.lib`, `secur32.lib`, `winhttp.lib` |

See [[Architecture]] for what each module does.

## Vendored third-party dependencies

All three libraries live as **plain source copies** under `third_party/` — no git submodules (there is no `.gitmodules` in the repo), no downloads at build time, no prebuilt binaries. Each is pinned to an exact commit, recorded in `third_party/VERSIONS.md`, and built locally with CMake configured with `-A x64 -T v143`.

| Library | Upstream | Pinned | Purpose | Build hook |
|---|---|---|---|---|
| MinHook | [TsudaKageyu/minhook](https://github.com/TsudaKageyu/minhook) | master @ 2026-06-13, commit `d94c64d32ea37bc4f5ee47d580709f70c6fb6080` | x64 API hooking for the capture engine (trampolines for all hooked WinHTTP/Schannel functions) | `scripts/build.ps1` CMake step → `build/third_party/minhook/Release/minhook.x64.lib`; linked by `HookEngine.vcxproj` and `BirriMonitor.vcxproj` |
| zlib | [madler/zlib](https://github.com/madler/zlib) | v1.3.1, commit `51b7f2abdade71cd9bb0e7a373ef2610ec6f9daf` | Inflate `Content-Encoding: gzip` / `deflate` response bodies in the logger | CMake step with `-DBUILD_SHARED_LIBS=OFF` → `build/third_party/zlib/Release/zlibstatic.lib`; linked by `BirriLogger.vcxproj` |
| brotli | [google/brotli](https://github.com/google/brotli) | v1.1.0, commit `ed738e842d2fbdf2d6459e39267a633c4a9b2f5d` | Decode `Content-Encoding: br` response bodies in the logger | CMake step with `-DBUILD_SHARED_LIBS=OFF` → `build/third_party/brotli/Release/brotlidec.lib` + `brotlicommon.lib`; linked by `BirriLogger.vcxproj` |

Notes from `third_party/VERSIONS.md`:

- MinHook's `v1.3.3` release tag predates its CMake support, so the pinned commit is on `master` (2026-06-13), the first revision that ships a `CMakeLists.txt`.
- The vendored trees are **unmodified upstream checkouts** — the "Source modifications" section of `VERSIONS.md` is empty.
- All three must be built with `-A x64 -T v143` to stay ABI-consistent with the main solution.

### Why "vendored, not cloned at build time"

The build must be reproducible and offline. If the build script cloned upstream at build time, two builds on different days could silently pick up different upstream code and produce different behavior — and the build would break whenever GitHub is unreachable. By vendoring pinned snapshots, the entire build chain is auditable: `third_party/VERSIONS.md` records exactly which upstream revision is compiled, and no step of the build depends on network access. The CI workflow exploits this too: the `build/third_party` directory is cached, keyed on the hash of everything under `third_party/`, so the cache invalidates automatically whenever any vendored source or pinned version changes.

## Hooking library choice

**MinHook is the hooking library used for every hook in the shipped code.** It provides the trampolines for all nine WinHTTP functions and all four Schannel/SSPI functions (see [[Architecture]]). The technical spec documents Detours as a permitted per-hook fallback if a specific function ever resisted MinHook (trampoline conflicts, functions too short to patch) — but no such case arose during development, so Detours is not present in the codebase and nothing needs to be linked or vendored for it. The rule if it ever *is* needed: vendor it the same way (pinned source under `third_party/`), and make sure its trampolines cannot conflict with MinHook's inside the same binary.

## Build pipeline at a glance

1. `scripts/build.ps1` locates Visual Studio 2022 with `vswhere`.
2. It configures and builds MinHook, zlib, and brotli with the CMake bundled with VS (`-A x64 -T v143`, static libs for zlib/brotli).
3. It builds the solution (`BirriMonitor.sln`, six projects) with MSBuild at `Release|x64` by default.
4. CI (`windows-latest`) then verifies the expected DLL/EXE/PDB outputs exist and uploads them as an artifact named after the run number and commit SHA. Full steps in [[Getting Started|Getting-Started]].
