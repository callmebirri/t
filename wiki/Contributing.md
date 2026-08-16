# Contributing

Contributions, issues, and feature requests are welcome. The project is small and its conventions are mostly implicit — this page collects what is known so a first-time contributor does not have to guess.

## Before you start

- **Read the Code of Conduct.** The repository ships a [CODE_OF_CONDUCT.md](https://github.com/callmebirri/BirriMonitor/blob/main/CODE_OF_CONDUCT.md) (Contributor Covenant 2.0). Reports go to callmebirri@gmail.com.
- **Know the license.** The project is under the **PolyForm Noncommercial License 1.0.0** — contributions land under the same terms (non-commercial use only). There is currently no CLA or formal contribution process beyond that.
- There is no `CONTRIBUTING.md` in the repo and no issue/PR template yet — if you have strong opinions, propose them.
- Open issues on the [issues page](https://github.com/callmebirri/BirriMonitor/issues). Before filing a bug, check [[Known Limitations|Known-Limitations]] and the [[Permissions and Injection|Permissions-and-Injection]] troubleshooting table — many "bugs" are designed behavior.

## Building and testing expectations

- **Build with the script, not the IDE alone.** `scripts/build.ps1` builds the vendored libraries (MinHook, zlib, brotli) with CMake and then the solution with MSBuild. The `.sln` itself does not build `third_party/`, so run `build.ps1` once before using Visual Studio. Full steps: [[Getting Started|Getting-Started]].
- **The build must be warning-clean.** First-party code compiles at `/W4 /WX` — a single warning anywhere in `src/` fails the build, in Debug and Release alike. Vendored code is exempt.
- **Test end to end.** The smoke test (`tls_server.ps1` + `BirriLogger.exe` + `BirriLauncher.exe` + `SspiTarget.exe`) exercises both capture layers; see [[Usage]]. If you change hooking or IPC behavior, that smoke test plus the concurrency flags of `SspiTarget` (`--threads`, `--count`) are the minimum bar.
- **CI parity.** `.github/workflows/build.yml` builds on `windows-latest` (Release x64), caches `build/third_party` keyed on `third_party/**`, verifies the expected outputs exist, and uploads them as an artifact. PRs into `main` run it.

## Project conventions

- **No comments in first-party code.** This is an explicit project rule (spec §17): no inline, block, or doc comments, no `TODO`/`FIXME` markers, no commented-out code in `src/`. The code is expected to be self-documenting via naming and structure. `third_party/` is exempt — never strip or reformat vendored source.
- **No comments in project files.** `.vcxproj` / `.sln` files carry no XML comments.
- **Commit style.** History uses conventional-commit messages (`build:`, `feat(dll):`, `feat(logger):`, `feat(launcher):`, `ci:`, `fix:`, `docs:`), one logical change per commit, only buildable states committed, and no merge commits (rebase + fast-forward).
- **Keep the vendor policy.** Any new dependency must be vendored as a pinned source copy under `third_party/` with its commit recorded in `third_party/VERSIONS.md` — no build-time `git clone`, no prebuilt binaries, no NuGet/vcpkg (see [[Tech Stack|Tech-Stack]]).

## Where the code lives

| Concern | Location |
|---|---|
| Hook installation, WinHTTP + Schannel hooks | `src/HookEngine/` |
| DLL entry point / init thread | `src/BirriMonitor/dllmain.cpp` |
| IPC client (pipe, queue, reconnect) | `src/IpcClient/` |
| Wire protocol shared header | `src/IpcCommon/IpcCommon.h` |
| Launcher (injection, handshake, diagnostics) | `src/BirriLauncher/launcher.cpp` |
| Logger (pipe server, reassembly, decoding, rendering) | `src/BirriLogger/logger.cpp` |
| Test client | `src/SspiTarget/`, `tests/tls_server.ps1` |

Start with [[Architecture]] for the map.
