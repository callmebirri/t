# Permissions and Injection

BirriMonitor captures traffic by loading `BirriMonitor.dll` into the target process and hooking its WinHTTP/Schannel calls. That means the launcher must be able to open the target, allocate memory inside it, and create a remote thread. Windows security, integrity levels, and security software all sit between the launcher and that goal. This page explains the two injection methods and — most importantly — what each failure message actually means, so you can self-serve instead of filing an issue.

## The two injection methods

### Method A — start the target suspended (preferred)

```bat
BirriLauncher.exe C:\path\to\target.exe [target args...]
```

Sequence: `CreateProcess(..., CREATE_SUSPENDED)` → architecture check → write the DLL path into the target → `CreateRemoteThread(LoadLibraryW)` → wait for the hooks-ready handshake event (10 s timeout) → `ResumeThread`.

**Use Method A whenever you can launch the target yourself.** Because the launcher *creates* the target, it holds a full-access process handle from birth — most of Method B's permission problems simply cannot occur, and no startup traffic is missed (capture is live before the target's main thread runs).

### Method B — attach to a running process

```bat
BirriLauncher.exe --pid <pid>
```

Sequence: `OpenProcess(PROCESS_ALL_ACCESS)` → if denied, fall back to minimal rights (`PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION`) → architecture check → inject → wait for the handshake (5 s timeout).

**Use Method B when the target is already running** and you cannot or do not want to restart it (for example, a long-lived service or a stateful app). Two caveats: the target must be running at an integrity level you can reach, and traffic generated before injection is not captured.

Before either method runs, the launcher checks its own elevation (`TokenElevation`) and, on Method B, the target's integrity level and architecture (`IsWow64Process2`, falling back to `IsWow64Process`). Every failure is logged with the numeric `GetLastError()` code plus its `FormatMessageW` text — not a bare function name.

## Troubleshooting table

The launcher never auto-elevates, never retries forever, and never attempts PPL/anti-tamper bypasses. If a step is denied, it diagnoses *why* and stops. Match your output below.

| Symptom (what you see) | Likely cause | What to do |
|---|---|---|
| `launcher is not elevated; if the target runs elevated, rerun the launcher as Administrator` | The launcher runs at a normal integrity level but the target requires elevation. | Rerun `BirriLauncher.exe` from an elevated (Administrator) console. The launcher will not silently re-launch itself elevated. |
| `target integrity level (N) is higher than the launcher (M)` / `run the launcher with equivalent or higher privileges` | The target runs at a higher integrity level than the launcher (classic case: target is elevated, launcher is not). | Run the launcher at an equal or higher integrity level — i.e. elevated if the target is elevated. |
| `the process is likely protected at system level (protected process/anti-tamper)` or `process is likely a protected process (PPL)` | The target is a Protected Process / Protected Process Light (PPL) or has active anti-tamper that blocks `OpenProcess`. This is the default conclusion when you are elevated, integrity levels match, and access is still denied. | You cannot inject into it from user mode. This is by design — BirriMonitor refuses to attempt PPL/anti-tamper bypasses. Choose a different target, or run the target un-protected if you control it. |
| `target process no longer exists (pid N not found) - it may have exited; try again` | The PID is stale: the process exited between enumeration and `OpenProcess` (`ERROR_INVALID_PARAMETER`, 87). | Confirm the PID (e.g. Task Manager) and retry. Not an access problem. |
| `possibly blocked by security software (EDR); consider an exclusion` (specifically at `CreateRemoteThread`) | `OpenProcess` + `WriteProcessMemory` succeeded but `CreateRemoteThread` was denied. Some EDR products block the classic injection primitive while allowing `OpenProcess`. | This is logged separately from access-denied because the cause is different. In a test environment you control, add an exclusion for the launcher and target. BirriMonitor will not silently switch to exotic thread-creation APIs to evade detection. |
| `possibly blocked by security software` with everything else looking fine | Defender/EDR is blocking the `OpenProcess` + `WriteProcessMemory` + `CreateRemoteThread` pattern, and the failure surfaces at `WriteProcessMemory`/`CreateRemoteThread` rather than `OpenProcess`. | Add a security-software exclusion for launcher and target in your controlled test environment. The launcher does not touch Defender or AV configuration itself. |
| `target architecture is 32-bit (WOW64) but BirriMonitor.dll is x64 only - refusing to inject` | Architecture mismatch: 32-bit target, 64-bit DLL. | BirriMonitor is x64-only. Use an x64 build of your target, or a different tool. The launcher refuses up front instead of crash-injecting. |
| `LoadLibraryW inside the target returned NULL - the DLL could not be loaded` | The remote `LoadLibraryW` failed even though the thread was created (exit code 0). Typically the DLL path is not visible from the target's point of view — sandbox/container with a different filesystem view, or the DLL was moved/deleted. | Keep `BirriMonitor.dll` next to `BirriLauncher.exe`; if the target runs in a sandbox, give it the same filesystem view. |
| `timed out waiting for the hooks-ready handshake (10s / 5s)` | The DLL was injected but never signaled ready — most commonly because **BirriLogger is not running**, so the DLL's pipe connection (which gates the handshake) cannot succeed within the wait. Could also be hooks failing to install in an exotic process. | Start `BirriLogger.exe` *before* launching. If the logger is running and this persists, the target likely blocks hook installation. |
| `target exited before hooks were ready` | The target terminated between injection and handshake (e.g. it crashes at startup, or exits immediately). | Fix the target's startup, then retry. Not an injection problem. |
| `injection failed: CreateRemoteThread failed` (with a `GetLastError` code) | Thread creation denied, or the target exited mid-injection. | See the EDR row above; or check the target is still alive. |

## General rules (by design)

- The launcher **never auto-elevates** — it prints what it needs and lets you decide (rerun elevated, pick another target, adjust the environment).
- Every failing Win32 call is logged with its numeric error code and formatted message, so a report of `OpenProcess failed ... (error 5: Access is denied.)` should be diagnosed before anything else.
- **Method A is the recommended path** whenever you can start the target yourself: it sidesteps most of the above entirely, because the launcher owns the process handle from creation.
- If your environment is clean (elevated, matching integrity, no PPL) and injection still fails, the overwhelmingly likely culprit is security software — see the EDR rows above.
