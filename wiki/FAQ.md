# FAQ

Short answers with pointers to the pages that go deeper.

## Why isn't my HTTPS traffic showing up?

Work through this checklist in order:

1. **Is the logger running?** The DLL's handshake requires a live pipe server. Start `BirriLogger.exe` before launching the target, or the launcher will time out on the handshake.
2. **Which TLS stack does the app use?** BirriMonitor only hooks **WinHTTP** and **Schannel/SSPI**. OpenSSL, BCrypt/CNG, mbedTLS, QUIC/HTTP3, Winsock, and WinINet traffic is invisible to it. See [[Known Limitations|Known-Limitations]].
3. **Was the traffic generated after injection?** Method B only captures traffic after the hooks install. Restart via Method A if you need traffic from process start. See [[Usage]].
4. **Is the Schannel stream missing its first exchange?** The Schannel hooks late-bind with a 100 ms poll; a TLS session that completes within ~100 ms of `schannel.dll` loading can be missed (Method A only). See [[Known Limitations|Known-Limitations]].
5. **Double-check the layer.** HTTPS through WinHTTP renders as a `TRANSACTION` block; direct SSPI usage renders as a `SCHANNEL` block. A WinHTTP request is deliberately reported **once**, not twice. See [[Architecture]].

## Can I monitor a process I don't own?

Only if the operating system grants you the rights to open and inject into it. The launcher must be able to `OpenProcess` the target with VM read/write, thread-creation, and query rights — which typically requires the same user, equal or higher integrity level (elevation), and no protected-process/anti-tamper restrictions. BirriMonitor is designed for **processes you own or are authorized to test**. When access is denied, the launcher diagnoses exactly why — see [[Permissions and Injection|Permissions-and-Injection]].

## Does this work like Fiddler / mitmproxy?

**No.** Those are MITM proxies: they sit in the network path, terminate TLS with their own certificates, and re-encrypt to the server. BirriMonitor is the opposite in almost every way:

- It is **not in the network path** — it never sees a packet and never touches a socket.
- It **does not install or trust any certificates** — nothing on the system changes.
- It **does not intercept or modify** anything — it only observes API calls inside the target process and reads data at the point where it is already plaintext.
- It covers **one process at a time**, not the whole machine.

The trade-off: it sees only the APIs it hooks ([[Known Limitations|Known-Limitations]]), and it needs the target to be injectable ([[Permissions and Injection|Permissions-and-Injection]]). The advantage: it shows the traffic an app *actually* produces through its own TLS stack, works with pinned/custom TLS (via SSPI), and never needs a certificate trust change.

## Why do I need Administrator rights?

Usually you don't — **Method A (suspended start) works from a normal user context in the common case**, because the launcher creates the target and therefore holds a full handle from birth. You need elevation only when the **target** requires it:

- The target runs elevated (or at a higher integrity level) and you want Method B, or
- Method A targets an elevated app.

When elevation is missing, `OpenProcess` fails with access denied and the launcher says so explicitly — it will never silently re-launch itself elevated. See [[Permissions and Injection|Permissions-and-Injection]] for the full matrix.

## Is this detected by antivirus?

**It can be.** BirriMonitor uses the classic user-mode injection pattern (`OpenProcess` + `WriteProcessMemory` + `CreateRemoteThread` + `LoadLibraryW`), which is exactly the pattern security products flag — sometimes with good reason. In a controlled test environment, you may need to add an exclusion for the launcher and target. BirriMonitor makes no attempt to evade detection: no exotic APIs, no driver, no PPL bypass. See [[Permissions and Injection|Permissions-and-Injection]] (the EDR rows) and the disclaimer in the repository README.

## What's the difference between the `TRANSACTION` and `SCHANNEL` blocks?

`TRANSACTION` = an HTTP request/response pair captured through the WinHTTP hooks — full URL, headers, decompressed body. `SCHANNEL` = a plaintext TLS stream captured at the SSPI boundary — the send direction is shown raw ("estimated"), and the receive direction is parsed when it looks like HTTP, or shown as a 32-byte hex preview when it doesn't. See [[Usage]].

## Can I capture more than one process at a time?

Not in the current release. BirriLauncher targets a single process per session. The IPC protocol already keys messages by PID (so the logger would not mis-associate streams from multiple targets), but the launcher and docs support one target at a time.

## Does it work on 32-bit apps or ARM?

No. x64-only, by design: the launcher checks the target's architecture (`IsWow64Process2`) and refuses 32-bit targets before injecting. See [[Known Limitations|Known-Limitations]].

## Where does the captured data go?

Nowhere but the console (stdout). No files are written, no config is stored, and there is no persistence. Kill the logger and the session data is gone.

## What license is this under?

PolyForm Noncommercial License 1.0.0 — free to use, modify, and distribute for non-commercial purposes only. See the repository `LICENSE` file and [[Contributing]].
