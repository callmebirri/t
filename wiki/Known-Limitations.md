# Known Limitations

This page exists so that things which are **working as designed** do not get filed as bugs. Read it before opening an issue: if your situation is listed here, the behavior is intentional (or a documented trade-off of the architecture).

## TLS stacks that are not hooked

Only two capture layers exist: **WinHTTP** and **Schannel/SSPI** (see [[Architecture]]). The following are explicitly out of scope in the current release and produce no output:

- **OpenSSL** (`SSL_read`/`SSL_write`) — dynamically or statically linked custom TLS libraries
- **BCrypt/CNG** (`BCryptEncrypt`/`BCryptDecrypt`)
- **mbedTLS**
- **QUIC / HTTP/3** (including QUIC that rides on Schannel for its TLS part)
- **Winsock, WinINet, and URLMon** layers (raw `send`/`recv`, legacy `wininet.dll` clients, `urlmon.dll` streams)

If the target uses any of these, BirriMonitor simply shows nothing for that traffic. A DLL search-order hijacking loader ("Method C") is also not implemented.

## Timing and coverage gaps

- **Traffic before injection is not captured.** Method B (attach to a running process) can only see traffic generated *after* the hooks install. This is inherent to late attachment — use Method A (suspended start) if you need traffic from the very first network call.
- **First-SSPI-stream edge case (Method A only):** Schannel hooks are installed by a late-bind thread that polls for `schannel.dll` every **100 ms**. If a target loads Schannel and completes an entire TLS session within ~100 ms of load — e.g. a local, low-latency handshake done immediately at startup — that first stream can be missed. The test client's `--delay-ms` flag exists precisely to make such tests deterministic; real-world targets rarely complete full TLS sessions inside 100 ms.
- **Async WinHTTP on a non-hooked thread:** the double-capture guard relies on Schannel calls made *inside* a WinHTTP hook being passed through unregistered. If WinHTTP performs TLS on an internal worker thread that is not inside a hook (an async WinHTTP scenario), that stream is not registered and can be missed. This is rare but possible; it is a known gap, not a regression.
- **A target that never loads `schannel.dll`** never gets Schannel hooks at all (by design — "no blind hooking"). Such a target can still be captured if it uses WinHTTP for HTTP (non-TLS).

## Capture fidelity

- **Schannel hooks are passive** — they observe handshakes but capture no handshake bytes. Only post-handshake plaintext (from `EncryptMessage`/`DecryptMessage`) is reported; the TLS handshake itself is not shown.
- **Non-HTTP Schannel streams are not parsed.** They are rendered with a 32-byte hex preview plus a `(non-HTTP schannel stream)` note. This is the only hex output in the tool, deliberately.
- **Bodies are capped at 64 MiB per direction** in the DLL; larger bodies are marked `(truncated at source, total N bytes)`. The logger retains up to the same cap and **renders at most 64 KiB** per body. The on-screen note says "full in debug log", but **no debug log file is written** — the logger's per-message debug lines go to stderr, and the retained body is the in-memory copy only.
- **Decompression failures degrade gracefully**: raw body shown with a `(decompression failed, showing raw)` note — never a crash.

## IPC behavior

- **Drops under overload.** The DLL's message queue is bounded (2048 messages). When full, the newest message is dropped and a counter is incremented. After reconnecting, the client sends a `DropCount` message — but the current logger does not render it, so a drop is silent in the console output. Heavy traffic bursts can therefore lose messages without an on-screen warning.
- **Dropping the logger mid-session:** if `BirriLogger.exe` is killed while the target is sending, messages are dropped and the target keeps running unharmed — no deadlock, no crash. Data sent while the logger is down is lost; the client reconnects with backoff (250 ms → 5 s max) when the logger returns.
- **Single-instance logger:** a second `BirriLogger.exe` exits immediately; only one pipe server can exist at a time.
- **One-shot per-message framing:** messages are length-prefixed and validated (max 16 MiB), so a corrupted or oversized frame is discarded rather than crashing the logger.

## Platform constraints

- **x64 only** — 32-bit targets are refused at injection time with a clear message (no WOW64 support, no 32-bit DLL variant).
- **No kernel driver, no PPL bypass, no anti-tamper bypass** — protected processes are diagnosed and left alone (see [[Permissions and Injection|Permissions-and-Injection]]).
- **Not a MITM proxy and not a system-wide sniffer** — one target process per session, captured at the API boundary inside that process. See [[Home]] for what the tool is and isn't.
- **No persistence, no config files, no saved capture files** — output is console-only.

## Output formatting

- Transactions are rendered **only when their response completes** (or when the timeout window expires); there is no live "pending" preview while a request is in flight.
- Console rendering is ASCII-safe: control characters (other than `\n`/`\t`) are escaped, and no Unicode box-drawing characters are used, to survive Windows console codepages.
