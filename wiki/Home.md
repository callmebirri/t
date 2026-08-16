# BirriMonitor

BirriMonitor is a **user-mode network traffic monitor for a single Windows x64 process**. It injects a small hook DLL into a target process, intercepts the WinHTTP and Schannel/SSPI APIs the process calls, captures the data **while it is still plaintext**, and streams it over a named pipe to a separate logger process that renders each request/response pair as a readable transaction.

It is **not** a MITM proxy. It does not install certificates, does not reroute traffic through itself, and does not decrypt anything — it observes API calls inside the target process, at the exact point where HTTPS data exists in plaintext form before WinHTTP hands it to Schannel (and after Schannel decrypts it). No kernel driver, no certificate store changes, no system-wide coverage.

This makes it useful for a specific job: **debugging the HTTP(S) traffic of an application you own or are allowed to test**. If your app uses WinHTTP (most Windows HTTPS clients, PowerShell, WinInet-based tools), BirriMonitor rebuilds the full request URL, headers, and body plus the parsed response. If your app talks TLS directly through SSPI/Schannel — RDP-style clients, custom HTTPS libraries, WebSockets that manage their own TLS — the Schannel layer reconstructs the plaintext stream, including TLS 1.3.

## Quick links

- **[[Getting Started|Getting-Started]]** — prerequisites, build steps, and how to verify the build.
- **[[Usage]]** — start the logger, launch a target, and read the output.
- **[[FAQ]]** — the short answers to the most common questions.
- **[[Architecture]]** — how the pieces fit together and how capture works.
- **[[Permissions and Injection|Permissions-and-Injection]]** — why injection may be denied and what to do about it.
- **[[Known Limitations|Known-Limitations]]** — what the tool does not capture, by design.
- **[[Tech Stack|Tech-Stack]]** — languages, toolset, and vendored dependencies.

## When to reach for it

You are debugging your own application and want to see exactly what it sends and receives over HTTPS — without standing up a proxy, without changing `WINHTTP_PROXY` configuration, and without weakening or bypassing certificate validation to make a MITM tool work. Because capture happens at the API boundary inside the process, BirriMonitor sees the *real* traffic the app produces, encrypted or not, and works for libraries that hard-code their own TLS (via Schannel/SSPI) that a proxy would never see.

Two things to know before you start:

1. **You need permission over the target process.** The launcher injects the DLL into the target's address space. If you do not have sufficient rights (elevation, integrity level, anti-tamper), injection fails with a diagnostic — see [[Permissions and Injection|Permissions-and-Injection]].
2. **It is a per-process, per-session tool.** You launch it for one target at a time, and traffic that happened *before* injection is not captured. For the cleanest results, use the suspended-start method so capture is live from the moment the target begins running — see [[Usage]].

The project is licensed under the PolyForm Noncommercial License 1.0.0 — free to use, modify, and distribute for non-commercial purposes. See the repository's `LICENSE` file and [[Contributing]].
