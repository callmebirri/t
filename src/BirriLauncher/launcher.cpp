#include "IpcCommon/IpcCommon.h"

#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <string>
#include <vector>

static void WriteLine(HANDLE hOut, const std::wstring& line) {
    DWORD written = 0;
    if (hOut != INVALID_HANDLE_VALUE && hOut != nullptr) {
        if (WriteConsoleW(hOut, line.c_str(), static_cast<DWORD>(line.size()), &written, nullptr)) {
            WriteConsoleW(hOut, L"\n", 1, &written, nullptr);
            return;
        }
    }
    int len = WideCharToMultiByte(CP_UTF8, 0, line.c_str(), static_cast<int>(line.size()), nullptr, 0, nullptr, nullptr);
    std::string utf8(static_cast<size_t>(len), '\0');
    WideCharToMultiByte(CP_UTF8, 0, line.c_str(), static_cast<int>(line.size()), utf8.data(), len, nullptr, nullptr);
    fwrite(utf8.data(), 1, utf8.size(), stdout);
    fwrite("\n", 1, 1, stdout);
    fflush(stdout);
}

static void Log(const std::wstring& line) {
    WriteLine(GetStdHandle(STD_OUTPUT_HANDLE), line);
}

static void LogErr(const std::wstring& line) {
    WriteLine(GetStdHandle(STD_ERROR_HANDLE), line);
}

static std::wstring LastErrorText(DWORD err) {
    wchar_t* buf = nullptr;
    DWORD n = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                             nullptr, err, 0, reinterpret_cast<LPWSTR>(&buf), 0, nullptr);
    std::wstring out = n ? std::wstring(buf, n) : std::wstring(L"(unknown error)");
    if (buf) {
        LocalFree(buf);
    }
    while (!out.empty() && (out.back() == L'\r' || out.back() == L'\n')) {
        out.pop_back();
    }
    return out;
}

static std::wstring WinError(DWORD err) {
    return L" (error " + std::to_wstring(err) + L": " + LastErrorText(err) + L")";
}

static bool IsElevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return false;
    }
    TOKEN_ELEVATION elev = {};
    DWORD size = 0;
    BOOL ok = GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &size);
    CloseHandle(token);
    return ok && elev.TokenIsElevated != 0;
}

static DWORD GetIntegrityLevel(HANDLE hProcess) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &token)) {
        return 0;
    }
    std::vector<unsigned char> buf(256);
    DWORD size = 0;
    BOOL ok = GetTokenInformation(token, TokenIntegrityLevel, buf.data(), static_cast<DWORD>(buf.size()), &size);
    CloseHandle(token);
    if (!ok) {
        return 0;
    }
    TOKEN_MANDATORY_LABEL* label = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buf.data());
    if (!label->Label.Sid) {
        return 0;
    }
    DWORD count = *GetSidSubAuthorityCount(label->Label.Sid);
    if (count == 0) {
        return 0;
    }
    return *GetSidSubAuthority(label->Label.Sid, count - 1);
}

static bool GetProcessArchitecture(HANDLE hProcess, bool& isX64, std::wstring& detail) {
    USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
    USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
    if (IsWow64Process2(hProcess, &processMachine, &nativeMachine)) {
        if (processMachine != IMAGE_FILE_MACHINE_UNKNOWN) {
            isX64 = false;
            detail = L"32-bit (WOW64)";
            return true;
        }
        isX64 = (nativeMachine == IMAGE_FILE_MACHINE_AMD64);
        detail = isX64 ? L"64-bit (native)" : L"64-bit on non-AMD64 OS";
        return true;
    }
    BOOL wow = FALSE;
    if (IsWow64Process(hProcess, &wow)) {
        if (wow) {
            isX64 = false;
            detail = L"32-bit (WOW64)";
            return true;
        }
        isX64 = true;
        detail = L"64-bit (native)";
        return true;
    }
    return false;
}

static std::wstring BuildDllPath() {
    wchar_t exe[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, exe, MAX_PATH);
    std::wstring path(exe);
    size_t slash = path.find_last_of(L'\\');
    if (slash == std::wstring::npos) {
        return L"BirriMonitor.dll";
    }
    return path.substr(0, slash + 1) + L"BirriMonitor.dll";
}

static bool InjectDll(HANDLE hProcess, const std::wstring& dllPath, bool& dllLoaded, std::wstring& error) {
    dllLoaded = false;
    size_t bytes = (dllPath.size() + 1) * sizeof(wchar_t);
    void* remote = VirtualAllocEx(hProcess, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) {
        error = L"VirtualAllocEx failed" + WinError(GetLastError());
        return false;
    }
    if (!WriteProcessMemory(hProcess, remote, dllPath.c_str(), bytes, nullptr)) {
        error = L"WriteProcessMemory failed" + WinError(GetLastError());
        VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
        return false;
    }
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC loadLib = GetProcAddress(k32, "LoadLibraryW");
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLib), remote, 0, nullptr);
    if (!hThread) {
        error = L"CreateRemoteThread failed" + WinError(GetLastError()) + L" - possibly blocked by security software (EDR); consider an exclusion for launcher/target in this test environment";
        VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
        return false;
    }
    DWORD wait = WaitForSingleObject(hThread, 10000);
    DWORD exitCode = 0;
    if (wait == WAIT_OBJECT_0) {
        GetExitCodeThread(hThread, &exitCode);
    } else {
        error = L"remote LoadLibraryW thread did not finish within 10s";
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
        return false;
    }
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
    dllLoaded = (exitCode != 0);
    return true;
}

static void DiagnoseOpenProcessFailure(DWORD pid, bool elevated) {
    Log(L"OpenProcess failed with access denied for pid " + std::to_wstring(pid));
    if (!elevated) {
        Log(L"launcher is not elevated; if the target runs elevated, rerun the launcher as Administrator");
    }
    HANDLE hLimited = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hLimited) {
        DWORD err = GetLastError();
        if (err == ERROR_INVALID_PARAMETER) {
            Log(L"target process no longer exists (pid " + std::to_wstring(pid) + L" not found) - it may have exited; try again");
            return;
        }
        Log(L"cannot open even PROCESS_QUERY_LIMITED_INFORMATION" + WinError(err));
        Log(L"the process is likely protected at system level (protected process/anti-tamper) or blocked by security software");
        return;
    }
    DWORD ourIntegrity = GetIntegrityLevel(GetCurrentProcess());
    DWORD targetIntegrity = GetIntegrityLevel(hLimited);
    CloseHandle(hLimited);
    if (ourIntegrity != 0 && targetIntegrity != 0 && targetIntegrity > ourIntegrity) {
        Log(L"target integrity level (" + std::to_wstring(targetIntegrity) + L") is higher than the launcher (" + std::to_wstring(ourIntegrity) + L")");
        Log(L"run the launcher with equivalent or higher privileges (Administrator)");
    } else {
        Log(L"access denied with matching privileges on the launcher side");
        if (elevated) {
            Log(L"the process is likely a protected process (PPL) or protected by anti-tamper/security software - user-mode injection is not possible");
        } else {
            Log(L"rerun the launcher as Administrator first; if still denied, the process is likely protected (PPL/anti-tamper)");
        }
        Log(L"if this is a controlled test environment, consider adding a security software exclusion for launcher and target");
    }
}

static void PrintUsage() {
    LogErr(L"usage: BirriLauncher.exe <target.exe> [target args...]");
    LogErr(L"       BirriLauncher.exe --pid <pid>");
    LogErr(L"Method A starts the target suspended, injects, waits for hooks-ready, then resumes.");
    LogErr(L"Method B injects into an already running process by pid.");
}

static int RunMethodA(const std::wstring& target, const std::vector<std::wstring>& args) {
    bool elevated = IsElevated();
    Log(L"launcher elevated: " + std::wstring(elevated ? L"yes" : L"no"));
    std::wstring dllPath = BuildDllPath();
    if (GetFileAttributesW(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        Log(L"BirriMonitor.dll not found at " + dllPath);
        return 1;
    }
    HANDLE readyEvent = CreateEventW(nullptr, TRUE, FALSE, ipc::kHooksReadyEventName);
    if (!readyEvent) {
        Log(L"failed to create hooks-ready event" + WinError(GetLastError()));
        return 1;
    }
    std::wstring cmdline = target;
    for (const std::wstring& a : args) {
        cmdline += L" ";
        cmdline += a;
    }
    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(target.c_str(), cmdline.data(), nullptr, nullptr, FALSE, CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, nullptr, nullptr, &si, &pi)) {
        Log(L"CreateProcessW failed for " + target + WinError(GetLastError()));
        CloseHandle(readyEvent);
        return 1;
    }
    Log(L"target started suspended (pid " + std::to_wstring(pi.dwProcessId) + L")");

    bool isX64 = false;
    std::wstring archDetail;
    if (!GetProcessArchitecture(pi.hProcess, isX64, archDetail)) {
        Log(L"failed to determine target architecture" + WinError(GetLastError()));
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        CloseHandle(readyEvent);
        return 1;
    }
    if (!isX64) {
        Log(L"target architecture is " + archDetail + L" but BirriMonitor.dll is x64 only - refusing to inject");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        CloseHandle(readyEvent);
        return 1;
    }

    bool dllLoaded = false;
    std::wstring injectErr;
    if (!InjectDll(pi.hProcess, dllPath, dllLoaded, injectErr)) {
        Log(L"injection failed: " + injectErr);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        CloseHandle(readyEvent);
        return 1;
    }
    if (!dllLoaded) {
        Log(L"LoadLibraryW inside the target returned NULL - the DLL could not be loaded; check that the path is visible to the target process");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        CloseHandle(readyEvent);
        return 1;
    }
    Log(L"DLL loaded in target");

    HANDLE waiters[2] = {readyEvent, pi.hProcess};
    DWORD w = WaitForMultipleObjects(2, waiters, FALSE, 10000);
    if (w == WAIT_OBJECT_0) {
        ResumeThread(pi.hThread);
        Log(L"hooks ready, target resumed (pid " + std::to_wstring(pi.dwProcessId) + L")");
        Log(L"injection complete - traffic will appear in the BirriLogger window");
    } else if (w == WAIT_OBJECT_0 + 1) {
        Log(L"target exited before hooks were ready - nothing to resume");
    } else if (w == WAIT_TIMEOUT) {
        Log(L"timed out waiting for the hooks-ready handshake (10s) - hooks did not initialize in time");
        TerminateProcess(pi.hProcess, 0);
        Log(L"suspended target terminated");
    } else {
        Log(L"handshake wait failed" + WinError(GetLastError()));
        TerminateProcess(pi.hProcess, 0);
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(readyEvent);
    return (w == WAIT_OBJECT_0) ? 0 : 1;
}

static int RunMethodB(DWORD pid) {
    bool elevated = IsElevated();
    Log(L"launcher elevated: " + std::wstring(elevated ? L"yes" : L"no"));
    std::wstring dllPath = BuildDllPath();
    if (GetFileAttributesW(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        Log(L"BirriMonitor.dll not found at " + dllPath);
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        DWORD err = GetLastError();
        if (err == ERROR_INVALID_PARAMETER) {
            Log(L"target process does not exist (pid " + std::to_wstring(pid) + L") - it may have exited; try again");
            return 1;
        }
        if (err == ERROR_ACCESS_DENIED) {
            Log(L"PROCESS_ALL_ACCESS denied" + WinError(err));
            hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
            if (hProcess) {
                Log(L"fell back to minimal access rights (CREATE_THREAD|VM_OPERATION|VM_WRITE|VM_READ|QUERY_INFORMATION)");
            } else {
                DiagnoseOpenProcessFailure(pid, elevated);
                return 1;
            }
        } else {
            Log(L"OpenProcess failed" + WinError(err));
            return 1;
        }
    } else {
        Log(L"opened target with PROCESS_ALL_ACCESS");
    }

    bool isX64 = false;
    std::wstring archDetail;
    if (!GetProcessArchitecture(hProcess, isX64, archDetail)) {
        Log(L"failed to determine target architecture" + WinError(GetLastError()));
        CloseHandle(hProcess);
        return 1;
    }
    if (!isX64) {
        Log(L"target architecture is " + archDetail + L" but BirriMonitor.dll is x64 only - refusing to inject");
        CloseHandle(hProcess);
        return 1;
    }

    HANDLE readyEvent = CreateEventW(nullptr, TRUE, FALSE, ipc::kHooksReadyEventName);
    if (!readyEvent) {
        Log(L"failed to create hooks-ready event" + WinError(GetLastError()));
        CloseHandle(hProcess);
        return 1;
    }

    bool dllLoaded = false;
    std::wstring injectErr;
    if (!InjectDll(hProcess, dllPath, dllLoaded, injectErr)) {
        Log(L"injection failed: " + injectErr);
        CloseHandle(readyEvent);
        CloseHandle(hProcess);
        return 1;
    }
    if (!dllLoaded) {
        Log(L"LoadLibraryW inside the target returned NULL - the DLL could not be loaded; check that the path is visible to the target process");
        CloseHandle(readyEvent);
        CloseHandle(hProcess);
        return 1;
    }
    Log(L"DLL loaded in target");

    HANDLE waiters[2] = {readyEvent, hProcess};
    DWORD w = WaitForMultipleObjects(2, waiters, FALSE, 5000);
    if (w == WAIT_OBJECT_0) {
        Log(L"hooks ready (pid " + std::to_wstring(pid) + L") - traffic will appear in the BirriLogger window");
    } else if (w == WAIT_OBJECT_0 + 1) {
        Log(L"target exited before hooks were ready");
    } else if (w == WAIT_TIMEOUT) {
        Log(L"timed out waiting for the hooks-ready handshake (5s) - hooks did not initialize in time");
    } else {
        Log(L"handshake wait failed" + WinError(GetLastError()));
    }
    CloseHandle(readyEvent);
    CloseHandle(hProcess);
    return (w == WAIT_OBJECT_0) ? 0 : 1;
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) {
        PrintUsage();
        return 1;
    }
    if (wcscmp(argv[1], L"--help") == 0 || wcscmp(argv[1], L"-h") == 0) {
        PrintUsage();
        return 0;
    }
    if (wcscmp(argv[1], L"--pid") == 0) {
        if (argc < 3) {
            PrintUsage();
            return 1;
        }
        wchar_t* end = nullptr;
        unsigned long pid = wcstoul(argv[2], &end, 10);
        if (end == argv[2] || pid == 0) {
            Log(L"invalid pid: " + std::wstring(argv[2]));
            return 1;
        }
        return RunMethodB(static_cast<DWORD>(pid));
    }
    std::wstring target = argv[1];
    std::vector<std::wstring> args;
    for (int i = 2; i < argc; ++i) {
        args.push_back(argv[i]);
    }
    return RunMethodA(target, args);
}
