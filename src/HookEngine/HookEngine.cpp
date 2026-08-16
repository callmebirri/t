#include "HookEngine/HookEngine.h"
#include "HookEngine/hook_common.h"
#include "IpcClient/IpcClient.h"
#include "IpcCommon/IpcCommon.h"

#include <MinHook.h>

#include <windows.h>

#include <atomic>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace hook_engine {

static std::atomic<bool> g_initialized{false};
static std::atomic<bool> g_winhttpInstalled{false};
static std::atomic<bool> g_schannelInstalled{false};
static std::mutex g_installMutex;
static std::vector<std::pair<std::string, uint32_t>> g_failures;
static std::mutex g_failuresMutex;
static HANDLE g_lateBindThread = nullptr;

void InstallWinhttpHooksNow();
void InstallSchannelHooksNow();

void RecordFailure(const std::string& name, uint32_t code) {
    std::lock_guard<std::mutex> lock(g_failuresMutex);
    g_failures.emplace_back(name, code);
}

static void InstallWinhttpHooks() {
    std::lock_guard<std::mutex> lock(g_installMutex);
    if (g_winhttpInstalled.load()) {
        return;
    }
    HMODULE mod = GetModuleHandleW(L"winhttp.dll");
    if (!mod) {
        return;
    }
    InstallWinhttpHooksNow();
    g_winhttpInstalled = true;
}

static void InstallSchannelHooks() {
    std::lock_guard<std::mutex> lock(g_installMutex);
    if (g_schannelInstalled.load()) {
        return;
    }
    HMODULE schannel = GetModuleHandleW(L"schannel.dll");
    if (!schannel) {
        schannel = GetModuleHandleW(L"ncrypt.dll");
    }
    if (!schannel) {
        return;
    }
    InstallSchannelHooksNow();
    g_schannelInstalled = true;
}

static DWORD WINAPI LateBindThreadMain(LPVOID) {
    while (!hook_common::ShuttingDown().load()) {
        if (!g_winhttpInstalled.load() && GetModuleHandleW(L"winhttp.dll")) {
            InstallWinhttpHooks();
        }
        if (!g_schannelInstalled.load()) {
            HMODULE schannel = GetModuleHandleW(L"schannel.dll");
            if (!schannel) {
                schannel = GetModuleHandleW(L"ncrypt.dll");
            }
            if (schannel) {
                InstallSchannelHooks();
            }
        }
        if (g_winhttpInstalled.load() && g_schannelInstalled.load()) {
            break;
        }
        Sleep(100);
    }
    return 0;
}

bool Initialize() {
    if (g_initialized.exchange(true)) {
        return true;
    }
    MH_STATUS st = MH_Initialize();
    if (st != MH_OK && st != MH_ERROR_ALREADY_INITIALIZED) {
        return false;
    }
    if (GetModuleHandleW(L"winhttp.dll")) {
        InstallWinhttpHooks();
    }
    HMODULE schannel = GetModuleHandleW(L"schannel.dll");
    if (!schannel) {
        schannel = GetModuleHandleW(L"ncrypt.dll");
    }
    if (schannel) {
        InstallSchannelHooks();
    }
    g_lateBindThread = CreateThread(nullptr, 0, LateBindThreadMain, nullptr, 0, nullptr);
    return true;
}

void Shutdown() {
    hook_common::ShuttingDown().store(true);
    {
        std::lock_guard<std::mutex> lock(g_installMutex);
        if (g_lateBindThread) {
            WaitForSingleObject(g_lateBindThread, 500);
            CloseHandle(g_lateBindThread);
            g_lateBindThread = nullptr;
        }
    }
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
}

void SendHookStatus() {
    ipc::PayloadWriter w;
    w.U32(WinhttpInstalledMask());
    w.U32(SchannelInstalledMask());
    std::vector<std::pair<std::string, uint32_t>> failures;
    {
        std::lock_guard<std::mutex> lock(g_failuresMutex);
        failures = g_failures;
    }
    w.U16(static_cast<uint16_t>(failures.size()));
    for (const auto& f : failures) {
        w.Str(f.first);
        w.U32(f.second);
    }
    ipc::IpcClient::Instance().SendPayload(ipc::MsgType::HookStatus, 0, w.Take());
}

}  // namespace hook_engine
