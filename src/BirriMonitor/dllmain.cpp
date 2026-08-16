#include "HookEngine/HookEngine.h"
#include "HookEngine/hook_common.h"
#include "IpcClient/IpcClient.h"
#include "IpcCommon/IpcCommon.h"

#include <windows.h>

#include <atomic>

static std::atomic<bool> g_initStarted{false};

static DWORD WINAPI InitThreadMain(LPVOID) {
    ipc::IpcClient::Instance().Start();
    hook_engine::Initialize();
    uint32_t waitedMs = 0;
    while (waitedMs < 10000) {
        if (ipc::IpcClient::Instance().IsConnected() || hook_common::ShuttingDown().load()) {
            break;
        }
        Sleep(50);
        waitedMs += 50;
    }
    if (ipc::IpcClient::Instance().IsConnected()) {
        hook_engine::SendHookStatus();
        HANDLE ready = OpenEventW(EVENT_MODIFY_STATE, FALSE, ipc::kHooksReadyEventName);
        if (ready) {
            SetEvent(ready);
            CloseHandle(ready);
        }
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        if (!g_initStarted.exchange(true)) {
            HANDLE thread = CreateThread(nullptr, 0, InitThreadMain, nullptr, 0, nullptr);
            if (thread) {
                CloseHandle(thread);
            }
        }
    } else if (reason == DLL_PROCESS_DETACH) {
        if (lpReserved == nullptr) {
            hook_engine::Shutdown();
            ipc::IpcClient::Instance().Stop();
        }
    }
    return TRUE;
}
