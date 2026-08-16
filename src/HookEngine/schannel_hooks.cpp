#include "HookEngine/HookEngine.h"
#include "HookEngine/hook_common.h"
#include "IpcClient/IpcClient.h"
#include "IpcCommon/IpcCommon.h"

#include <MinHook.h>
#include <windows.h>

#define SECURITY_WIN32
#include <sspi.h>

#include <atomic>
#include <cstddef>
#include <mutex>
#include <string>
#include <unordered_map>

namespace hook_engine {

using InitializeSecurityContextW_t = SECURITY_STATUS(SEC_ENTRY*)(PCredHandle, PCtxtHandle, SEC_WCHAR*, ULONG, ULONG, ULONG, PSecBufferDesc, ULONG, PCtxtHandle, PSecBufferDesc, PULONG, PTimeStamp);
using EncryptMessage_t = SECURITY_STATUS(SEC_ENTRY*)(PCtxtHandle, ULONG, PSecBufferDesc, ULONG);
using DecryptMessage_t = SECURITY_STATUS(SEC_ENTRY*)(PCtxtHandle, PSecBufferDesc, ULONG, PULONG);
using DeleteSecurityContext_t = SECURITY_STATUS(SEC_ENTRY*)(PCtxtHandle);

static InitializeSecurityContextW_t RealInitializeSecurityContextW = nullptr;
static EncryptMessage_t RealEncryptMessage = nullptr;
static DecryptMessage_t RealDecryptMessage = nullptr;
static DeleteSecurityContext_t RealDeleteSecurityContext = nullptr;

static constexpr uint32_t kBitInitializeSecurityContext = 1u << 0;
static constexpr uint32_t kBitEncryptMessage = 1u << 1;
static constexpr uint32_t kBitDecryptMessage = 1u << 2;
static constexpr uint32_t kBitDeleteSecurityContext = 1u << 3;

static std::atomic<uint32_t> g_installedMask{0};

struct CtxKey {
    ULONG_PTR low;
    ULONG_PTR high;
    bool operator==(const CtxKey& other) const {
        return low == other.low && high == other.high;
    }
};

struct CtxKeyHash {
    size_t operator()(const CtxKey& k) const {
        return std::hash<ULONG_PTR>()(k.low) ^ (std::hash<ULONG_PTR>()(k.high) << 1);
    }
};

struct StreamState {
    uint64_t streamId;
    std::string target;
};

static std::mutex g_streamMutex;
static std::unordered_map<CtxKey, StreamState, CtxKeyHash> g_streams;
static std::atomic<uint32_t> g_streamSeq{0};

static bool IsValidCtx(PCtxtHandle ctx) {
    return ctx != nullptr && ctx->dwLower != 0 && ctx->dwUpper != 0;
}

static CtxKey KeyOf(PCtxtHandle ctx) {
    CtxKey k{};
    if (ctx) {
        k.low = ctx->dwLower;
        k.high = ctx->dwUpper;
    }
    return k;
}

static uint64_t FindStream(PCtxtHandle ctx) {
    CtxKey k = KeyOf(ctx);
    if (k.low == 0 && k.high == 0) {
        return 0;
    }
    std::lock_guard<std::mutex> lock(g_streamMutex);
    auto it = g_streams.find(k);
    return it == g_streams.end() ? 0 : it->second.streamId;
}

static uint64_t TakeStream(PCtxtHandle ctx) {
    CtxKey k = KeyOf(ctx);
    if (k.low == 0 && k.high == 0) {
        return 0;
    }
    std::lock_guard<std::mutex> lock(g_streamMutex);
    auto it = g_streams.find(k);
    if (it == g_streams.end()) {
        return 0;
    }
    uint64_t id = it->second.streamId;
    g_streams.erase(it);
    return id;
}

static std::string CollectDataBuffers(PSecBufferDesc desc, bool fallbackToStream) {
    if (!desc) {
        return {};
    }
    std::string out;
    bool haveData = false;
    for (ULONG i = 0; i < desc->cBuffers; ++i) {
        SecBuffer& buf = desc->pBuffers[i];
        if (buf.BufferType == SECBUFFER_DATA && buf.cbBuffer > 0 && buf.pvBuffer) {
            out.append(static_cast<const char*>(buf.pvBuffer), buf.cbBuffer);
            haveData = true;
        }
    }
    if (!haveData && fallbackToStream) {
        for (ULONG i = 0; i < desc->cBuffers; ++i) {
            SecBuffer& buf = desc->pBuffers[i];
            if (buf.BufferType == SECBUFFER_STREAM && buf.cbBuffer > 0 && buf.pvBuffer) {
                out.append(static_cast<const char*>(buf.pvBuffer), buf.cbBuffer);
                break;
            }
        }
    }
    return out;
}

static void SendStreamData(uint64_t streamId, ipc::MsgType type, const std::string& data) {
    if (data.empty()) {
        return;
    }
    ipc::PayloadWriter w;
    w.Bytes(data.data(), data.size());
    ipc::IpcClient::Instance().SendPayload(type, streamId, w.Take());
}

static void SendStreamEnd(uint64_t streamId) {
    ipc::PayloadWriter w;
    w.U32(0);
    ipc::IpcClient::Instance().SendPayload(ipc::MsgType::SchannelStreamEnd, streamId, w.Take());
}

SECURITY_STATUS SEC_ENTRY InitializeSecurityContextWHook(PCredHandle cred, PCtxtHandle ctx, SEC_WCHAR* targetName, ULONG contextReq, ULONG reserved1, ULONG targetDataRep, PSecBufferDesc input, ULONG reserved2, PCtxtHandle newCtx, PSecBufferDesc output, PULONG contextAttr, PTimeStamp expiry) {
    if (hook_common::ShuttingDown().load() || hook_common::InsideWinhttpHook() || hook_common::InsideSchannelHook()) {
        return RealInitializeSecurityContextW(cred, ctx, targetName, contextReq, reserved1, targetDataRep, input, reserved2, newCtx, output, contextAttr, expiry);
    }
    hook_common::SchannelGuard guard;
    SECURITY_STATUS st = RealInitializeSecurityContextW(cred, ctx, targetName, contextReq, reserved1, targetDataRep, input, reserved2, newCtx, output, contextAttr, expiry);
    bool progressed = st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED || st == SEC_I_COMPLETE_NEEDED || st == SEC_I_COMPLETE_AND_CONTINUE || st == SEC_I_INCOMPLETE_CREDENTIALS;
    if (!progressed) {
        return st;
    }
    bool isNew = !IsValidCtx(ctx);
    PCtxtHandle resolved = isNew ? newCtx : ctx;
    if (!IsValidCtx(resolved)) {
        return st;
    }
    CtxKey key = KeyOf(resolved);
    uint64_t streamId = 0;
    bool created = false;
    {
        std::lock_guard<std::mutex> lock(g_streamMutex);
        auto it = g_streams.find(key);
        if (it == g_streams.end()) {
            streamId = (static_cast<uint64_t>(GetCurrentThreadId()) << 32) | g_streamSeq.fetch_add(1);
            std::string target = targetName ? ipc::WideToUtf8(targetName) : std::string();
            g_streams[key] = StreamState{streamId, target};
            created = true;
        } else {
            streamId = it->second.streamId;
        }
    }
    if (created) {
        ipc::PayloadWriter w;
        w.Str(targetName ? ipc::WideToUtf8(targetName) : std::string());
        ipc::IpcClient::Instance().SendPayload(ipc::MsgType::SchannelHandshake, streamId, w.Take());
    }
    return st;
}

SECURITY_STATUS SEC_ENTRY EncryptMessageHook(PCtxtHandle ctx, ULONG qualityOfProtection, PSecBufferDesc message, ULONG messageSeqNo) {
    if (hook_common::ShuttingDown().load() || hook_common::InsideWinhttpHook() || hook_common::InsideSchannelHook()) {
        return RealEncryptMessage(ctx, qualityOfProtection, message, messageSeqNo);
    }
    hook_common::SchannelGuard guard;
    uint64_t streamId = FindStream(ctx);
    std::string plaintext;
    if (streamId != 0) {
        plaintext = CollectDataBuffers(message, true);
    }
    SECURITY_STATUS st = RealEncryptMessage(ctx, qualityOfProtection, message, messageSeqNo);
    if (st == SEC_E_OK && streamId != 0) {
        SendStreamData(streamId, ipc::MsgType::SchannelDataSend, plaintext);
    }
    return st;
}

SECURITY_STATUS SEC_ENTRY DecryptMessageHook(PCtxtHandle ctx, PSecBufferDesc message, ULONG messageSeqNo, PULONG qualityOfProtection) {
    if (hook_common::ShuttingDown().load() || hook_common::InsideWinhttpHook() || hook_common::InsideSchannelHook()) {
        return RealDecryptMessage(ctx, message, messageSeqNo, qualityOfProtection);
    }
    hook_common::SchannelGuard guard;
    SECURITY_STATUS st = RealDecryptMessage(ctx, message, messageSeqNo, qualityOfProtection);
    if (st == SEC_E_OK) {
        uint64_t streamId = FindStream(ctx);
        if (streamId != 0) {
            std::string plaintext = CollectDataBuffers(message, false);
            SendStreamData(streamId, ipc::MsgType::SchannelDataRecv, plaintext);
        }
    } else if (st == SEC_E_CONTEXT_EXPIRED) {
        uint64_t streamId = TakeStream(ctx);
        if (streamId != 0) {
            SendStreamEnd(streamId);
        }
    }
    return st;
}

SECURITY_STATUS SEC_ENTRY DeleteSecurityContextHook(PCtxtHandle ctx) {
    if (hook_common::ShuttingDown().load() || hook_common::InsideWinhttpHook() || hook_common::InsideSchannelHook()) {
        return RealDeleteSecurityContext(ctx);
    }
    hook_common::SchannelGuard guard;
    SECURITY_STATUS st = RealDeleteSecurityContext(ctx);
    if (st == SEC_E_OK) {
        uint64_t streamId = TakeStream(ctx);
        if (streamId != 0) {
            SendStreamEnd(streamId);
        }
    }
    return st;
}

static void InstallOneSchannel(HMODULE mod, const char* name, void* detour, void** trampoline, uint32_t bit) {
    FARPROC p = GetProcAddress(mod, name);
    if (!p) {
        RecordFailure(name, 0);
        return;
    }
    MH_STATUS st = MH_CreateHook(p, detour, trampoline);
    if (st != MH_OK) {
        RecordFailure(name, static_cast<uint32_t>(st));
        return;
    }
    st = MH_EnableHook(p);
    if (st != MH_OK) {
        RecordFailure(name, static_cast<uint32_t>(st));
        return;
    }
    g_installedMask.fetch_or(bit);
}

void InstallSchannelHooksNow() {
    HMODULE mod = GetModuleHandleW(L"secur32.dll");
    if (!mod) {
        return;
    }
    InstallOneSchannel(mod, "InitializeSecurityContextW", reinterpret_cast<void*>(&InitializeSecurityContextWHook), reinterpret_cast<void**>(&RealInitializeSecurityContextW), kBitInitializeSecurityContext);
    InstallOneSchannel(mod, "EncryptMessage", reinterpret_cast<void*>(&EncryptMessageHook), reinterpret_cast<void**>(&RealEncryptMessage), kBitEncryptMessage);
    InstallOneSchannel(mod, "DecryptMessage", reinterpret_cast<void*>(&DecryptMessageHook), reinterpret_cast<void**>(&RealDecryptMessage), kBitDecryptMessage);
    InstallOneSchannel(mod, "DeleteSecurityContext", reinterpret_cast<void*>(&DeleteSecurityContextHook), reinterpret_cast<void**>(&RealDeleteSecurityContext), kBitDeleteSecurityContext);
}

uint32_t SchannelInstalledMask() {
    return g_installedMask.load();
}

}  // namespace hook_engine
