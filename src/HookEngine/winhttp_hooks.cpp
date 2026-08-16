#include "HookEngine/HookEngine.h"
#include "HookEngine/hook_common.h"
#include "IpcClient/IpcClient.h"
#include "IpcCommon/IpcCommon.h"

#include <MinHook.h>
#include <windows.h>
#include <winhttp.h>

#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>

namespace hook_engine {

using WinHttpConnect_t = HINTERNET(WINAPI*)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
using WinHttpOpenRequest_t = HINTERNET(WINAPI*)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
using WinHttpAddRequestHeaders_t = BOOL(WINAPI*)(HINTERNET, LPCWSTR, DWORD, DWORD);
using WinHttpSendRequest_t = BOOL(WINAPI*)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
using WinHttpWriteData_t = BOOL(WINAPI*)(HINTERNET, LPCVOID, DWORD, LPDWORD);
using WinHttpReceiveResponse_t = BOOL(WINAPI*)(HINTERNET, LPVOID);
using WinHttpQueryDataAvailable_t = BOOL(WINAPI*)(HINTERNET, LPDWORD);
using WinHttpReadData_t = BOOL(WINAPI*)(HINTERNET, LPVOID, DWORD, LPDWORD);
using WinHttpCloseHandle_t = BOOL(WINAPI*)(HINTERNET);

static WinHttpConnect_t RealWinHttpConnect = nullptr;
static WinHttpOpenRequest_t RealWinHttpOpenRequest = nullptr;
static WinHttpAddRequestHeaders_t RealWinHttpAddRequestHeaders = nullptr;
static WinHttpSendRequest_t RealWinHttpSendRequest = nullptr;
static WinHttpWriteData_t RealWinHttpWriteData = nullptr;
static WinHttpReceiveResponse_t RealWinHttpReceiveResponse = nullptr;
static WinHttpQueryDataAvailable_t RealWinHttpQueryDataAvailable = nullptr;
static WinHttpReadData_t RealWinHttpReadData = nullptr;
static WinHttpCloseHandle_t RealWinHttpCloseHandle = nullptr;

static constexpr uint32_t kBitConnect = 1u << 0;
static constexpr uint32_t kBitOpenRequest = 1u << 1;
static constexpr uint32_t kBitAddRequestHeaders = 1u << 2;
static constexpr uint32_t kBitSendRequest = 1u << 3;
static constexpr uint32_t kBitWriteData = 1u << 4;
static constexpr uint32_t kBitReceiveResponse = 1u << 5;
static constexpr uint32_t kBitQueryDataAvailable = 1u << 6;
static constexpr uint32_t kBitReadData = 1u << 7;
static constexpr uint32_t kBitCloseHandle = 1u << 8;

static std::atomic<uint32_t> g_installedMask{0};

struct ConnectInfo {
    std::string host;
    uint16_t port = 0;
};

struct RequestState {
    HINTERNET hConnect = nullptr;
    uint64_t id = 0;
    std::string method;
    std::string path;
    std::string protocol;
    DWORD flags = 0;
    std::string extraHeaders;
    bool started = false;
    bool responseEnded = false;
    uint64_t requestBytes = 0;
    uint64_t responseBytes = 0;
    bool requestTruncated = false;
    bool responseTruncated = false;
};

static std::shared_mutex g_stateMutex;
static std::unordered_map<HINTERNET, ConnectInfo> g_connects;
static std::unordered_map<HINTERNET, RequestState> g_requests;
static std::atomic<uint64_t> g_nextRequestId{1};

static std::string NormalizeLines(const std::string& in) {
    std::string out;
    size_t pos = 0;
    bool first = true;
    while (pos <= in.size()) {
        size_t eol = in.find('\n', pos);
        size_t end = (eol == std::string::npos) ? in.size() : eol;
        size_t len = end - pos;
        while (len > 0 && (in[pos + len - 1] == '\r' || in[pos + len - 1] == ' ' || in[pos + len - 1] == '\t')) {
            --len;
        }
        std::string line = in.substr(pos, len);
        size_t start = 0;
        while (start < line.size() && (line[start] == ' ' || line[start] == '\t')) {
            ++start;
        }
        line = line.substr(start);
        if (!line.empty()) {
            if (!first) {
                out += "\r\n";
            }
            out += line;
            first = false;
        }
        if (eol == std::string::npos) {
            break;
        }
        pos = eol + 1;
    }
    return out;
}

static void SendBodyChunk(uint64_t id, uint8_t direction, const void* data, size_t len, uint64_t total) {
    ipc::PayloadWriter w;
    w.U8(direction);
    w.U64(total);
    w.U8(0);
    w.BytesN(data, len);
    ipc::IpcClient::Instance().SendPayload(ipc::MsgType::TransactionBody, id, w.Take());
}

static void TrackRequestBody(HINTERNET hRequest, uint64_t id, const void* data, size_t len) {
    uint64_t total = 0;
    bool sendChunk = false;
    {
        std::lock_guard<std::shared_mutex> lock(g_stateMutex);
        auto it = g_requests.find(hRequest);
        if (it == g_requests.end()) {
            return;
        }
        it->second.requestBytes += len;
        total = it->second.requestBytes;
        if (total <= ipc::kBodyLimitBytes) {
            sendChunk = true;
        } else {
            it->second.requestTruncated = true;
        }
    }
    if (sendChunk) {
        SendBodyChunk(id, ipc::kBodyRequest, data, len, total);
    }
}

static void TrackResponseBody(HINTERNET hRequest, uint64_t id, const void* data, size_t len) {
    uint64_t total = 0;
    bool sendChunk = false;
    {
        std::lock_guard<std::shared_mutex> lock(g_stateMutex);
        auto it = g_requests.find(hRequest);
        if (it == g_requests.end()) {
            return;
        }
        it->second.responseBytes += len;
        total = it->second.responseBytes;
        if (total <= ipc::kBodyLimitBytes) {
            sendChunk = true;
        } else {
            it->second.responseTruncated = true;
        }
    }
    if (sendChunk) {
        SendBodyChunk(id, ipc::kBodyResponse, data, len, total);
    }
}

static std::string QueryRawResponseHeaders(HINTERNET hRequest) {
    DWORD size = 0;
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, nullptr, &size, WINHTTP_NO_HEADER_INDEX);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || size == 0) {
        return {};
    }
    std::wstring buf(static_cast<size_t>(size) / sizeof(wchar_t), L'\0');
    if (!WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, buf.data(), &size, WINHTTP_NO_HEADER_INDEX)) {
        return {};
    }
    return ipc::WideToUtf8(buf);
}

static void MarkResponseEnded(HINTERNET hRequest) {
    uint64_t id = 0;
    {
        std::lock_guard<std::shared_mutex> lock(g_stateMutex);
        auto it = g_requests.find(hRequest);
        if (it == g_requests.end() || it->second.responseEnded) {
            return;
        }
        it->second.responseEnded = true;
        id = it->second.id;
    }
    ipc::IpcClient::Instance().SendPayload(ipc::MsgType::ResponseEnd, id, {});
}

HINTERNET WINAPI WinHttpConnectHook(HINTERNET hSession, LPCWSTR host, INTERNET_PORT port, DWORD reserved) {
    if (hook_common::ShuttingDown().load() || hook_common::InsideWinhttpHook()) {
        return RealWinHttpConnect(hSession, host, port, reserved);
    }
    hook_common::WinhttpGuard guard;
    HINTERNET h = RealWinHttpConnect(hSession, host, port, reserved);
    if (h) {
        ConnectInfo ci;
        ci.host = ipc::WideToUtf8(host);
        ci.port = static_cast<uint16_t>(port);
        std::lock_guard<std::shared_mutex> lock(g_stateMutex);
        g_connects[h] = std::move(ci);
    }
    return h;
}

HINTERNET WINAPI WinHttpOpenRequestHook(HINTERNET hConnect, LPCWSTR verb, LPCWSTR object, LPCWSTR version, LPCWSTR referrer, LPCWSTR* acceptTypes, DWORD flags) {
    if (hook_common::ShuttingDown().load() || hook_common::InsideWinhttpHook()) {
        return RealWinHttpOpenRequest(hConnect, verb, object, version, referrer, acceptTypes, flags);
    }
    hook_common::WinhttpGuard guard;
    HINTERNET h = RealWinHttpOpenRequest(hConnect, verb, object, version, referrer, acceptTypes, flags);
    if (h) {
        RequestState st;
        st.hConnect = hConnect;
        st.id = g_nextRequestId.fetch_add(1);
        st.method = (verb && verb[0]) ? ipc::WideToUtf8(verb) : "GET";
        st.path = object ? ipc::WideToUtf8(object) : "/";
        if (st.path.empty() || st.path[0] != '/') {
            st.path = "/" + st.path;
        }
        st.protocol = (version && version[0]) ? ipc::WideToUtf8(version) : "HTTP/1.1";
        st.flags = flags;
        std::lock_guard<std::shared_mutex> lock(g_stateMutex);
        g_requests[h] = std::move(st);
    }
    return h;
}

BOOL WINAPI WinHttpAddRequestHeadersHook(HINTERNET hRequest, LPCWSTR headers, DWORD headersLength, DWORD modifiers) {
    if (hook_common::ShuttingDown().load() || hook_common::InsideWinhttpHook()) {
        return RealWinHttpAddRequestHeaders(hRequest, headers, headersLength, modifiers);
    }
    hook_common::WinhttpGuard guard;
    BOOL ok = RealWinHttpAddRequestHeaders(hRequest, headers, headersLength, modifiers);
    if (ok && headers) {
        std::string text = (headersLength == (DWORD)-1)
                               ? ipc::WideToUtf8(headers)
                               : ipc::WideToUtf8(headers, headersLength);
        std::string normalized = NormalizeLines(text);
        if (!normalized.empty()) {
            std::lock_guard<std::shared_mutex> lock(g_stateMutex);
            auto it = g_requests.find(hRequest);
            if (it != g_requests.end()) {
                if (!it->second.extraHeaders.empty()) {
                    it->second.extraHeaders += "\r\n";
                }
                it->second.extraHeaders += normalized;
            }
        }
    }
    return ok;
}

BOOL WINAPI WinHttpSendRequestHook(HINTERNET hRequest, LPCWSTR headers, DWORD headersLength, LPVOID optional, DWORD optionalLength, DWORD totalLength, DWORD_PTR context) {
    if (hook_common::ShuttingDown().load() || hook_common::InsideWinhttpHook()) {
        return RealWinHttpSendRequest(hRequest, headers, headersLength, optional, optionalLength, totalLength, context);
    }
    hook_common::WinhttpGuard guard;
    std::string sendHeaders;
    if (headers) {
        sendHeaders = (headersLength == (DWORD)-1) ? ipc::WideToUtf8(headers) : ipc::WideToUtf8(headers, headersLength);
    }
    std::string optionalBody;
    if (optional && optionalLength > 0) {
        optionalBody.assign(static_cast<const char*>(optional), optionalLength);
    }

    RequestState st;
    {
        std::lock_guard<std::shared_mutex> lock(g_stateMutex);
        auto it = g_requests.find(hRequest);
        if (it == g_requests.end() || it->second.started) {
            return RealWinHttpSendRequest(hRequest, headers, headersLength, optional, optionalLength, totalLength, context);
        }
        it->second.started = true;
        st = it->second;
    }

    ConnectInfo ci;
    bool haveConnect = false;
    {
        std::shared_lock<std::shared_mutex> lock(g_stateMutex);
        auto it = g_connects.find(st.hConnect);
        if (it != g_connects.end()) {
            ci = it->second;
            haveConnect = true;
        }
    }

    if (haveConnect) {
        std::string scheme = (st.flags & WINHTTP_FLAG_SECURE) ? "https" : "http";
        std::string url = scheme + "://" + ci.host + ":" + std::to_string(ci.port) + st.path;

        std::string headerBlock = "Host: " + ci.host + ":" + std::to_string(ci.port);
        std::string extra = NormalizeLines(st.extraHeaders);
        if (!extra.empty()) {
            headerBlock += "\r\n" + extra;
        }
        std::string sendNorm = NormalizeLines(sendHeaders);
        if (!sendNorm.empty()) {
            headerBlock += "\r\n" + sendNorm;
        }

        ipc::PayloadWriter w;
        w.Str(st.method);
        w.Str(url);
        w.Str(st.protocol);
        w.Str(headerBlock);
        w.U32(optionalBody.empty() ? 0u : ipc::kTransactionHasRequestBody);
        ipc::IpcClient::Instance().SendPayload(ipc::MsgType::TransactionStart, st.id, w.Take());
    }

    BOOL ok = RealWinHttpSendRequest(hRequest, headers, headersLength, optional, optionalLength, totalLength, context);
    if (!ok) {
        return FALSE;
    }
    if (!optionalBody.empty()) {
        TrackRequestBody(hRequest, st.id, optionalBody.data(), optionalBody.size());
    }
    return TRUE;
}

BOOL WINAPI WinHttpWriteDataHook(HINTERNET hRequest, LPCVOID buffer, DWORD numberOfBytesToWrite, LPDWORD numberOfBytesWritten) {
    if (hook_common::ShuttingDown().load() || hook_common::InsideWinhttpHook()) {
        return RealWinHttpWriteData(hRequest, buffer, numberOfBytesToWrite, numberOfBytesWritten);
    }
    hook_common::WinhttpGuard guard;
    BOOL ok = RealWinHttpWriteData(hRequest, buffer, numberOfBytesToWrite, numberOfBytesWritten);
    if (!ok) {
        return FALSE;
    }
    uint64_t id = 0;
    {
        std::shared_lock<std::shared_mutex> lock(g_stateMutex);
        auto it = g_requests.find(hRequest);
        if (it != g_requests.end()) {
            id = it->second.id;
        }
    }
    if (id != 0 && numberOfBytesToWrite > 0) {
        TrackRequestBody(hRequest, id, buffer, numberOfBytesToWrite);
    }
    return TRUE;
}

BOOL WINAPI WinHttpReceiveResponseHook(HINTERNET hRequest, LPVOID reserved) {
    if (hook_common::ShuttingDown().load() || hook_common::InsideWinhttpHook()) {
        return RealWinHttpReceiveResponse(hRequest, reserved);
    }
    hook_common::WinhttpGuard guard;
    BOOL ok = RealWinHttpReceiveResponse(hRequest, reserved);
    if (!ok) {
        return FALSE;
    }
    uint64_t id = 0;
    {
        std::shared_lock<std::shared_mutex> lock(g_stateMutex);
        auto it = g_requests.find(hRequest);
        if (it != g_requests.end()) {
            id = it->second.id;
        }
    }
    if (id != 0) {
        std::string raw = QueryRawResponseHeaders(hRequest);
        if (!raw.empty()) {
            ipc::PayloadWriter w;
            w.Str(raw);
            ipc::IpcClient::Instance().SendPayload(ipc::MsgType::ResponseHeaders, id, w.Take());
        }
    }
    return TRUE;
}

BOOL WINAPI WinHttpQueryDataAvailableHook(HINTERNET hRequest, LPDWORD numberOfBytesAvailable) {
    if (hook_common::ShuttingDown().load() || hook_common::InsideWinhttpHook()) {
        return RealWinHttpQueryDataAvailable(hRequest, numberOfBytesAvailable);
    }
    hook_common::WinhttpGuard guard;
    BOOL ok = RealWinHttpQueryDataAvailable(hRequest, numberOfBytesAvailable);
    if (ok && numberOfBytesAvailable && *numberOfBytesAvailable == 0) {
        MarkResponseEnded(hRequest);
    }
    return ok;
}

BOOL WINAPI WinHttpReadDataHook(HINTERNET hRequest, LPVOID buffer, DWORD numberOfBytesToRead, LPDWORD numberOfBytesRead) {
    if (hook_common::ShuttingDown().load() || hook_common::InsideWinhttpHook()) {
        return RealWinHttpReadData(hRequest, buffer, numberOfBytesToRead, numberOfBytesRead);
    }
    hook_common::WinhttpGuard guard;
    BOOL ok = RealWinHttpReadData(hRequest, buffer, numberOfBytesToRead, numberOfBytesRead);
    if (!ok) {
        DWORD err = GetLastError();
        if (err == ERROR_MORE_DATA && numberOfBytesRead && *numberOfBytesRead > 0) {
            ok = TRUE;
        } else {
            return FALSE;
        }
    }
    if (!numberOfBytesRead || *numberOfBytesRead == 0) {
        return TRUE;
    }
    uint64_t id = 0;
    {
        std::shared_lock<std::shared_mutex> lock(g_stateMutex);
        auto it = g_requests.find(hRequest);
        if (it != g_requests.end()) {
            id = it->second.id;
        }
    }
    if (id != 0) {
        TrackResponseBody(hRequest, id, buffer, *numberOfBytesRead);
    }
    return TRUE;
}

BOOL WINAPI WinHttpCloseHandleHook(HINTERNET hInternet) {
    RequestState st;
    bool found = false;
    if (hook_common::ShuttingDown().load() || hook_common::InsideWinhttpHook()) {
        return RealWinHttpCloseHandle(hInternet);
    }
    hook_common::WinhttpGuard guard;
    {
        std::lock_guard<std::shared_mutex> lock(g_stateMutex);
        auto it = g_requests.find(hInternet);
        if (it != g_requests.end()) {
            st = it->second;
            g_requests.erase(it);
            found = true;
        }
        auto cit = g_connects.find(hInternet);
        if (cit != g_connects.end()) {
            g_connects.erase(cit);
        }
    }
    BOOL ok = RealWinHttpCloseHandle(hInternet);
    if (found) {
        uint32_t flags = 0;
        if (st.requestTruncated) {
            flags |= ipc::kTransactionRequestTruncated;
        }
        if (st.responseTruncated) {
            flags |= ipc::kTransactionResponseTruncated;
        }
        ipc::PayloadWriter w;
        w.U32(flags);
        w.U64(st.requestBytes);
        w.U64(st.responseBytes);
        ipc::IpcClient::Instance().SendPayload(ipc::MsgType::TransactionEnd, st.id, w.Take());
    }
    return ok;
}

static void InstallOneWinhttp(HMODULE mod, const char* name, void* detour, void** trampoline, uint32_t bit) {
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

void InstallWinhttpHooksNow() {
    HMODULE mod = GetModuleHandleW(L"winhttp.dll");
    if (!mod) {
        return;
    }
    InstallOneWinhttp(mod, "WinHttpConnect", reinterpret_cast<void*>(&WinHttpConnectHook), reinterpret_cast<void**>(&RealWinHttpConnect), kBitConnect);
    InstallOneWinhttp(mod, "WinHttpOpenRequest", reinterpret_cast<void*>(&WinHttpOpenRequestHook), reinterpret_cast<void**>(&RealWinHttpOpenRequest), kBitOpenRequest);
    InstallOneWinhttp(mod, "WinHttpAddRequestHeaders", reinterpret_cast<void*>(&WinHttpAddRequestHeadersHook), reinterpret_cast<void**>(&RealWinHttpAddRequestHeaders), kBitAddRequestHeaders);
    InstallOneWinhttp(mod, "WinHttpSendRequest", reinterpret_cast<void*>(&WinHttpSendRequestHook), reinterpret_cast<void**>(&RealWinHttpSendRequest), kBitSendRequest);
    InstallOneWinhttp(mod, "WinHttpWriteData", reinterpret_cast<void*>(&WinHttpWriteDataHook), reinterpret_cast<void**>(&RealWinHttpWriteData), kBitWriteData);
    InstallOneWinhttp(mod, "WinHttpReceiveResponse", reinterpret_cast<void*>(&WinHttpReceiveResponseHook), reinterpret_cast<void**>(&RealWinHttpReceiveResponse), kBitReceiveResponse);
    InstallOneWinhttp(mod, "WinHttpQueryDataAvailable", reinterpret_cast<void*>(&WinHttpQueryDataAvailableHook), reinterpret_cast<void**>(&RealWinHttpQueryDataAvailable), kBitQueryDataAvailable);
    InstallOneWinhttp(mod, "WinHttpReadData", reinterpret_cast<void*>(&WinHttpReadDataHook), reinterpret_cast<void**>(&RealWinHttpReadData), kBitReadData);
    InstallOneWinhttp(mod, "WinHttpCloseHandle", reinterpret_cast<void*>(&WinHttpCloseHandleHook), reinterpret_cast<void**>(&RealWinHttpCloseHandle), kBitCloseHandle);
}

uint32_t WinhttpInstalledMask() {
    return g_installedMask.load();
}

}  // namespace hook_engine
