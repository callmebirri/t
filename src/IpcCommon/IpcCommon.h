#pragma once

#include <windows.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace ipc {

constexpr uint32_t kMagic = 0x42495252;
constexpr uint32_t kVersion = 1;
constexpr uint32_t kMaxMessageSize = 16 * 1024 * 1024;
constexpr uint32_t kMaxQueuedMessages = 2048;
constexpr uint32_t kBodyLimitBytes = 64 * 1024 * 1024;
constexpr uint32_t kWriteTimeoutMs = 3000;
constexpr uint32_t kConnectTimeoutMs = 3000;
constexpr wchar_t kPipeName[] = L"\\\\.\\pipe\\BirriMonitorIpc";
constexpr wchar_t kHooksReadyEventName[] = L"Local\\BirriMonitorHooksReady";
constexpr wchar_t kLoggerMutexName[] = L"Local\\BirriMonitorLoggerMutex";

enum class MsgType : uint32_t {
    Hello = 1,
    TransactionStart = 2,
    TransactionBody = 3,
    ResponseHeaders = 4,
    ResponseEnd = 5,
    TransactionEnd = 6,
    DropCount = 7,
    HookStatus = 8,
    SchannelHandshake = 0x10,
    SchannelDataSend = 0x11,
    SchannelDataRecv = 0x12,
    SchannelStreamEnd = 0x13,
};

enum TransactionFlags : uint32_t {
    kTransactionHasRequestBody = 0x00000001,
    kTransactionRequestTruncated = 0x00000002,
    kTransactionResponseTruncated = 0x00000004,
};

enum BodyDirection : uint8_t {
    kBodyRequest = 1,
    kBodyResponse = 2,
};

#pragma pack(push, 1)
struct WireHeader {
    uint32_t magic;
    uint32_t version;
    uint32_t type;
    uint32_t flags;
    uint64_t requestId;
    uint32_t pid;
    uint32_t reserved;
    uint64_t timestampMs;
    uint32_t payloadLength;
};
#pragma pack(pop)

static_assert(sizeof(WireHeader) == 44, "WireHeader layout mismatch");

struct Message {
    WireHeader header;
    std::vector<uint8_t> payload;
};

inline uint64_t NowMs() {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    uint64_t t = (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    return (t - 116444736000000000ULL) / 10000;
}

inline Message MakeMessage(MsgType type, uint64_t requestId, std::vector<uint8_t> payload) {
    Message msg;
    msg.header.magic = kMagic;
    msg.header.version = kVersion;
    msg.header.type = static_cast<uint32_t>(type);
    msg.header.flags = 0;
    msg.header.requestId = requestId;
    msg.header.pid = GetCurrentProcessId();
    msg.header.reserved = 0;
    msg.header.timestampMs = NowMs();
    msg.header.payloadLength = static_cast<uint32_t>(payload.size());
    msg.payload = std::move(payload);
    return msg;
}

inline std::vector<uint8_t> SerializeMessage(const Message& msg) {
    std::vector<uint8_t> out(sizeof(WireHeader) + msg.payload.size());
    std::memcpy(out.data(), &msg.header, sizeof(WireHeader));
    if (!msg.payload.empty()) {
        std::memcpy(out.data() + sizeof(WireHeader), msg.payload.data(), msg.payload.size());
    }
    return out;
}

inline bool DeserializeMessage(const uint8_t* data, size_t len, Message& out) {
    if (len < sizeof(WireHeader)) {
        return false;
    }
    WireHeader hdr;
    std::memcpy(&hdr, data, sizeof(WireHeader));
    if (hdr.magic != kMagic) {
        return false;
    }
    if (hdr.version != kVersion) {
        return false;
    }
    if (hdr.payloadLength > kMaxMessageSize) {
        return false;
    }
    if (len < sizeof(WireHeader) + static_cast<size_t>(hdr.payloadLength)) {
        return false;
    }
    out.header = hdr;
    out.payload.assign(data + sizeof(WireHeader), data + sizeof(WireHeader) + hdr.payloadLength);
    return true;
}

class PayloadWriter {
public:
    void U8(uint8_t v) { Push(&v, sizeof(v)); }
    void U16(uint16_t v) { Push(&v, sizeof(v)); }
    void U32(uint32_t v) { Push(&v, sizeof(v)); }
    void U64(uint64_t v) { Push(&v, sizeof(v)); }
    void Str(const std::string& s) {
        U16(static_cast<uint16_t>(s.size()));
        Push(s.data(), s.size());
    }
    void Bytes(const void* p, size_t n) { Push(p, n); }
    std::vector<uint8_t> Take() { return std::move(buf_); }

private:
    void Push(const void* p, size_t n) {
        const uint8_t* b = static_cast<const uint8_t*>(p);
        buf_.insert(buf_.end(), b, b + n);
    }
    std::vector<uint8_t> buf_;
};

class PayloadReader {
public:
    PayloadReader(const uint8_t* p, size_t n) : p_(p), n_(n) {}

    bool Ok() const { return !failed_; }

    uint8_t U8() {
        uint8_t v = 0;
        Read(&v, sizeof(v));
        return v;
    }

    uint16_t U16() {
        uint16_t v = 0;
        Read(&v, sizeof(v));
        return v;
    }

    uint32_t U32() {
        uint32_t v = 0;
        Read(&v, sizeof(v));
        return v;
    }

    uint64_t U64() {
        uint64_t v = 0;
        Read(&v, sizeof(v));
        return v;
    }

    std::string Str() {
        uint16_t len = U16();
        if (failed_ || pos_ + len > n_) {
            failed_ = true;
            return {};
        }
        std::string s(reinterpret_cast<const char*>(p_ + pos_), len);
        pos_ += len;
        return s;
    }

    std::string BytesN() {
        uint32_t len = U32();
        if (failed_ || pos_ + len > n_) {
            failed_ = true;
            return {};
        }
        std::string s(reinterpret_cast<const char*>(p_ + pos_), len);
        pos_ += len;
        return s;
    }

    void Skip(size_t n) {
        if (failed_ || pos_ + n > n_) {
            failed_ = true;
            return;
        }
        pos_ += n;
    }

private:
    void Read(void* out, size_t sz) {
        if (failed_ || pos_ + sz > n_) {
            failed_ = true;
            std::memset(out, 0, sz);
            return;
        }
        std::memcpy(out, p_ + pos_, sz);
        pos_ += sz;
    }

    const uint8_t* p_;
    size_t n_;
    size_t pos_ = 0;
    bool failed_ = false;
};

inline std::string WideToUtf8(const wchar_t* w, size_t len) {
    if (len == 0) {
        return {};
    }
    int n = WideCharToMultiByte(CP_UTF8, 0, w, static_cast<int>(len), nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, static_cast<int>(len), out.data(), n, nullptr, nullptr);
    return out;
}

inline std::string WideToUtf8(const wchar_t* w) {
    if (w == nullptr) {
        return {};
    }
    return WideToUtf8(w, wcslen(w));
}

inline std::string WideToUtf8(const std::wstring& w) {
    return WideToUtf8(w.data(), w.size());
}

}  // namespace ipc
