#include "IpcClient/IpcClient.h"

#include <algorithm>
#include <chrono>

namespace ipc {

IpcClient& IpcClient::Instance() {
    static IpcClient instance;
    return instance;
}

void IpcClient::Start() {
    stopping_ = false;
    thread_ = std::thread(&IpcClient::ThreadMain, this);
}

void IpcClient::Stop() {
    stopping_ = true;
    queueCv_.notify_all();
    if (pipe_ != INVALID_HANDLE_VALUE) {
        CancelIoEx(pipe_, nullptr);
    }
    if (thread_.joinable()) {
        thread_.join();
    }
    ClosePipe();
    connected_ = false;
}

void IpcClient::SendPayload(MsgType type, uint64_t requestId, std::vector<uint8_t> payload) {
    if (stopping_.load()) {
        return;
    }
    try {
        Message msg = MakeMessage(type, requestId, std::move(payload));
        std::lock_guard<std::mutex> lock(queueMutex_);
        if (queue_.size() >= kMaxQueuedMessages) {
            queue_.pop_back();
            dropped_.fetch_add(1);
        }
        queue_.push_back(std::move(msg));
        queueCv_.notify_one();
    } catch (...) {
        dropped_.fetch_add(1);
    }
}

bool IpcClient::ConnectPipe() {
    HANDLE h = CreateFileW(kPipeName, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err != ERROR_PIPE_BUSY) {
            return false;
        }
        if (!WaitNamedPipeW(kPipeName, kConnectTimeoutMs)) {
            return false;
        }
        h = CreateFileW(kPipeName, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            return false;
        }
    }
    pipe_ = h;
    connected_ = true;
    return true;
}

void IpcClient::ClosePipe() {
    if (pipe_ != INVALID_HANDLE_VALUE) {
        CloseHandle(pipe_);
        pipe_ = INVALID_HANDLE_VALUE;
    }
}

bool IpcClient::WriteMessage(const Message& msg) {
    std::vector<uint8_t> buf = SerializeMessage(msg);
    HANDLE evt = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!evt) {
        return false;
    }
    OVERLAPPED ov = {};
    ov.hEvent = evt;
    DWORD written = 0;
    BOOL ok = WriteFile(pipe_, buf.data(), static_cast<DWORD>(buf.size()), &written, &ov);
    if (!ok && GetLastError() == ERROR_IO_PENDING) {
        DWORD wait = WaitForSingleObject(evt, kWriteTimeoutMs);
        if (wait == WAIT_OBJECT_0) {
            ok = GetOverlappedResult(pipe_, &ov, &written, FALSE);
        } else if (wait == WAIT_TIMEOUT) {
            CancelIo(pipe_);
            WaitForSingleObject(evt, INFINITE);
            ok = FALSE;
        } else {
            ok = FALSE;
        }
    }
    CloseHandle(evt);
    return ok && written == buf.size();
}

void IpcClient::ThreadMain() {
    uint32_t backoff = 250;
    while (!stopping_.load()) {
        if (!connected_.load()) {
            if (ConnectPipe()) {
                backoff = 250;
                PayloadWriter w;
                w.U32(GetCurrentProcessId());
                wchar_t name[MAX_PATH] = {};
                DWORD nameLen = GetModuleFileNameW(nullptr, name, MAX_PATH);
                w.Str(WideToUtf8(name, nameLen));
                Message hello = MakeMessage(MsgType::Hello, 0, w.Take());
                WriteMessage(hello);
                uint64_t dropped = dropped_.exchange(0);
                if (dropped > 0) {
                    PayloadWriter dw;
                    dw.U64(dropped);
                    Message dm = MakeMessage(MsgType::DropCount, 0, dw.Take());
                    WriteMessage(dm);
                }
                continue;
            }
            Sleep(backoff);
            backoff = std::min<uint32_t>(backoff * 2, 5000);
            continue;
        }

        std::unique_lock<std::mutex> lock(queueMutex_);
        queueCv_.wait_for(lock, std::chrono::milliseconds(200), [this] {
            return !queue_.empty() || stopping_.load();
        });
        if (stopping_.load()) {
            break;
        }
        if (queue_.empty()) {
            continue;
        }
        Message msg = std::move(queue_.front());
        queue_.pop_front();
        lock.unlock();

        if (!WriteMessage(msg)) {
            dropped_.fetch_add(1);
            ClosePipe();
            connected_ = false;
        }
    }
    ClosePipe();
    connected_ = false;
}

}  // namespace ipc
