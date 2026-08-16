#pragma once

#include "IpcCommon/IpcCommon.h"

#include <atomic>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>

namespace ipc {

class IpcClient {
public:
    static IpcClient& Instance();

    void Start();
    void Stop();
    bool IsConnected() const { return connected_.load(); }

    void SendPayload(MsgType type, uint64_t requestId, std::vector<uint8_t> payload);

private:
    IpcClient() = default;
    IpcClient(const IpcClient&) = delete;
    IpcClient& operator=(const IpcClient&) = delete;

    void ThreadMain();
    bool ConnectPipe();
    bool WriteMessage(const Message& msg);
    void ClosePipe();

    std::mutex queueMutex_;
    std::condition_variable queueCv_;
    std::deque<Message> queue_;
    std::atomic<bool> connected_{false};
    std::atomic<bool> stopping_{false};
    std::atomic<uint64_t> dropped_{0};
    std::thread thread_;
    HANDLE pipe_ = INVALID_HANDLE_VALUE;
};

}  // namespace ipc
