#pragma once

#include <atomic>

namespace hook_common {

inline std::atomic<bool>& ShuttingDown() {
    static std::atomic<bool> flag{false};
    return flag;
}

inline thread_local bool t_insideWinhttpHook = false;
inline thread_local bool t_insideSchannelHook = false;

struct WinhttpGuard {
    WinhttpGuard() : prev_(t_insideWinhttpHook) { t_insideWinhttpHook = true; }
    ~WinhttpGuard() { t_insideWinhttpHook = prev_; }
    bool prev_;
};

struct SchannelGuard {
    SchannelGuard() : prev_(t_insideSchannelHook) { t_insideSchannelHook = true; }
    ~SchannelGuard() { t_insideSchannelHook = prev_; }
    bool prev_;
};

inline bool InsideWinhttpHook() { return t_insideWinhttpHook; }
inline bool InsideSchannelHook() { return t_insideSchannelHook; }

}  // namespace hook_common
