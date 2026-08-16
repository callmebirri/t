#pragma once

#include <cstdint>
#include <string>

namespace hook_engine {

bool Initialize();
void Shutdown();
void SendHookStatus();
void InstallWinhttpHooksNow();
void InstallSchannelHooksNow();
uint32_t WinhttpInstalledMask();
uint32_t SchannelInstalledMask();
void RecordFailure(const std::string& name, uint32_t code);

}  // namespace hook_engine
