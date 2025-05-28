#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <string>
#include <unordered_map>

namespace MemExternal {
	std::pair<HANDLE, ULONG> WaitForProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, std::string procName);
	ULONG getProcId(std::string name);
	bool handleIsStillValid(HANDLE handle);

	ULONGLONG readJmp32Rel(HANDLE handle, ULONGLONG instructionAddr);
	ULONGLONG readJmpAbs(HANDLE handle, ULONGLONG instructionAddr);
	ULONGLONG writeJmpAbs(HANDLE handle, ULONGLONG instructionAddr, ULONGLONG targetAddr);

	std::unordered_map<std::string, ULONG> getExportsFunctions(HANDLE handle, HMODULE module);
	HMODULE getLoadedModule(HANDLE handle, const char* modName);
	ULONG getModuleSize(HANDLE handle, HMODULE module);

	//for testing
	void suspendAllThreads(HANDLE handle);
	void resumeAllThreads(HANDLE handle);
	void suspendByfronThreads(HANDLE handle);
	void resumeByfronThreads(HANDLE handle);

	std::vector<ULONG> GetThreadIds(ULONG processId);
	ULONGLONG getThreadStartAddr(HANDLE threadHandle);
}

namespace MemInternal {

}
